// Copyright 2026, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPolicyCompliancePoliciesClient struct {
	pages [][]cloudapitype.PolicyComplianceRow
	reqs  []cloudapitype.AngularGridGetRowsRequest
	err   error
}

func (m *mockPolicyCompliancePoliciesClient) ListPoliciesCompliance(
	_ context.Context, _ string, req cloudapitype.AngularGridGetRowsRequest,
) (cloudapitype.ListPoliciesComplianceResponse, error) {
	m.reqs = append(m.reqs, req)
	if m.err != nil {
		return cloudapitype.ListPoliciesComplianceResponse{}, m.err
	}
	idx := len(m.reqs) - 1
	if idx >= len(m.pages) {
		return cloudapitype.ListPoliciesComplianceResponse{}, nil
	}
	return cloudapitype.ListPoliciesComplianceResponse{Policies: m.pages[idx]}, nil
}

func complianceRows(n int) []cloudapitype.PolicyComplianceRow {
	rows := make([]cloudapitype.PolicyComplianceRow, n)
	for i := range rows {
		rows[i] = cloudapitype.PolicyComplianceRow{
			PolicyPack:        "aws",
			PolicyName:        fmt.Sprintf("policy-%d", i),
			PolicyGroupName:   "default",
			PolicyGroupType:   cloudapitype.PolicyGroupModeAudit,
			Severity:          cloudapitype.AppPolicySeverityHigh,
			FailingResources:  i,
			GovernedResources: 100,
			PercentCompliant:  50,
		}
	}
	return rows
}

func runPolicyCompliancePoliciesCmd(
	t *testing.T, c policyCompliancePoliciesClient, args ...string,
) (string, error) {
	t.Helper()
	cmd := newPolicyCompliancePoliciesCmdWith(
		func(context.Context, string) (policyCompliancePoliciesClient, string, error) {
			return c, "acme", nil
		})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

func TestPolicyCompliancePolicies_Paginates(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{
		pages: [][]cloudapitype.PolicyComplianceRow{complianceRows(100), complianceRows(20)},
	}
	out, err := runPolicyCompliancePoliciesCmd(t, c, "--output", "json")
	require.NoError(t, err)

	require.Len(t, c.reqs, 2)
	assert.Equal(t, 0, c.reqs[0].StartRow)
	assert.Equal(t, 100, c.reqs[0].EndRow)
	assert.Equal(t, 100, c.reqs[1].StartRow)
	assert.Equal(t, 200, c.reqs[1].EndRow)
	for _, req := range c.reqs {
		assert.Equal(t, policyComplianceSortModel(), req.SortModel)
	}

	var got policyCompliancePoliciesJSON
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Policies, 120)
}

func TestPolicyCompliancePolicies_FullPageThenEmpty(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{
		pages: [][]cloudapitype.PolicyComplianceRow{complianceRows(100), nil},
	}
	out, err := runPolicyCompliancePoliciesCmd(t, c, "--output", "json")
	require.NoError(t, err)
	require.Len(t, c.reqs, 2)

	var got policyCompliancePoliciesJSON
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Policies, 100)
}

func TestPolicyCompliancePolicies_JSONOmitsPlaceholderFields(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{pages: [][]cloudapitype.PolicyComplianceRow{complianceRows(1)}}
	out, err := runPolicyCompliancePoliciesCmd(t, c, "--output", "json")
	require.NoError(t, err)
	assert.NotContains(t, out, "governedResources")
	assert.NotContains(t, out, "percentCompliant")
	assert.Contains(t, out, "failingResources")
	assert.Contains(t, out, "policyGroupType")
}

func TestPolicyCompliancePolicies_Filters(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{}
	_, err := runPolicyCompliancePoliciesCmd(t, c, "--pack", "aws", "--severity", "high")
	require.NoError(t, err)
	require.Len(t, c.reqs, 1)
	require.NotNil(t, c.reqs[0].FilterModel)
	sortBody, err := json.Marshal(c.reqs[0].SortModel)
	require.NoError(t, err)
	assert.JSONEq(t, `[
		{"colId":"failingResources","sort":"desc"},
		{"colId":"policyPack","sort":"asc"},
		{"colId":"policyName","sort":"asc"},
		{"colId":"policyGroupName","sort":"asc"}]`, string(sortBody))
	body, err := json.Marshal(c.reqs[0].FilterModel)
	require.NoError(t, err)
	assert.Contains(t, string(body), "aws")
	assert.Contains(t, string(body), "high")
}

func TestPolicyCompliancePolicies_InvalidFilterFailsBeforeRequest(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{}
	_, err := runPolicyCompliancePoliciesCmd(t, c, "--severity", "urgent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical")
	assert.Empty(t, c.reqs)
}

func TestPolicyCompliancePolicies_Table(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{pages: [][]cloudapitype.PolicyComplianceRow{complianceRows(2)}}
	out, err := runPolicyCompliancePoliciesCmd(t, c)
	require.NoError(t, err)
	for _, want := range []string{"POLICY PACK", "POLICY", "GROUP", "SEVERITY", "FAILING RESOURCES", "policy-1"} {
		assert.Contains(t, out, want)
	}
}

func TestPolicyCompliancePolicies_Empty(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{}
	out, err := runPolicyCompliancePoliciesCmd(t, c)
	require.NoError(t, err)
	assert.Equal(t, "No failing policies found for this organization.\n", out)
}

func TestPolicyCompliancePolicies_ServerError(t *testing.T) {
	t.Parallel()

	c := &mockPolicyCompliancePoliciesClient{err: assert.AnError}
	_, err := runPolicyCompliancePoliciesCmd(t, c)
	require.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, assert.AnError.Error(), err.Error())
}
