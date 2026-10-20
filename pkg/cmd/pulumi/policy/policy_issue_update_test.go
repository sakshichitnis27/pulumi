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
	"errors"
	"sync"
	"testing"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPolicyIssueUpdateClient struct {
	mu            sync.Mutex
	factoryCalled bool
	calls         []string
	requests      []cloudapitype.UpdatePolicyIssueRequest
	failIDs       map[string]error
}

func (m *mockPolicyIssueUpdateClient) UpdatePolicyIssue(
	_ context.Context, _, issueID string, req cloudapitype.UpdatePolicyIssueRequest,
) (cloudapitype.GetPolicyIssueResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, issueID)
	m.requests = append(m.requests, req)
	if err := m.failIDs[issueID]; err != nil {
		return cloudapitype.GetPolicyIssueResponse{}, err
	}
	issue := cloudapitype.PolicyIssue{ID: issueID}
	if req.Status != nil {
		issue.Status = *req.Status
	}
	if req.Priority != nil {
		issue.Priority = *req.Priority
	}
	if req.AssignedTo != nil && *req.AssignedTo != "" {
		issue.AssignedTo = &cloudapitype.UserInfo{GitHubLogin: *req.AssignedTo}
	}
	return cloudapitype.GetPolicyIssueResponse{PolicyIssue: issue}, nil
}

func runPolicyIssueUpdateCmd(
	t *testing.T, c *mockPolicyIssueUpdateClient, cmdArgs ...string,
) (string, error) {
	t.Helper()
	factory := func(context.Context, string) (policyIssueUpdateClient, string, string, error) {
		c.factoryCalled = true
		return c, "acme", "alice", nil
	}
	cmd := newPolicyIssueUpdateCmdWith(factory)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(cmdArgs)
	err := cmd.ExecuteContext(t.Context())
	return buf.String(), err
}

func TestBuildUpdatePolicyIssueRequest(t *testing.T) {
	t.Parallel()

	t.Run("status and priority", func(t *testing.T) {
		t.Parallel()
		req, err := buildUpdatePolicyIssueRequest(policyIssueUpdateArgs{status: "in_progress", priority: "p1"}, "alice")
		require.NoError(t, err)
		require.NotNil(t, req.Status)
		assert.Equal(t, cloudapitype.PolicyIssueStatusInProgress, *req.Status)
		require.NotNil(t, req.Priority)
		assert.Equal(t, cloudapitype.PolicyIssuePriorityP1, *req.Priority)
		assert.Nil(t, req.AssignedTo)
	})

	t.Run("assignee me", func(t *testing.T) {
		t.Parallel()
		req, err := buildUpdatePolicyIssueRequest(policyIssueUpdateArgs{assignee: "me"}, "alice")
		require.NoError(t, err)
		require.NotNil(t, req.AssignedTo)
		assert.Equal(t, "alice", *req.AssignedTo)
	})

	t.Run("unassign", func(t *testing.T) {
		t.Parallel()
		req, err := buildUpdatePolicyIssueRequest(policyIssueUpdateArgs{unassign: true}, "alice")
		require.NoError(t, err)
		require.NotNil(t, req.AssignedTo)
		assert.Empty(t, *req.AssignedTo)
	})

	t.Run("bad priority", func(t *testing.T) {
		t.Parallel()
		_, err := buildUpdatePolicyIssueRequest(policyIssueUpdateArgs{priority: "p9"}, "alice")
		require.ErrorContains(t, err, "p0, p1, p2, p3, p4")
	})
}

func TestPolicyIssueUpdate_RequiresAChange(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	_, err := runPolicyIssueUpdateCmd(t, c, "i1")
	require.ErrorContains(t, err, "--status, --priority, --assignee or --unassign")
	assert.False(t, c.factoryCalled)
	assert.Empty(t, c.calls)
}

func TestPolicyIssueUpdate_RejectsReadOnlyStatus(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"fixed", "by_design"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			c := &mockPolicyIssueUpdateClient{}
			_, err := runPolicyIssueUpdateCmd(t, c, "i1", "--status", status)
			require.ErrorContains(t, err, "open, in_progress, ignored")
			assert.False(t, c.factoryCalled)
			assert.Empty(t, c.calls)
		})
	}
}

type updateJSONOut struct {
	Results []struct {
		ID    string `json:"id"`
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Issue *struct {
			Status string `json:"status"`
		} `json:"issue"`
	} `json:"results"`
	Updated int `json:"updated"`
	Failed  int `json:"failed"`
}

func TestPolicyIssueUpdate_JSON(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	out, err := runPolicyIssueUpdateCmd(t, c, "i1", "i2", "--status", "in_progress", "--output", "json")
	require.NoError(t, err)

	var got updateJSONOut
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, 2, got.Updated)
	assert.Equal(t, 0, got.Failed)
	require.Len(t, got.Results, 2)
	require.NotNil(t, got.Results[0].Issue)
	assert.Equal(t, "in_progress", got.Results[0].Issue.Status)
}

func TestPolicyIssueUpdate_PartialFailure(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{failIDs: map[string]error{"i2": errors.New("boom")}}
	out, err := runPolicyIssueUpdateCmd(t, c, "i1", "i2", "i3", "--priority", "p2", "--output", "json")
	require.EqualError(t, err, "failed to update 1 of 3 policy issues")
	assert.Contains(t, c.calls, "i3")

	var got updateJSONOut
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Results, 3)
	assert.Equal(t, "i1", got.Results[0].ID)
	assert.Equal(t, "i2", got.Results[1].ID)
	assert.Equal(t, "i3", got.Results[2].ID)
	assert.False(t, got.Results[1].OK)
	assert.NotEmpty(t, got.Results[1].Error)
	assert.Equal(t, 2, got.Updated)
	assert.Equal(t, 1, got.Failed)
}

func TestPolicyIssueUpdate_DeduplicatesIDs(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	out, err := runPolicyIssueUpdateCmd(t, c, "i1", "i1", "--status", "open", "--output", "json")
	require.NoError(t, err)
	assert.Equal(t, []string{"i1"}, c.calls)

	var got updateJSONOut
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Results, 1)
}

func TestPolicyIssueUpdate_Text(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	out, err := runPolicyIssueUpdateCmd(t, c, "i1", "--status", "ignored")
	require.NoError(t, err)
	assert.Contains(t, out, "✓ i1: status=ignored priority=- assignee=-")
	assert.Contains(t, out, "Updated 1 of 1 policy issue(s).")
}

func TestPolicyIssueUpdate_AssigneeMeSendsCurrentLogin(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	_, err := runPolicyIssueUpdateCmd(t, c, "i1", "--assignee", "me")
	require.NoError(t, err)
	require.Len(t, c.requests, 1)
	require.NotNil(t, c.requests[0].AssignedTo)
	assert.Equal(t, "alice", *c.requests[0].AssignedTo)
}

func TestPolicyIssueUpdate_AssigneeMeRequiresLogin(t *testing.T) {
	t.Parallel()

	c := &mockPolicyIssueUpdateClient{}
	factory := func(context.Context, string) (policyIssueUpdateClient, string, string, error) {
		return c, "acme", "", nil
	}
	cmd := newPolicyIssueUpdateCmdWith(factory)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"i1", "--assignee", "me"})
	err := cmd.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "--assignee me")
	assert.Empty(t, c.requests)
}
