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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pulumi/pulumi/pkg/v3/backend/httpstate/client"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
)

// capturedPolicyIssueListCall records the inputs to a single ListPolicyIssues
// call so tests can assert on the flag-to-request propagation.
type capturedPolicyIssueListCall struct {
	org    string
	req    cloudapitype.AngularGridGetRowsRequest
	closed bool
}

// mockPolicyIssueListClient stubs policyIssueListClient. It returns a fixed
// response (or error) and records the most recent invocation.
type mockPolicyIssueListClient struct {
	resp     cloudapitype.ListPolicyIssuesResponse
	err      error
	captured *capturedPolicyIssueListCall
}

func (m *mockPolicyIssueListClient) ListPolicyIssues(
	_ context.Context, org string, req cloudapitype.AngularGridGetRowsRequest, closed bool,
) (cloudapitype.ListPolicyIssuesResponse, error) {
	if m.captured != nil {
		*m.captured = capturedPolicyIssueListCall{org: org, req: req, closed: closed}
	}
	if m.err != nil {
		return cloudapitype.ListPolicyIssuesResponse{}, m.err
	}
	return m.resp, nil
}

func stubPolicyIssueListFactory(c policyIssueListClient, org string) policyIssueListClientFactory {
	return stubPolicyIssueListFactoryWithLogin(c, org, "")
}

func stubPolicyIssueListFactoryWithLogin(
	c policyIssueListClient, org, login string,
) policyIssueListClientFactory {
	return func(_ context.Context, _ string) (policyIssueListClient, string, string, error) {
		return c, org, login, nil
	}
}

func mustParseTime(t string) *time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, t)
	if err != nil {
		panic(err)
	}
	return &parsed
}

func samplePolicyIssueListResponse() cloudapitype.ListPolicyIssuesResponse {
	return cloudapitype.ListPolicyIssuesResponse{
		RowCount: new(2),
		PolicyIssues: []cloudapitype.PolicyIssue{
			{
				ID:            "issue-1",
				PolicyName:    "no-public-buckets",
				PolicyPack:    "aws-guardrails",
				PolicyPackTag: "1.2.0",
				Level:         string(apitype.Mandatory),
				Severity:      cloudapitype.AppPolicySeverityHigh,
				ResourceURN:   "urn:pulumi:prod::web::aws:s3/bucket:Bucket::data",
				ResourceType:  "aws:s3/bucket:Bucket",
				EntityID:      "prod",
				EntityProject: "web",
				Message:       "S3 bucket must not allow public access",
				ObservedAt:    mustParseTime("2026-05-01T12:00:00Z"),
			},
			{
				ID:            "issue-2",
				PolicyName:    "required-tags",
				PolicyPack:    "tagging",
				Level:         string(apitype.Advisory),
				EntityID:      "staging",
				EntityProject: "web",
				Message: "Resource is missing required tags: this message is intentionally " +
					"long enough to exercise the truncation path in the table renderer",
				ObservedAt: mustParseTime("2026-04-30T08:00:00Z"),
			},
		},
	}
}

func TestPolicyIssueList_DefaultOutput(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	c := &mockPolicyIssueListClient{resp: samplePolicyIssueListResponse()}
	err := runPolicyIssueList(t.Context(), buf,
		stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()})
	require.NoError(t, err)

	out := buf.String()
	// Table headers.
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "POLICY PACK")
	assert.Contains(t, out, "POLICY")
	assert.Contains(t, out, "ENFORCEMENT")
	assert.Contains(t, out, "STACK")
	assert.Contains(t, out, "MESSAGE")

	// First row content.
	assert.Contains(t, out, "issue-1")
	assert.Contains(t, out, "aws-guardrails@1.2.0")
	assert.Contains(t, out, "no-public-buckets")
	assert.Contains(t, out, "mandatory")
	assert.Contains(t, out, "web/prod")
	assert.Contains(t, out, "S3 bucket must not allow public access")

	// Second row: long message should be truncated with an ellipsis.
	assert.Contains(t, out, "issue-2")
	assert.Contains(t, out, "tagging")
	assert.Contains(t, out, "advisory")
	assert.Contains(t, out, "web/staging")
	assert.Contains(t, out, "...")
	assert.NotContains(t, out, "truncation path in the table renderer")

	// Footer summary (no page number).
	assert.Contains(t, out, "Showing 2 of 2 policy issue(s)")
}

func TestPolicyIssueList_DefaultOutput_Empty(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	c := &mockPolicyIssueListClient{resp: cloudapitype.ListPolicyIssuesResponse{}}
	err := runPolicyIssueList(t.Context(), buf,
		stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()})
	require.NoError(t, err)
	assert.Equal(t, "No policy issues found for this organization.\n", buf.String())
}

func TestPolicyIssueList_JSONOutput(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	c := &mockPolicyIssueListClient{resp: samplePolicyIssueListResponse()}
	args := policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()}
	require.NoError(t, args.outputFormat.Set("json"))
	err := runPolicyIssueList(t.Context(), buf,
		stubPolicyIssueListFactory(c, "acme"), args)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"issues": [
			{
				"id": "issue-1",
				"policyName": "no-public-buckets",
				"policyPack": "aws-guardrails",
				"policyPackTag": "1.2.0",
				"level": "mandatory",
				"severity": "high",
				"resourceURN": "urn:pulumi:prod::web::aws:s3/bucket:Bucket::data",
				"resourceType": "aws:s3/bucket:Bucket",
				"entityId": "prod",
				"entityProject": "web",
				"message": "S3 bucket must not allow public access",
				"observedAt": "2026-05-01T12:00:00Z"
			},
			{
				"id": "issue-2",
				"policyName": "required-tags",
				"policyPack": "tagging",
				"level": "advisory",
				"entityId": "staging",
				"entityProject": "web",
				"message": "Resource is missing required tags: this message is intentionally `+
		`long enough to exercise the truncation path in the table renderer",
				"observedAt": "2026-04-30T08:00:00Z"
			}
		],
		"total": 2
	}`, buf.String())
}

func newPolicyIssueServerClient(t *testing.T, respond func(r *http.Request) string) *client.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respond(r)))
	}))
	t.Cleanup(server.Close)
	return client.NewClient(server.URL, "token", false, nil)
}

const unknownEnumIssueJSON = `{
	"id": "issue-9",
	"entityType": "stack",
	"entityProject": "web",
	"entityId": "prod",
	"policyPack": "aws-guardrails",
	"policyName": "s3-no-public",
	"level": "mandatory",
	"severity": "future",
	"status": "future_status",
	"kind": "future_kind",
	"priority": "p9",
	"observedAt": "2026-10-01T12:34:56Z"
}`

const fractionalTimestampIssueJSON = `{
	"id": "issue-1",
	"entityType": "stack",
	"entityProject": "web",
	"entityId": "prod",
	"policyPack": "aws-guardrails",
	"policyPackTag": "3.1.0",
	"policyName": "s3-no-public",
	"level": "mandatory",
	"severity": "critical",
	"resourceURN": "urn:pulumi:prod::web::aws:s3/bucket:Bucket::assets",
	"resourceProvider": "aws",
	"resourceType": "aws:s3/bucket:Bucket",
	"resourceName": "assets",
	"message": "Bucket must not allow public access & <must> be \"private\".",
	"observedAt": "2026-10-01T12:34:56.789123Z",
	"status": "open",
	"kind": "audit",
	"priority": "P1"
}`

const minimalIssueJSON = `{
	"id": "issue-2",
	"policyPack": "tagging",
	"policyName": "require-owner",
	"level": "advisory"
}`

func runPolicyIssueListAgainstServer(
	t *testing.T, body string, args policyIssueListArgs,
) string {
	t.Helper()
	c := newPolicyIssueServerClient(t, func(*http.Request) string { return body })
	buf := &bytes.Buffer{}
	require.NoError(t, runPolicyIssueList(t.Context(), buf, stubPolicyIssueListFactory(c, "acme"), args))
	return buf.String()
}

func TestPolicyIssueList_UnknownEnumValues(t *testing.T) {
	t.Parallel()

	body := `{"policyIssues": [` + unknownEnumIssueJSON + `], "rowCount": 1}`

	jsonArgs := policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()}
	require.NoError(t, jsonArgs.outputFormat.Set("json"))
	var envelope struct {
		Issues []map[string]any `json:"issues"`
	}
	require.NoError(t, json.Unmarshal([]byte(runPolicyIssueListAgainstServer(t, body, jsonArgs)), &envelope))
	require.Len(t, envelope.Issues, 1)
	assert.Equal(t, "future_kind", envelope.Issues[0]["kind"])
	assert.Equal(t, "future_status", envelope.Issues[0]["status"])
	assert.Equal(t, "p9", envelope.Issues[0]["priority"])
	assert.Equal(t, "future", envelope.Issues[0]["severity"])

	table := runPolicyIssueListAgainstServer(t, body,
		policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()})
	assert.Contains(t, table, "issue-9")
	assert.Contains(t, table, "Showing 1 of 1 policy issue(s)")
}

func TestPolicyIssueList_Timestamps(t *testing.T) {
	t.Parallel()

	body := `{"policyIssues": [` + fractionalTimestampIssueJSON + `, ` + minimalIssueJSON + `], "rowCount": 250}`

	jsonArgs := policyIssueListArgs{count: 2, outputFormat: defaultPolicyIssueListOutputFormat()}
	require.NoError(t, jsonArgs.outputFormat.Set("json"))
	out := runPolicyIssueListAgainstServer(t, body, jsonArgs)
	assert.Contains(t, out, `"observedAt": "2026-10-01T12:34:56.789123Z"`)
	assert.NotContains(t, out, "lastModified")

	table := runPolicyIssueListAgainstServer(t, body,
		policyIssueListArgs{count: 2, outputFormat: defaultPolicyIssueListOutputFormat()})
	want := renderPin(t, func(w *bytes.Buffer) error {
		return renderPolicyIssueListTable(w, cloudapitype.ListPolicyIssuesResponse{
			PolicyIssues: []cloudapitype.PolicyIssue{pinIssueFull(), pinIssueMinimal()},
			RowCount:     new(250),
		}, false)
	})
	assert.Equal(t, want, table)
}

func TestPolicyIssueList_ClosedFlagPassedToClient(t *testing.T) {
	t.Parallel()

	var closedByPage []bool
	c := &pagingPolicyIssueListClient{
		onCall: func(closed bool) { closedByPage = append(closedByPage, closed) },
	}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{},
		stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{closed: true, all: true, outputFormat: defaultPolicyIssueListOutputFormat()})
	require.NoError(t, err)
	assert.Equal(t, []bool{true, true}, closedByPage)
}

func TestPolicyIssueList_ClosedEmptyMessage(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	c := &mockPolicyIssueListClient{resp: cloudapitype.ListPolicyIssuesResponse{}}
	err := runPolicyIssueList(t.Context(), buf,
		stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{closed: true, outputFormat: defaultPolicyIssueListOutputFormat()})
	require.NoError(t, err)
	assert.Equal(t, "No closed policy issues found for this organization.\n", buf.String())
}

type pagingPolicyIssueListClient struct {
	onCall func(closed bool)
	calls  int
}

func (p *pagingPolicyIssueListClient) ListPolicyIssues(
	_ context.Context, _ string, _ cloudapitype.AngularGridGetRowsRequest, closed bool,
) (cloudapitype.ListPolicyIssuesResponse, error) {
	p.onCall(closed)
	p.calls++
	return cloudapitype.ListPolicyIssuesResponse{
		PolicyIssues: []cloudapitype.PolicyIssue{{ID: fmt.Sprintf("issue-%d", p.calls)}},
		RowCount:     new(2),
	}, nil
}

type recordingPolicyIssueListClient struct {
	reqs []cloudapitype.AngularGridGetRowsRequest
	all  []cloudapitype.PolicyIssue
	err  error
}

func (r *recordingPolicyIssueListClient) ListPolicyIssues(
	_ context.Context, _ string, req cloudapitype.AngularGridGetRowsRequest, _ bool,
) (cloudapitype.ListPolicyIssuesResponse, error) {
	if r.err != nil {
		return cloudapitype.ListPolicyIssuesResponse{}, r.err
	}
	r.reqs = append(r.reqs, req)
	end := min(req.EndRow, len(r.all))
	return cloudapitype.ListPolicyIssuesResponse{
		PolicyIssues: r.all[min(req.StartRow, end):end],
		RowCount:     new(len(r.all)),
	}, nil
}

func TestPolicyIssueList_NoFiltersBodyUnchanged(t *testing.T) {
	t.Parallel()

	c := &recordingPolicyIssueListClient{all: []cloudapitype.PolicyIssue{{ID: "issue-1"}}}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{}, stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()})
	require.NoError(t, err)
	require.Len(t, c.reqs, 1)
	assert.Nil(t, c.reqs[0].FilterModel)
	assert.Nil(t, c.reqs[0].SortModel)
}

func TestPolicyIssueList_FiltersOnEveryPage(t *testing.T) {
	t.Parallel()

	issues := make([]cloudapitype.PolicyIssue, 250)
	for i := range issues {
		issues[i] = cloudapitype.PolicyIssue{ID: fmt.Sprintf("issue-%d", i)}
	}
	c := &recordingPolicyIssueListClient{all: issues}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{}, stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{
			all:          true,
			filters:      policyIssueFilters{severities: []string{"high"}, sort: []string{"observedAt:desc"}},
			outputFormat: defaultPolicyIssueListOutputFormat(),
		})
	require.NoError(t, err)
	require.Len(t, c.reqs, 3)
	require.NotNil(t, c.reqs[0].FilterModel)
	require.NotEmpty(t, c.reqs[0].SortModel)
	for _, req := range c.reqs {
		assert.Equal(t, c.reqs[0].FilterModel, req.FilterModel)
		assert.Equal(t, c.reqs[0].SortModel, req.SortModel)
	}
}

func TestPolicyIssueList_AssignedToMeUsesLogin(t *testing.T) {
	t.Parallel()

	c := &recordingPolicyIssueListClient{}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{},
		stubPolicyIssueListFactoryWithLogin(c, "acme", "alice"),
		policyIssueListArgs{
			filters:      policyIssueFilters{assignedTo: []string{"me"}},
			outputFormat: defaultPolicyIssueListOutputFormat(),
		})
	require.NoError(t, err)
	require.Len(t, c.reqs, 1)
	body, err := json.Marshal(c.reqs[0])
	require.NoError(t, err)
	assert.Contains(t, string(body), `"alice"`)
	assert.NotContains(t, string(body), `"me"`)
}

func TestPolicyIssueList_InvalidFilterFailsBeforeRequest(t *testing.T) {
	t.Parallel()

	c := &recordingPolicyIssueListClient{}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{}, stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{
			filters:      policyIssueFilters{severities: []string{"urgent"}},
			outputFormat: defaultPolicyIssueListOutputFormat(),
		})
	require.ErrorContains(t, err, "urgent")
	assert.Empty(t, c.reqs)
}

func TestPolicyIssueList_ServerRejectsFilter(t *testing.T) {
	t.Parallel()

	c := &recordingPolicyIssueListClient{err: errors.New(`[400] Invalid input: unknown field "x"`)}
	err := runPolicyIssueList(t.Context(), &bytes.Buffer{}, stubPolicyIssueListFactory(c, "acme"),
		policyIssueListArgs{
			filters:      policyIssueFilters{packs: []string{"p"}},
			outputFormat: defaultPolicyIssueListOutputFormat(),
		})
	require.ErrorContains(t, err, "unknown field")
}

func TestPolicyIssueList_JSONIncludesAssigneeAndGroup(t *testing.T) {
	t.Parallel()

	groupType := cloudapitype.PolicyGroupMode("audit")
	c := &mockPolicyIssueListClient{resp: cloudapitype.ListPolicyIssuesResponse{
		RowCount: new(1),
		PolicyIssues: []cloudapitype.PolicyIssue{{
			ID:              "issue-1",
			AssignedTo:      &cloudapitype.UserInfo{GitHubLogin: "alice"},
			PolicyGroupName: new("prod"),
			PolicyGroupType: &groupType,
		}},
	}}
	args := policyIssueListArgs{outputFormat: defaultPolicyIssueListOutputFormat()}
	require.NoError(t, args.outputFormat.Set("json"))
	buf := &bytes.Buffer{}
	require.NoError(t, runPolicyIssueList(t.Context(), buf, stubPolicyIssueListFactory(c, "acme"), args))
	assert.Contains(t, buf.String(), `"assignedTo": "alice"`)
	assert.Contains(t, buf.String(), `"policyGroupName": "prod"`)
	assert.Contains(t, buf.String(), `"policyGroupType": "audit"`)
}
