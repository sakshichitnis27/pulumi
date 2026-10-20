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
	"testing"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/stretchr/testify/assert"
)

func pinIssueFull() cloudapitype.PolicyIssue {
	return cloudapitype.PolicyIssue{
		ID:               "issue-1",
		EntityType:       cloudapitype.IssueEntityTypeStack,
		EntityProject:    "web",
		EntityID:         "prod",
		PolicyPack:       "aws-guardrails",
		PolicyPackTag:    "3.1.0",
		PolicyName:       "s3-no-public",
		Level:            "mandatory",
		Severity:         cloudapitype.AppPolicySeverityCritical,
		ResourceURN:      "urn:pulumi:prod::web::aws:s3/bucket:Bucket::assets",
		ResourceProvider: "aws",
		ResourceType:     "aws:s3/bucket:Bucket",
		ResourceName:     "assets",
		Message:          "Bucket must not allow public access & <must> be \"private\".",
		ObservedAt:       mustParseTime("2026-03-04T05:06:07.123456Z"),
		LastModified:     mustParseTime("2026-03-05T06:07:08.5Z"),
		Status:           cloudapitype.PolicyIssueStatusOpen,
		Kind:             cloudapitype.PolicyIssueKindAudit,
		Priority:         "P1",
	}
}

func pinIssueMinimal() cloudapitype.PolicyIssue {
	return cloudapitype.PolicyIssue{
		ID:         "issue-2",
		PolicyPack: "tagging",
		PolicyName: "require-owner",
		Level:      "advisory",
	}
}

func TestPin_PolicyIssueList_JSON_Full(t *testing.T) {
	t.Parallel()
	resp := cloudapitype.ListPolicyIssuesResponse{
		PolicyIssues: []cloudapitype.PolicyIssue{pinIssueFull(), pinIssueMinimal()},
		RowCount:     new(250),
	}
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyIssueListJSON(w, resp, false) })
	assert.JSONEq(t, `{
  "issues": [
    {
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
      "observedAt": "2026-03-04T05:06:07.123456Z",
      "lastModified": "2026-03-05T06:07:08.5Z",
      "status": "open",
      "kind": "audit",
      "priority": "P1"
    },
    {
      "id": "issue-2",
      "policyPack": "tagging",
      "policyName": "require-owner",
      "level": "advisory"
    }
  ],
  "total": 250
}
`, got)
}

func TestPin_PolicyIssueList_JSON_Minimal(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error {
		return renderPolicyIssueListJSON(w, cloudapitype.ListPolicyIssuesResponse{}, false)
	})
	assert.JSONEq(t, `{
  "issues": [],
  "total": 0
}
`, got)
}

func TestPin_PolicyIssueList_Table(t *testing.T) {
	t.Parallel()
	resp := cloudapitype.ListPolicyIssuesResponse{
		PolicyIssues: []cloudapitype.PolicyIssue{pinIssueFull(), pinIssueMinimal()},
		RowCount:     new(250),
	}
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyIssueListTable(w, resp, false) })
	assert.Equal(t, ""+
		`┌─────────┬──────────────────────┬───────────────┬─────────────┬──────`+
		`────┬────────────────────────────────────────────────────────────┐`+"\n"+
		`│ ID      │ POLICY PACK          │ POLICY        │ ENFORCEMENT │ STACK`+
		`    │ MESSAGE                                                    │`+"\n"+
		`├─────────┼──────────────────────┼───────────────┼─────────────┼──────`+
		`────┼────────────────────────────────────────────────────────────┤`+"\n"+
		`│ issue-1 │ aws-guardrails@3.1.0 │ s3-no-public  │ mandatory   │ web/p`+
		`rod │ Bucket must not allow public access & <must> be "private". │`+"\n"+
		`│ issue-2 │ tagging              │ require-owner │ advisory    │ -    `+
		`    │                                                            │`+"\n"+
		`└─────────┴──────────────────────┴───────────────┴─────────────┴──────`+
		`────┴────────────────────────────────────────────────────────────┘`+"\n"+
		"\n"+
		"Showing 2 of 250 policy issue(s)\n", got)
}

func TestPin_PolicyIssueGet_JSON_Full(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error {
		return renderPolicyIssueGetJSON(w, cloudapitype.GetPolicyIssueResponse{PolicyIssue: pinIssueFull()})
	})
	assert.JSONEq(t, `{
  "id": "issue-1",
  "entityType": "stack",
  "kind": "audit",
  "priority": "P1",
  "resourceName": "assets",
  "resourceProvider": "aws",
  "lastModified": "2026-03-05T06:07:08.5Z",
  "policyName": "s3-no-public",
  "policyPack": "aws-guardrails",
  "policyPackTag": "3.1.0",
  "level": "mandatory",
  "severity": "critical",
  "status": "open",
  "resourceURN": "urn:pulumi:prod::web::aws:s3/bucket:Bucket::assets",
  "resourceType": "aws:s3/bucket:Bucket",
  "entityProject": "web",
  "entityId": "prod",
  "message": "Bucket must not allow public access & <must> be \"private\".",
  "observedAt": "2026-03-04T05:06:07.123456Z"
}
`, got)
}

func TestPin_PolicyIssueGet_JSON_Minimal(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error {
		return renderPolicyIssueGetJSON(w, cloudapitype.GetPolicyIssueResponse{PolicyIssue: pinIssueMinimal()})
	})
	assert.JSONEq(t, `{
  "id": "issue-2",
  "policyName": "require-owner",
  "policyPack": "tagging",
  "level": "advisory"
}
`, got)
}

func TestPin_PolicyIssueGet_Table(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error {
		return renderPolicyIssueGetText(w, cloudapitype.GetPolicyIssueResponse{PolicyIssue: pinIssueFull()})
	})
	assert.Equal(t, `ID:                  issue-1
Policy pack:         aws-guardrails@3.1.0
Policy:              s3-no-public
Enforcement level:   mandatory
Severity:            critical
Status:              open
Priority:            P1
Kind:                audit
Stack:               web/prod
Resource URN:        urn:pulumi:prod::web::aws:s3/bucket:Bucket::assets
Resource type:       aws:s3/bucket:Bucket
Observed at:         2026-03-04T05:06:07.123456Z
Message:             Bucket must not allow public access & <must> be "private".
`, got)
}
