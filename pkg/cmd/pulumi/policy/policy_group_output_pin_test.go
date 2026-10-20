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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
)

func pinRawJSONPtr(s string) *json.RawMessage {
	return new(json.RawMessage(s))
}

func pinGroupSummariesFull() []apitype.PolicyGroupSummary {
	return []apitype.PolicyGroupSummary{
		{
			Name:                  "default-policy-group",
			IsOrgDefault:          true,
			NumStacks:             42,
			NumAccounts:           3,
			EntityType:            apitype.Stacks,
			Mode:                  apitype.PolicyGroupModePreventative,
			NumEnabledPolicyPacks: 5,
		},
		{
			Name:                  "audit-accounts",
			IsOrgDefault:          false,
			NumStacks:             0,
			NumAccounts:           7,
			EntityType:            apitype.Accounts,
			Mode:                  apitype.PolicyGroupModeAudit,
			NumEnabledPolicyPacks: 2,
		},
	}
}

func pinGroupSummariesMinimal() []apitype.PolicyGroupSummary {
	return []apitype.PolicyGroupSummary{{Name: "bare", EntityType: apitype.Stacks}}
}

func pinGroupFull() apitype.GetPolicyGroupResponse {
	return apitype.GetPolicyGroupResponse{
		Name:         "prod-policies",
		IsOrgDefault: true,
		EntityType:   apitype.Stacks,
		Mode:         apitype.PolicyGroupModePreventative,
		Stacks: []apitype.PulumiStackReference{
			{Name: "prod", RoutingProject: "web"},
			{Name: "standalone"},
		},
		AppliedPolicyPacks: []apitype.PolicyPackMetadata{
			{
				Name:        "aws-guardrails",
				DisplayName: "AWS Guardrails",
				Version:     3,
				VersionTag:  "3.1.0",
				Config: map[string]*json.RawMessage{
					"s3-no-public": pinRawJSONPtr(`{"enforcementLevel":"mandatory","nested":{"tags":["a","b"],"limit":2.5}}`),
				},
				Environments: []string{"infra/policy-secrets", "infra/other@v2"},
			},
			{Name: "tagging", Version: 7},
		},
		Accounts:    []string{"prod-aws", "prod-gcp"},
		AgentPoolID: "pool-123",
	}
}

func pinGroupMinimal() apitype.GetPolicyGroupResponse {
	return apitype.GetPolicyGroupResponse{
		Name:       "bare",
		EntityType: apitype.Accounts,
		Mode:       apitype.PolicyGroupModeAudit,
	}
}

func TestPin_PolicyGroupList_JSON_Full(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return formatPolicyGroupsJSON(w, pinGroupSummariesFull()) })
	assert.JSONEq(t, `[
  {
    "name": "default-policy-group",
    "default": true,
    "numPolicyPacks": 5,
    "numStacks": 42
  },
  {
    "name": "audit-accounts",
    "default": false,
    "numPolicyPacks": 2,
    "numStacks": 0
  }
]
`, got)
}

func TestPin_PolicyGroupList_JSON_Minimal(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return formatPolicyGroupsJSON(w, pinGroupSummariesMinimal()) })
	assert.JSONEq(t, `[
  {
    "name": "bare",
    "default": false,
    "numPolicyPacks": 0,
    "numStacks": 0
  }
]
`, got)
}

func TestPin_PolicyGroupList_Table(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return formatPolicyGroupsConsole(w, pinGroupSummariesFull()) })
	assert.Equal(t, `NAME                  DEFAULT  ENABLED POLICY PACKS  STACKS
default-policy-group  Y        5                     42
audit-accounts        N        2                     0
`, got)
}

func TestPin_PolicyGroupGet_JSON_Full(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyGroupGetJSON(w, pinGroupFull()) })
	assert.JSONEq(t, `{
  "name": "prod-policies",
  "isOrgDefault": true,
  "entityType": "stacks",
  "mode": "preventative",
  "stacks": [
    {
      "name": "prod",
      "routingProject": "web"
    },
    {
      "name": "standalone"
    }
  ],
  "appliedPolicyPacks": [
    {
      "name": "aws-guardrails",
      "displayName": "AWS Guardrails",
      "version": 3,
      "versionTag": "3.1.0",
      "config": {
        "s3-no-public": {
          "enforcementLevel": "mandatory",
          "nested": {
            "tags": [
              "a",
              "b"
            ],
            "limit": 2.5
          }
        }
      },
      "environments": [
        "infra/policy-secrets",
        "infra/other@v2"
      ]
    },
    {
      "name": "tagging",
      "version": 7
    }
  ],
  "accounts": [
    "prod-aws",
    "prod-gcp"
  ],
  "agentPoolId": "pool-123"
}
`, got)
}

func TestPin_PolicyGroupGet_JSON_Minimal(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyGroupGetJSON(w, pinGroupMinimal()) })
	assert.JSONEq(t, `{
  "name": "bare",
  "isOrgDefault": false,
  "entityType": "accounts",
  "mode": "audit",
  "stacks": [],
  "appliedPolicyPacks": [],
  "accounts": []
}
`, got)
}

func TestPin_PolicyGroupGet_Table(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyGroupGetText(w, pinGroupFull()) })
	assert.Equal(t, `Name:                  prod-policies
Org default:           yes
Entity type:           stacks
Mode:                  preventative
Agent pool:            pool-123
Applied policy packs:  2
  - aws-guardrails (3.1.0)
  - tagging (v7)
Stacks:                2
  - web/prod
  - standalone
Accounts:              2
  - prod-aws
  - prod-gcp
`, got)
}

func TestPin_PolicyGroupNew_JSON(t *testing.T) {
	t.Parallel()

	c := &mockPolicyGroupNewClient{getResp: pinGroupFull()}
	args := policyGroupNewArgs{
		entityType:   "stacks",
		mode:         "preventative",
		agentPoolID:  "pool-123",
		yes:          true,
		outputFormat: defaultPolicyGroupGetOutputFormat(),
	}
	require.NoError(t, args.outputFormat.Set("json"))
	var buf bytes.Buffer
	require.NoError(t, runPolicyGroupNew(t.Context(), &buf,
		stubPolicyGroupNewFactory(c, "acme"), "prod-policies", args))
	assert.JSONEq(t, `{
  "name": "prod-policies",
  "isOrgDefault": true,
  "entityType": "stacks",
  "mode": "preventative",
  "stacks": [
    {
      "name": "prod",
      "routingProject": "web"
    },
    {
      "name": "standalone"
    }
  ],
  "appliedPolicyPacks": [
    {
      "name": "aws-guardrails",
      "displayName": "AWS Guardrails",
      "version": 3,
      "versionTag": "3.1.0",
      "config": {
        "s3-no-public": {
          "enforcementLevel": "mandatory",
          "nested": {
            "tags": [
              "a",
              "b"
            ],
            "limit": 2.5
          }
        }
      },
      "environments": [
        "infra/policy-secrets",
        "infra/other@v2"
      ]
    },
    {
      "name": "tagging",
      "version": 7
    }
  ],
  "accounts": [
    "prod-aws",
    "prod-gcp"
  ],
  "agentPoolId": "pool-123"
}
`, buf.String())
}

func TestPin_PolicyGroupEdit_JSON(t *testing.T) {
	t.Parallel()

	c := &mockPolicyGroupEditClient{getResp: pinGroupFull()}
	args := policyGroupEditArgs{
		outputFormat: defaultPolicyGroupGetOutputFormat(),
		rename:       "prod-policies",
		changed:      map[string]bool{"name": true},
	}
	require.NoError(t, args.outputFormat.Set("json"))
	var buf bytes.Buffer
	require.NoError(t, runPolicyGroupEdit(t.Context(), &buf,
		stubPolicyGroupEditFactory(c, "acme"), "old-name", args))
	assert.JSONEq(t, `{
  "name": "prod-policies",
  "isOrgDefault": true,
  "entityType": "stacks",
  "mode": "preventative",
  "stacks": [
    {
      "name": "prod",
      "routingProject": "web"
    },
    {
      "name": "standalone"
    }
  ],
  "appliedPolicyPacks": [
    {
      "name": "aws-guardrails",
      "displayName": "AWS Guardrails",
      "version": 3,
      "versionTag": "3.1.0",
      "config": {
        "s3-no-public": {
          "enforcementLevel": "mandatory",
          "nested": {
            "tags": [
              "a",
              "b"
            ],
            "limit": 2.5
          }
        }
      },
      "environments": [
        "infra/policy-secrets",
        "infra/other@v2"
      ]
    },
    {
      "name": "tagging",
      "version": 7
    }
  ],
  "accounts": [
    "prod-aws",
    "prod-gcp"
  ],
  "agentPoolId": "pool-123"
}
`, buf.String())
}

func TestPin_PolicyGroupRemove_JSON(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyGroupRemoveJSON(w, "acme", "prod-policies") })
	assert.JSONEq(t, `{
  "organizationName": "acme",
  "name": "prod-policies"
}
`, got)
}

func TestPin_PolicyGroupRemove_Table(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return renderPolicyGroupRemoveText(w, "acme", "prod-policies") })
	assert.Equal(t, `Removed policy group prod-policies from organization acme.
`, got)
}
