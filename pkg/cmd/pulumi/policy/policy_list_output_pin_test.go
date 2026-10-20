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

	"github.com/stretchr/testify/assert"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
)

func pinPolicyPacks() []apitype.PolicyPackWithVersions {
	return []apitype.PolicyPackWithVersions{
		{
			Name:        "aws-guardrails",
			DisplayName: "AWS Guardrails",
			Versions:    []int{1, 2, 3},
			VersionTags: []string{"1.0.0", "2.0.0", "3.1.0"},
		},
		{Name: "tagging", DisplayName: "Tagging", Versions: []int{7}, VersionTags: []string{"7.0.0"}},
	}
}

func TestPin_PolicyList_JSON(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return formatPolicyPacksJSON(w, pinPolicyPacks()) })
	assert.JSONEq(t, `[
  {
    "name": "aws-guardrails",
    "versions": [
      "1.0.0",
      "2.0.0",
      "3.1.0"
    ]
  },
  {
    "name": "tagging",
    "versions": [
      "7.0.0"
    ]
  }
]
`, got)
}

func TestPin_PolicyList_Table(t *testing.T) {
	t.Parallel()
	got := renderPin(t, func(w *bytes.Buffer) error { return formatPolicyPacksConsole(w, pinPolicyPacks()) })
	assert.Equal(t, `NAME            VERSIONS
aws-guardrails  1.0.0, 2.0.0, 3.1.0
tagging         7.0.0
`, got)
}
