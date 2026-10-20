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

package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
)

func TestPin_ListPolicyIssues_Body(t *testing.T) {
	t.Parallel()

	var got capturedRequest
	c := newCapturingClient(t, &got)
	_, err := c.ListPolicyIssues(t.Context(), "acme", ListPolicyIssuesOptions{StartRow: 100, EndRow: 200})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/api/orgs/acme/policyresults/issues", got.path)
	assert.JSONEq(t, `{"startRow": 100, "endRow": 200, "sortModel": null}`, got.body)
}

func TestPin_GetPolicyComplianceResults_Body(t *testing.T) {
	t.Parallel()

	var got capturedRequest
	c := newCapturingClient(t, &got)
	size := 50
	token := "next-page-token"
	_, err := c.GetPolicyComplianceResults(t.Context(), "acme", apitype.GetPolicyComplianceResultsRequest{
		Entity:            "stack",
		Size:              &size,
		ContinuationToken: &token,
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/api/orgs/acme/policyresults/compliance", got.path)
	assert.JSONEq(t, `{"entity": "stack", "size": 50, "continuationToken": "next-page-token"}`, got.body)
}
