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
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/spf13/cobra"

	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/constrictor"
	"github.com/pulumi/pulumi/pkg/v3/util/outputflag"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
)

type policyCompliancePoliciesClient interface {
	ListPoliciesCompliance(
		ctx context.Context, orgName string, req cloudapitype.AngularGridGetRowsRequest,
	) (cloudapitype.ListPoliciesComplianceResponse, error)
}

type policyCompliancePoliciesClientFactory func(
	ctx context.Context, orgFlag string,
) (client policyCompliancePoliciesClient, org string, err error)

type policyCompliancePoliciesRenderFunc func(w io.Writer, rows []cloudapitype.PolicyComplianceRow) error

type policyCompliancePoliciesArgs struct {
	org          string
	filters      policyIssueFilters
	outputFormat outputflag.OutputFlag[policyCompliancePoliciesRenderFunc]
}

const policyCompliancePoliciesPageSize = 100

func newPolicyCompliancePoliciesCmd() *cobra.Command {
	return newPolicyCompliancePoliciesCmdWith(defaultPolicyCompliancePoliciesClientFactory)
}

func newPolicyCompliancePoliciesCmdWith(factory policyCompliancePoliciesClientFactory) *cobra.Command {
	contract.Assertf(factory != nil, "policyCompliancePoliciesClientFactory must not be nil")
	var args policyCompliancePoliciesArgs
	args.outputFormat = outputflag.OutputFlag[policyCompliancePoliciesRenderFunc]{
		RenderForTerminal: renderPolicyCompliancePoliciesTable,
		RenderJSON:        renderPolicyCompliancePoliciesJSON,
	}

	cmd := &cobra.Command{
		Use:   "policies",
		Short: "[EXPERIMENTAL] List policies with failing resources",
		Long: "[EXPERIMENTAL] List the policies that have failing resources in an organization.\n" +
			"\n" +
			"Each row is a policy, with its policy pack, policy group, severity and the\n" +
			"number of resources failing it. All matching policies are returned.\n" +
			"\n" +
			"Default output is a human-readable table; pass --output=json for JSON.",
		Example: "  # List policies with failing resources\n" +
			"  pulumi policy compliance policies\n\n" +
			"  # List failing critical policies from one pack as JSON\n" +
			"  pulumi policy compliance policies --pack aws --severity critical -o json",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyCompliancePolicies(cmd.Context(), cmd.OutOrStdout(), factory, args)
		},
	}

	constrictor.AttachArguments(cmd, constrictor.NoArgs)

	cmd.Flags().StringVar(&args.org, "org", "", "The organization to list policy compliance for")
	addPolicyIssueFilterFlags(cmd.Flags(), &args.filters,
		filterSeverity|filterPack|filterPolicy|filterGroup|filterStack|filterAccount|filterResourceType)
	outputflag.VarP(cmd.Flags(), &args.outputFormat)

	return cmd
}

func defaultPolicyCompliancePoliciesClientFactory(
	ctx context.Context, orgFlag string,
) (policyCompliancePoliciesClient, string, error) {
	c, org, _, err := resolvePolicyIssueCloudClient(ctx, orgFlag, "listing policy compliance")
	if err != nil {
		return nil, "", err
	}
	return c, org, nil
}

func runPolicyCompliancePolicies(
	ctx context.Context, w io.Writer,
	factory policyCompliancePoliciesClientFactory, args policyCompliancePoliciesArgs,
) error {
	filterModel, _, err := buildPolicyIssueGrid(args.filters, "")
	if err != nil {
		return err
	}

	c, org, err := factory(ctx, args.org)
	if err != nil {
		return err
	}

	var rows []cloudapitype.PolicyComplianceRow
	for startRow := 0; ; startRow += policyCompliancePoliciesPageSize {
		resp, err := c.ListPoliciesCompliance(ctx, org, cloudapitype.AngularGridGetRowsRequest{
			StartRow:    startRow,
			EndRow:      startRow + policyCompliancePoliciesPageSize,
			FilterModel: filterModel,
		})
		if err != nil {
			return fmt.Errorf("listing policy compliance: %w", err)
		}
		rows = append(rows, resp.Policies...)
		if len(resp.Policies) < policyCompliancePoliciesPageSize {
			break
		}
	}

	return args.outputFormat.Get()(w, rows)
}

func renderPolicyCompliancePoliciesTable(w io.Writer, rows []cloudapitype.PolicyComplianceRow) error {
	if len(rows) == 0 {
		fmt.Fprintln(w, "No failing policies found for this organization.")
		return nil
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"POLICY PACK", "POLICY", "GROUP", "SEVERITY", "FAILING RESOURCES"})
	for _, row := range rows {
		severity := string(row.Severity)
		if severity == "" {
			severity = "-"
		}
		t.AppendRow(table.Row{row.PolicyPack, row.PolicyName, row.PolicyGroupName, severity, row.FailingResources})
	}
	t.Render()
	return nil
}

// The service fills governedResources and percentCompliant with a placeholder (governed is always 100), so they
// are deliberately not exposed.
type policyComplianceRowJSON struct {
	PolicyPack       string `json:"policyPack"`
	PolicyName       string `json:"policyName"`
	PolicyGroupName  string `json:"policyGroupName"`
	PolicyGroupType  string `json:"policyGroupType,omitempty"`
	Severity         string `json:"severity,omitempty"`
	FailingResources int    `json:"failingResources"`
}

type policyCompliancePoliciesJSON struct {
	Policies []policyComplianceRowJSON `json:"policies"`
}

func renderPolicyCompliancePoliciesJSON(w io.Writer, rows []cloudapitype.PolicyComplianceRow) error {
	out := policyCompliancePoliciesJSON{Policies: make([]policyComplianceRowJSON, 0, len(rows))}
	for _, row := range rows {
		out.Policies = append(out.Policies, policyComplianceRowJSON{
			PolicyPack:       row.PolicyPack,
			PolicyName:       row.PolicyName,
			PolicyGroupName:  row.PolicyGroupName,
			PolicyGroupType:  string(row.PolicyGroupType),
			Severity:         string(row.Severity),
			FailingResources: row.FailingResources,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
