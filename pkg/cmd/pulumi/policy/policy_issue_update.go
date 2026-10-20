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
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pulumi/pulumi/pkg/v3/backend/display"
	"github.com/pulumi/pulumi/pkg/v3/backend/httpstate"
	cmdBackend "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/backend"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/constrictor"
	"github.com/pulumi/pulumi/pkg/v3/util/outputflag"
	pkgWorkspace "github.com/pulumi/pulumi/pkg/v3/workspace"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
)

const policyIssueUpdateConcurrency = 4

// policyIssueUpdateStatuses are the statuses a user may set; the API also
// defines by_design and fixed, which are assigned by the service.
var policyIssueUpdateStatuses = []cloudapitype.PolicyIssueStatus{
	cloudapitype.PolicyIssueStatusOpen,
	cloudapitype.PolicyIssueStatusInProgress,
	cloudapitype.PolicyIssueStatusIgnored,
}

type policyIssueUpdateClient interface {
	UpdatePolicyIssue(
		ctx context.Context, orgName, issueID string, req cloudapitype.UpdatePolicyIssueRequest,
	) (cloudapitype.GetPolicyIssueResponse, error)
}

// policyIssueUpdateClientFactory returns the client, the organization, and the
// current user's login (used to resolve `--assignee me`).
type policyIssueUpdateClientFactory func(
	ctx context.Context, orgFlag string,
) (policyIssueUpdateClient, string, string, error)

type policyIssueUpdateArgs struct {
	org          string
	status       string
	priority     string
	assignee     string
	unassign     bool
	outputFormat outputflag.OutputFlag[policyIssueUpdateRenderFunc]
}

type policyIssueUpdateRenderFunc func(w io.Writer, results []policyIssueUpdateResult) error

type policyIssueUpdateResult struct {
	ID    string              `json:"id"`
	OK    bool                `json:"ok"`
	Issue *policyIssueGetJSON `json:"issue,omitempty"`
	Error string              `json:"error,omitempty"`
}

type policyIssueUpdateJSON struct {
	Results []policyIssueUpdateResult `json:"results"`
	Updated int                       `json:"updated"`
	Failed  int                       `json:"failed"`
}

func defaultPolicyIssueUpdateOutputFormat() outputflag.OutputFlag[policyIssueUpdateRenderFunc] {
	return outputflag.OutputFlag[policyIssueUpdateRenderFunc]{
		RenderForTerminal: renderPolicyIssueUpdateText,
		RenderJSON:        renderPolicyIssueUpdateJSON,
	}
}

func newPolicyIssueUpdateCmd() *cobra.Command {
	return newPolicyIssueUpdateCmdWith(defaultPolicyIssueUpdateClientFactory)
}

func newPolicyIssueUpdateCmdWith(factory policyIssueUpdateClientFactory) *cobra.Command {
	contract.Assertf(factory != nil, "policyIssueUpdateClientFactory must not be nil")
	var args policyIssueUpdateArgs
	args.outputFormat = defaultPolicyIssueUpdateOutputFormat()

	cmd := &cobra.Command{
		Use:   "update <issue-id>...",
		Short: "[EXPERIMENTAL] Update the status, priority or assignee of policy issues",
		Long: "[EXPERIMENTAL] Update the status, priority or assignee of one or more policy issues.\n" +
			"\n" +
			"At least one of --status, --priority, --assignee or --unassign is required, and the\n" +
			"same change is applied to every issue ID given. Issues are updated independently: a\n" +
			"failure on one issue does not stop the others, and the command exits with an error if\n" +
			"any update failed.\n" +
			"\n" +
			"Allowed values:\n" +
			"  --status    open, in_progress, ignored\n" +
			"  --priority  p0, p1, p2, p3, p4\n" +
			"  --assignee  the Pulumi login of an organization member, or 'me'\n" +
			"              for the current user\n" +
			"\n" +
			"Pass --output=json for a machine-readable result per issue.",
		Example: "  # Mark a single policy issue as in progress\n" +
			"  pulumi policy issue update <issue-id> --status in_progress\n\n" +
			"  # Triage several policy issues at once\n" +
			"  pulumi policy issue update <issue-id-1> <issue-id-2> <issue-id-3> \\\n" +
			"      --priority p1 --assignee me\n\n" +
			"  # Clear the assignee of a policy issue\n" +
			"  pulumi policy issue update <issue-id> --unassign",
		RunE: func(cmd *cobra.Command, posArgs []string) error {
			return runPolicyIssueUpdate(cmd.Context(), cmd.OutOrStdout(), factory, posArgs, args)
		},
	}

	constrictor.AttachArguments(cmd, &constrictor.Arguments{
		Arguments: []constrictor.Argument{
			{Name: "issue-id"},
		},
		Required: 1,
		Variadic: true,
	})

	cmd.Flags().StringVar(&args.org, "org", "", "The organization that owns the issues")
	cmd.Flags().StringVar(&args.status, "status", "",
		"Set the status ("+joinPolicyIssueValues(policyIssueUpdateStatuses)+")")
	cmd.Flags().StringVar(&args.priority, "priority", "",
		"Set the priority ("+joinPolicyIssueValues(cloudapitype.PolicyIssuePriority("").AllValues())+")")
	cmd.Flags().StringVar(&args.assignee, "assignee", "",
		"Assign to the Pulumi login of an organization member, or 'me' for the current user")
	cmd.Flags().BoolVar(&args.unassign, "unassign", false, "Clear the assignee")
	cmd.MarkFlagsMutuallyExclusive("assignee", "unassign")
	outputflag.VarP(cmd.Flags(), &args.outputFormat)

	return cmd
}

func defaultPolicyIssueUpdateClientFactory(
	ctx context.Context, orgFlag string,
) (policyIssueUpdateClient, string, string, error) {
	ws := pkgWorkspace.Instance
	opts := display.Options{Color: cmdutil.GetGlobalColorization()}

	be, err := cmdBackend.CurrentBackend(ctx, ws, cmdBackend.DefaultLoginManager, nil, opts)
	if err != nil {
		return nil, "", "", err
	}
	cloudBackend, ok := be.(httpstate.Backend)
	if !ok {
		return nil, "", "", errors.New(
			"updating policy issues requires the Pulumi Cloud backend; run `pulumi login`")
	}

	userName, orgs, _, err := cloudBackend.CurrentUser()
	if err != nil {
		return nil, "", "", err
	}

	org := orgFlag
	if org == "" {
		defaultOrg, err := cloudBackend.GetDefaultOrg(ctx)
		if err != nil {
			return nil, "", "", err
		}
		org = defaultOrg
	}
	if org == "" {
		org = userName
	}

	if !slices.Contains(orgs, org) && org != userName {
		return nil, "", "", fmt.Errorf("user %s is not a member of organization %s", userName, org)
	}

	return cloudBackend.Client(), org, userName, nil
}

func joinPolicyIssueValues[T ~string](values []T) string {
	names := make([]string, len(values))
	for i, v := range values {
		names[i] = string(v)
	}
	return strings.Join(names, ", ")
}

func validatePolicyIssueUpdateArgs(args policyIssueUpdateArgs) error {
	if args.status != "" &&
		!slices.Contains(policyIssueUpdateStatuses, cloudapitype.PolicyIssueStatus(args.status)) {
		return fmt.Errorf("invalid status %q: must be one of %s",
			args.status, joinPolicyIssueValues(policyIssueUpdateStatuses))
	}
	if priority := cloudapitype.PolicyIssuePriority(args.priority); args.priority != "" && !priority.IsValid() {
		return fmt.Errorf("invalid priority %q: must be one of %s",
			args.priority, joinPolicyIssueValues(priority.AllValues()))
	}
	if args.status == "" && args.priority == "" && args.assignee == "" && !args.unassign {
		return errors.New("nothing to update: specify at least one of --status, --priority, --assignee or --unassign")
	}
	return nil
}

func buildUpdatePolicyIssueRequest(
	args policyIssueUpdateArgs, currentLogin string,
) (cloudapitype.UpdatePolicyIssueRequest, error) {
	var req cloudapitype.UpdatePolicyIssueRequest
	if err := validatePolicyIssueUpdateArgs(args); err != nil {
		return req, err
	}

	if args.status != "" {
		status := cloudapitype.PolicyIssueStatus(args.status)
		req.Status = &status
	}
	if args.priority != "" {
		priority := cloudapitype.PolicyIssuePriority(args.priority)
		req.Priority = &priority
	}

	switch {
	case args.unassign:
		empty := ""
		req.AssignedTo = &empty
	case args.assignee == "me":
		if currentLogin == "" {
			return req, errors.New("unable to determine the current user for --assignee me")
		}
		req.AssignedTo = &currentLogin
	case args.assignee != "":
		assignee := args.assignee
		req.AssignedTo = &assignee
	}
	return req, nil
}

func runPolicyIssueUpdate(
	ctx context.Context, w io.Writer,
	factory policyIssueUpdateClientFactory, issueIDs []string, args policyIssueUpdateArgs,
) error {
	if err := validatePolicyIssueUpdateArgs(args); err != nil {
		return err
	}

	c, org, login, err := factory(ctx, args.org)
	if err != nil {
		return err
	}

	req, err := buildUpdatePolicyIssueRequest(args, login)
	if err != nil {
		return err
	}

	ids := make([]string, 0, len(issueIDs))
	for _, id := range issueIDs {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}

	results := make([]policyIssueUpdateResult, len(ids))
	var group errgroup.Group
	group.SetLimit(policyIssueUpdateConcurrency)
	for i, id := range ids {
		group.Go(func() error {
			results[i] = policyIssueUpdateResult{ID: id}
			resp, err := c.UpdatePolicyIssue(ctx, org, id, req)
			if err != nil {
				results[i].Error = strings.TrimPrefix(err.Error(), "updating policy issue: ")
				return nil
			}
			issue := toPolicyIssueGetJSON(resp)
			results[i].OK = true
			results[i].Issue = &issue
			return nil
		})
	}
	contract.IgnoreError(group.Wait())

	if err := args.outputFormat.Get()(w, results); err != nil {
		return err
	}

	failed := 0
	for _, r := range results {
		if !r.OK {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("failed to update %d of %d policy issues", failed, len(results))
	}
	return nil
}

func renderPolicyIssueUpdateText(w io.Writer, results []policyIssueUpdateResult) error {
	updated := 0
	for _, r := range results {
		if !r.OK {
			fmt.Fprintf(w, "✗ %s: %s\n", r.ID, r.Error)
			continue
		}
		updated++
		fmt.Fprintf(w, "✓ %s: status=%s priority=%s assignee=%s\n",
			r.ID, orDash(r.Issue.Status), orDash(r.Issue.Priority), orDash(r.Issue.AssignedTo))
	}
	fmt.Fprintf(w, "Updated %d of %d policy issue(s).\n", updated, len(results))
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func renderPolicyIssueUpdateJSON(w io.Writer, results []policyIssueUpdateResult) error {
	out := policyIssueUpdateJSON{Results: results}
	for _, r := range results {
		if r.OK {
			out.Updated++
		} else {
			out.Failed++
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
