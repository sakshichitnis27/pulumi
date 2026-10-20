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
	"fmt"
	"slices"
	"strings"

	cloudapitype "github.com/pulumi/pulumi-cloud-sdk/go/apitype"
	"github.com/spf13/pflag"
)

type policyIssueFilters struct {
	severities, priorities, statuses []string
	packs, policies, groups          []string
	stacks, accounts                 []string
	resourceTypes, urns              []string
	assignedTo                       []string
	sort                             []string // "<field>[:asc|desc]"
}

// policyIssueFilterSet is a bitmask of the filter flags a command registers.
type policyIssueFilterSet int

const (
	filterSeverity policyIssueFilterSet = 1 << iota
	filterPriority
	filterStatus
	filterPack
	filterPolicy
	filterGroup
	filterStack
	filterAccount
	filterResourceType
	filterURN
	filterAssignedTo
	filterSort

	filterAll = filterSort<<1 - 1
)

const (
	gridFilterTypeText = "text"
	gridOpEquals       = "equals"
	gridCombinatorAnd  = "AND"
	gridCombinatorOr   = "OR"
	gridSortAsc        = "asc"
	gridSortDesc       = "desc"
	assignedToMe       = "me"

	colEntityType    = "entityType"
	colEntityProject = "entityProject"
	colEntityID      = "entityId"
)

var policyIssueSortFields = []string{
	"severity", "priority", "status", "observedAt", "lastModified",
	"policyPack", "policyName", "policyGroupName", "resourceType",
}

var policyIssueSortDirections = []string{gridSortAsc, gridSortDesc}

type policyIssueFilterColumn struct {
	flag    string
	which   policyIssueFilterSet
	colID   string
	allowed []string
	usage   string
	values  func(*policyIssueFilters) *[]string
}

func enumStrings[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, v := range all {
		if v != "" {
			out = append(out, string(v))
		}
	}
	return out
}

// policyIssueFilterColumns lists the simple one-flag-one-column filters in the order they are ANDed.
// The stack and account filters span several columns and are handled separately, between group and
// resourceType.
func policyIssueFilterColumns() []policyIssueFilterColumn {
	return []policyIssueFilterColumn{
		{
			flag: "severity", which: filterSeverity, colID: "severity",
			allowed: enumStrings(cloudapitype.AppPolicySeverity("").AllValues()),
			usage:   "Filter by severity (repeatable)",
			values:  func(f *policyIssueFilters) *[]string { return &f.severities },
		},
		{
			flag: "priority", which: filterPriority, colID: "priority",
			allowed: enumStrings(cloudapitype.PolicyIssuePriority("").AllValues()),
			usage:   "Filter by priority (repeatable)",
			values:  func(f *policyIssueFilters) *[]string { return &f.priorities },
		},
		{
			flag: "status", which: filterStatus, colID: "status",
			allowed: enumStrings(cloudapitype.PolicyIssueStatus("").AllValues()),
			usage:   "Filter by status (repeatable)",
			values:  func(f *policyIssueFilters) *[]string { return &f.statuses },
		},
		{
			flag: "pack", which: filterPack, colID: "policyPack",
			usage:  "Filter by policy pack (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.packs },
		},
		{
			flag: "policy", which: filterPolicy, colID: "policyName",
			usage:  "Filter by policy name (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.policies },
		},
		{
			flag: "group", which: filterGroup, colID: "policyGroupName",
			usage:  "Filter by policy group (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.groups },
		},
		{
			flag: "resource-type", which: filterResourceType, colID: "resourceType",
			usage:  "Filter by resource type (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.resourceTypes },
		},
		{
			flag: "urn", which: filterURN, colID: "resourceURN",
			usage:  "Filter by resource URN (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.urns },
		},
		{
			flag: "assigned-to", which: filterAssignedTo, colID: "assignedTo",
			usage:  "Filter by assignee login, or 'me' for the current user (repeatable)",
			values: func(f *policyIssueFilters) *[]string { return &f.assignedTo },
		},
	}
}

func (c policyIssueFilterColumn) fullUsage() string {
	if len(c.allowed) == 0 {
		return c.usage
	}
	return fmt.Sprintf("%s. One of: %s", c.usage, strings.Join(c.allowed, ", "))
}

// addPolicyIssueFilterFlags registers the filter flags selected by which and binds them to f.
func addPolicyIssueFilterFlags(flags *pflag.FlagSet, f *policyIssueFilters, which policyIssueFilterSet) {
	for _, c := range policyIssueFilterColumns() {
		if which&c.which != 0 {
			flags.StringArrayVar(c.values(f), c.flag, nil, c.fullUsage())
		}
	}
	if which&filterStack != 0 {
		flags.StringArrayVar(&f.stacks, "stack", nil,
			"Filter by stack, as <project>/<stack> (repeatable)")
	}
	if which&filterAccount != 0 {
		flags.StringArrayVar(&f.accounts, "account", nil,
			"Filter by Insights account (repeatable)")
	}
	if which&filterSort != 0 {
		flags.StringArrayVar(&f.sort, "sort", nil,
			"Sort by <field>[:asc|desc], default asc (repeatable). Fields: "+
				strings.Join(policyIssueSortFields, ", "))
	}
}

// empty reports whether no filter or sort flag was set.
func (f policyIssueFilters) empty() bool {
	return len(f.severities)+len(f.priorities)+len(f.statuses)+
		len(f.packs)+len(f.policies)+len(f.groups)+
		len(f.stacks)+len(f.accounts)+
		len(f.resourceTypes)+len(f.urns)+
		len(f.assignedTo)+len(f.sort) == 0
}

func gridLeaf(colID, value string) cloudapitype.AngularGridFilterModel {
	return cloudapitype.AngularGridFilterModel{
		ColID:      colID,
		FilterType: gridFilterTypeText,
		Type:       gridOpEquals,
		Filter:     value,
	}
}

func gridGroup(combinator string, conds []cloudapitype.AngularGridFilterModel) cloudapitype.AngularGridFilterModel {
	if len(conds) == 1 {
		return conds[0]
	}
	return cloudapitype.AngularGridFilterModel{Type: combinator, Conditions: conds}
}

func validateFlagValues(flag string, values, allowed []string) error {
	for _, v := range values {
		if v == "" {
			return fmt.Errorf("invalid value %q for --%s: must not be empty", v, flag)
		}
		if allowed != nil && !slices.Contains(allowed, v) {
			return fmt.Errorf("invalid value %q for --%s: must be one of %s", v, flag, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func validateStack(s string) error {
	project, stack, ok := strings.Cut(s, "/")
	if !ok || project == "" || stack == "" || strings.Contains(stack, "/") {
		return fmt.Errorf("invalid value %q for --stack: expected <project>/<stack>", s)
	}
	return nil
}

// validatePolicyIssueFilters checks every filter and sort flag value without needing the current user, so bad
// input is rejected before the backend is resolved.
func validatePolicyIssueFilters(f policyIssueFilters) error {
	for _, c := range policyIssueFilterColumns() {
		if err := validateFlagValues(c.flag, *c.values(&f), c.allowed); err != nil {
			return err
		}
	}
	if err := validateFlagValues("stack", f.stacks, nil); err != nil {
		return err
	}
	for _, s := range f.stacks {
		if err := validateStack(s); err != nil {
			return err
		}
	}
	if err := validateFlagValues("account", f.accounts, nil); err != nil {
		return err
	}
	if err := validateFlagValues("sort", f.sort, nil); err != nil {
		return err
	}
	_, err := buildSortModel(f.sort)
	return err
}

func entityFilter(parts ...[2]string) cloudapitype.AngularGridFilterModel {
	conds := make([]cloudapitype.AngularGridFilterModel, 0, len(parts))
	for _, p := range parts {
		conds = append(conds, gridLeaf(p[0], p[1]))
	}
	return cloudapitype.AngularGridFilterModel{Type: gridCombinatorAnd, Conditions: conds}
}

func buildStackCondition(stacks []string) cloudapitype.AngularGridFilterModel {
	conds := make([]cloudapitype.AngularGridFilterModel, 0, len(stacks))
	for _, s := range stacks {
		project, stack, _ := strings.Cut(s, "/")
		conds = append(conds, entityFilter(
			[2]string{colEntityType, string(cloudapitype.IssueEntityTypeStack)},
			[2]string{colEntityProject, project},
			[2]string{colEntityID, stack},
		))
	}
	return gridGroup(gridCombinatorOr, conds)
}

func buildAccountCondition(accounts []string) cloudapitype.AngularGridFilterModel {
	conds := make([]cloudapitype.AngularGridFilterModel, 0, len(accounts))
	for _, a := range accounts {
		conds = append(conds, entityFilter(
			[2]string{colEntityType, string(cloudapitype.IssueEntityTypeInsightsAccount)},
			[2]string{colEntityProject, a},
		))
	}
	return gridGroup(gridCombinatorOr, conds)
}

// policyComplianceSortModel orders the grouped compliance rows. The service sorts them by count alone, so the group
// columns break ties to keep offset paging from repeating or skipping rows.
func policyComplianceSortModel() []cloudapitype.AngularGridSortModelItem {
	return []cloudapitype.AngularGridSortModelItem{
		{ColID: "failingResources", Sort: gridSortDesc},
		{ColID: "policyPack", Sort: gridSortAsc},
		{ColID: "policyName", Sort: gridSortAsc},
		{ColID: "policyGroupName", Sort: gridSortAsc},
	}
}

func buildSortModel(specs []string) ([]cloudapitype.AngularGridSortModelItem, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	items := make([]cloudapitype.AngularGridSortModelItem, 0, len(specs))
	for _, spec := range specs {
		field, dir, hasDir := strings.Cut(spec, ":")
		if !slices.Contains(policyIssueSortFields, field) {
			return nil, fmt.Errorf("invalid field %q for --sort: must be one of %s",
				field, strings.Join(policyIssueSortFields, ", "))
		}
		if !hasDir {
			dir = gridSortAsc
		}
		if !slices.Contains(policyIssueSortDirections, dir) {
			return nil, fmt.Errorf("invalid direction %q for --sort: must be one of %s",
				dir, strings.Join(policyIssueSortDirections, ", "))
		}
		items = append(items, cloudapitype.AngularGridSortModelItem{ColID: field, Sort: dir})
	}
	return items, nil
}

// buildPolicyIssueGrid converts the filter flags into the grid filter and sort models sent to the service.
// It returns nil for a model whose flags were not set. currentLogin resolves '--assigned-to me'.
func buildPolicyIssueGrid(
	f policyIssueFilters, currentLogin string,
) (*cloudapitype.AngularGridAdvancedFilterModel, []cloudapitype.AngularGridSortModelItem, error) {
	if err := validatePolicyIssueFilters(f); err != nil {
		return nil, nil, err
	}
	sortModel, err := buildSortModel(f.sort)
	if err != nil {
		return nil, nil, err
	}

	var perFlag []cloudapitype.AngularGridFilterModel
	addColumn := func(c policyIssueFilterColumn) error {
		values := *c.values(&f)
		if len(values) == 0 {
			return nil
		}
		leaves := make([]cloudapitype.AngularGridFilterModel, 0, len(values))
		for _, v := range values {
			if c.which == filterAssignedTo && v == assignedToMe {
				if currentLogin == "" {
					return fmt.Errorf("cannot resolve --%s %s: unable to determine the current user", c.flag, assignedToMe)
				}
				v = currentLogin
			}
			leaves = append(leaves, gridLeaf(c.colID, v))
		}
		perFlag = append(perFlag, gridGroup(gridCombinatorOr, leaves))
		return nil
	}

	for _, c := range policyIssueFilterColumns() {
		if c.which == filterResourceType {
			if len(f.stacks) > 0 {
				perFlag = append(perFlag, buildStackCondition(f.stacks))
			}
			if len(f.accounts) > 0 {
				perFlag = append(perFlag, buildAccountCondition(f.accounts))
			}
		}
		if err := addColumn(c); err != nil {
			return nil, nil, err
		}
	}

	if len(perFlag) == 0 {
		return nil, sortModel, nil
	}
	return &cloudapitype.AngularGridAdvancedFilterModel{Type: gridCombinatorAnd, Conditions: perFlag}, sortModel, nil
}
