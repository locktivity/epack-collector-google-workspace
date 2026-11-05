package googleworkspace

import (
	"context"
	"slices"

	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	"google.golang.org/api/googleapi"
)

// ListAccessPolicies lists Access Context Manager policies under a GCP
// organization for optional device-access config enrichment.
func (c *APIClient) ListAccessPolicies(ctx context.Context, parent string, callback func([]AccessPolicy) error) error {
	call := c.accessContext.AccessPolicies.List().
		Parent(parent).
		PageSize(maxAccessPoliciesPerPage).
		Fields(googleapi.Field("nextPageToken,accessPolicies(name,parent,title)"))

	err := call.Pages(named(ctx, OpAccessPoliciesList), func(resp *accesscontextmanager.ListAccessPoliciesResponse) error {
		policies := make([]AccessPolicy, 0, len(resp.AccessPolicies))
		for _, policy := range resp.AccessPolicies {
			if policy == nil {
				continue
			}
			policies = append(policies, AccessPolicy{
				Name:   policy.Name,
				Parent: policy.Parent,
				Title:  policy.Title,
			})
		}
		if len(policies) == 0 {
			return nil
		}
		return callback(policies)
	})
	return listError(OpAccessPoliciesList, "listing access policies", err)
}

// ListAccessLevels lists Access Context Manager access levels for a policy.
func (c *APIClient) ListAccessLevels(ctx context.Context, policyName string, callback func([]AccessLevel) error) error {
	call := c.accessContext.AccessPolicies.AccessLevels.List(policyName).
		PageSize(maxAccessLevelsPerPage).
		Fields(googleapi.Field("nextPageToken,accessLevels(name,title,basic(combiningFunction,conditions(negate,ipSubnetworks,regions,requiredAccessLevels,devicePolicy(allowedDeviceManagementLevels,allowedEncryptionStatuses,osConstraints,requireAdminApproval,requireCorpOwned,requireScreenlock))),custom)"))

	err := call.Pages(named(ctx, OpAccessLevelsList), func(resp *accesscontextmanager.ListAccessLevelsResponse) error {
		levels := make([]AccessLevel, 0, len(resp.AccessLevels))
		for _, level := range resp.AccessLevels {
			if level == nil {
				continue
			}
			levels = append(levels, mapAccessLevel(level))
		}
		if len(levels) == 0 {
			return nil
		}
		return callback(levels)
	})
	return listError(OpAccessLevelsList, "listing access levels", err)
}

func mapAccessLevel(level *accesscontextmanager.AccessLevel) AccessLevel {
	mapped := AccessLevel{
		Name:   level.Name,
		Title:  level.Title,
		Custom: level.Custom != nil,
	}

	if level.Basic == nil {
		return mapped
	}

	deviceManagementLevels := map[string]struct{}{}
	encryptionStatuses := map[string]struct{}{}

	var conditions []*accesscontextmanager.Condition
	for _, condition := range level.Basic.Conditions {
		if condition != nil {
			conditions = append(conditions, condition)
		}
	}
	// A request has to meet every condition when the level joins them with
	// AND, the default, or when there is only one. With OR it has to meet
	// just one of them.
	everyConditionApplies := level.Basic.CombiningFunction != "OR" || len(conditions) == 1

	for _, condition := range conditions {
		mapped.IPSubnetworks = append(mapped.IPSubnetworks, condition.IpSubnetworks...)
		mapped.Regions = append(mapped.Regions, condition.Regions...)
		mapped.RequiredAccessLevels = append(mapped.RequiredAccessLevels, condition.RequiredAccessLevels...)

		if condition.DevicePolicy == nil {
			continue
		}
		mapped.HasDevicePolicy = true

		// The device policy is a requirement of the level only when every
		// condition applies and this one is not negated. A negated condition
		// is met by a request that fails any of its settings.
		if !everyConditionApplies || condition.Negate {
			continue
		}
		if condition.DevicePolicy.RequireScreenlock {
			mapped.RequiresScreenlock = true
		}
		if condition.DevicePolicy.RequireAdminApproval {
			mapped.RequiresAdminApproval = true
		}
		if condition.DevicePolicy.RequireCorpOwned {
			mapped.RequiresCorpOwned = true
		}
		mapped.OSConstraintCount += len(condition.DevicePolicy.OsConstraints)
		for _, level := range condition.DevicePolicy.AllowedDeviceManagementLevels {
			if level == "" {
				continue
			}
			deviceManagementLevels[level] = struct{}{}
		}
		for _, status := range condition.DevicePolicy.AllowedEncryptionStatuses {
			if status == "" {
				continue
			}
			encryptionStatuses[status] = struct{}{}
		}
	}

	mapped.AllowedDeviceManagementLevels = sortedStringSet(deviceManagementLevels)
	mapped.AllowedEncryptionStatuses = sortedStringSet(encryptionStatuses)
	return mapped
}

func sortedStringSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
