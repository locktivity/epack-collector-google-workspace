package collector

import (
	"context"
	"math"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// The sign-in values in the detailed artifact.
const (
	webSessionPointer     = "/sign_in/web_session_duration_max_minutes"
	lessSecureAppsPointer = "/sign_in/less_secure_apps_allowed"
)

// scanSignInPolicy reads the web session length and the less secure apps
// setting from the Policy API, at every level. Each value is the weakest one
// any org unit or group gets. A value whose policies could not be read is
// left out with a gap, and so is one with no policy at all, since Google
// then reports nothing to go on.
func (c *Collector) scanSignInPolicy(ctx context.Context, scope scanScope) *SignInPolicy {
	var policy SignInPolicy

	var sessions []googleworkspace.SessionPolicy
	err := c.client.ListSessionPolicies(ctx, scope.customerID, func(batch []googleworkspace.SessionPolicy) error {
		sessions = append(sessions, batch...)
		return nil
	})
	switch {
	case err != nil:
		c.policyReadFailed("session_controls", err, webSessionPointer)
	case len(sessions) == 0:
		c.gaps.leaveOut(&missing{code: componentsdk.CodeVendorError, detail: "The Policy API returned no session controls policy."}, webSessionPointer)
	default:
		policy.WebSessionDurationMaxMinutes = intPtr(longestSessionMinutes(sessions))
	}

	var lessSecure []googleworkspace.LessSecureAppsPolicy
	err = c.client.ListLessSecureAppsPolicies(ctx, scope.customerID, func(batch []googleworkspace.LessSecureAppsPolicy) error {
		lessSecure = append(lessSecure, batch...)
		return nil
	})
	switch {
	case err != nil:
		c.policyReadFailed("less_secure_apps", err, lessSecureAppsPointer)
	case len(lessSecure) == 0:
		c.gaps.leaveOut(&missing{code: componentsdk.CodeVendorError, detail: "The Policy API returned no less secure apps policy."}, lessSecureAppsPointer)
	default:
		policy.LessSecureAppsAllowed = boolPtr(anyAllowsLessSecureApps(lessSecure))
	}

	if policy == (SignInPolicy{}) {
		return nil
	}
	return &policy
}

// policyReadFailed records a failed Policy API read of one setting, the way
// scanPasswordPolicy does. An edition without the Policy API answers 404,
// which is a licensing gap.
func (c *Collector) policyReadFailed(surface string, err error, pointers ...string) {
	if isFeatureNotLicensed(err) {
		c.warnFeatureNotLicensed(surface, "Policy API")
		c.gaps.leaveOut(unlicensed("the tenant's edition does not include the Policy API"), pointers...)
		return
	}
	c.warnSurfaceScan(surface, "cloud-identity.policies.readonly", "Super Admin", err)
	c.gaps.leaveOut(failed(err), pointers...)
}

// longestSessionMinutes is the longest web session any policy sets, in whole
// minutes, rounded up so a session is never shorter than it reads.
func longestSessionMinutes(policies []googleworkspace.SessionPolicy) int {
	longest := 0.0
	for _, p := range policies {
		longest = math.Max(longest, p.WebSessionSeconds)
	}
	return int(math.Ceil(longest / 60))
}

// anyAllowsLessSecureApps reports whether any policy lets users reach apps
// that use less secure sign-in.
func anyAllowsLessSecureApps(policies []googleworkspace.LessSecureAppsPolicy) bool {
	for _, p := range policies {
		if p.Allowed {
			return true
		}
	}
	return false
}
