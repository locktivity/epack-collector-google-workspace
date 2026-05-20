package collector

import (
	"errors"
	"regexp"
	"strings"

	"google.golang.org/api/googleapi"
)

// googleAPIHostRe extracts a "<service>.googleapis.com" host from an error
// message (SERVICE_DISABLED errors name the API that needs enabling).
var googleAPIHostRe = regexp.MustCompile(`[a-z0-9-]+\.googleapis\.com`)

// The collector distinguishes three graceful-degradation paths per surface.
// Each is recoverable by the customer but the fixes live in different consoles,
// so the diagnostic names which one applies. The affected surface degrades (its
// pointer field stays nil, or a core surface emits zeroed data) rather than
// failing the whole run. Scope and role denials are recorded under
// diagnostics.permission_errors; a licensing gap is an informational warning.

// recordScopeDenied records that a surface was skipped because the service
// account's Domain-Wide Delegation grant is missing an OAuth scope. Customer
// fix: add the scope in the Workspace admin console.
func (c *Collector) recordScopeDenied(surface, missingScope string) {
	c.permissionError("surface %s: scope denied (missing OAuth scope: %s)", surface, missingScope)
}

// recordRoleInsufficient records that a surface was skipped because the
// impersonation user lacks the required Workspace admin role. Customer fix:
// assign the role to the impersonation user in the admin console.
func (c *Collector) recordRoleInsufficient(surface, requiredRole string) {
	c.permissionError("surface %s: impersonation user lacks required admin role: %s", surface, requiredRole)
}

// warnFeatureNotLicensed records that a surface was skipped because the
// customer's edition does not include the feature (e.g. Vault). Customer fix:
// contact sales or accept the gap.
func (c *Collector) warnFeatureNotLicensed(surface, requiredLicense string) {
	c.warn("surface %s: feature requires %s license", surface, requiredLicense)
}

// recordAPINotEnabled records that a surface was skipped because its Google API
// is not enabled in the service account's Cloud project. This is distinct from
// a missing OAuth scope: the scope is granted, but the API itself is off.
// Customer fix: enable the API in the Cloud console. The API host is named when
// it can be extracted from the error.
func (c *Collector) recordAPINotEnabled(surface string, err error) {
	if host := googleAPIHostRe.FindString(err.Error()); host != "" {
		c.permissionError("surface %s: Google API %s is not enabled in the service account's Cloud project; enable it and retry", surface, host)
		return
	}
	c.permissionError("surface %s: a required Google API is not enabled in the service account's Cloud project", surface)
}

// isScopeDenied reports whether err is caused by an OAuth scope that the
// service account's domain-wide-delegation grant doesn't authorize (fixable by
// adding the scope in the Workspace admin console). This shows up two ways:
//   - at token minting, as an OAuth2 "unauthorized_client" error (the grant is
//     missing the scope entirely), or
//   - on the API call, as a 403 with reason ACCESS_TOKEN_SCOPE_INSUFFICIENT.
func isScopeDenied(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "unauthorized_client") {
		return true
	}
	apiErr := asGoogleAPIError(err)
	if apiErr == nil || apiErr.Code != 403 {
		return false
	}
	for _, item := range apiErr.Errors {
		if item.Reason == "ACCESS_TOKEN_SCOPE_INSUFFICIENT" {
			return true
		}
	}
	return false
}

// isRoleInsufficient reports whether err is a 403 caused by the impersonation
// user lacking the required Workspace admin role (fixable in the admin console).
// This is distinct from isScopeDenied: same HTTP status, different remedy.
func isRoleInsufficient(err error) bool {
	apiErr := asGoogleAPIError(err)
	if apiErr == nil || apiErr.Code != 403 {
		return false
	}
	for _, item := range apiErr.Errors {
		switch item.Reason {
		case "INSUFFICIENT_PERMISSIONS", "forbidden", "authError":
			return true
		}
	}
	return false
}

// isFeatureNotLicensed reports whether err is a 404 indicating the customer's
// edition does not include the queried feature (Vault, advanced Endpoint).
func isFeatureNotLicensed(err error) bool {
	apiErr := asGoogleAPIError(err)
	return apiErr != nil && apiErr.Code == 404
}

// isAPINotEnabled reports whether err is a 403 SERVICE_DISABLED: the OAuth scope
// is granted but the Google API is not enabled in the service account's Cloud
// project (fixable in the Cloud console, separate from the DWD scope grant).
func isAPINotEnabled(err error) bool {
	apiErr := asGoogleAPIError(err)
	if apiErr == nil || apiErr.Code != 403 {
		return false
	}
	for _, item := range apiErr.Errors {
		if item.Reason == "accessNotConfigured" {
			return true
		}
	}
	return strings.Contains(err.Error(), "SERVICE_DISABLED")
}

func asGoogleAPIError(err error) *googleapi.Error {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}
