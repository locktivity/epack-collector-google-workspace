package googleworkspace

import (
	"encoding/json"
	"net/http"

	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	groupssettings "google.golang.org/api/groupssettings/v1"
	vault "google.golang.org/api/vault/v1"
)

// operationPermissions maps each call to the permission Google's API
// reference names for it. A Workspace call needs the OAuth scope its
// service's token asks for, which the delegation grant must list. An Access
// Context Manager or IAM Credentials call needs an IAM permission. The token
// exchanges and the runner's identity token need none.
var operationPermissions = map[string]string{
	OpCustomersGet:        admin.AdminDirectoryCustomerReadonlyScope,
	OpUsersList:           admin.AdminDirectoryUserReadonlyScope,
	OpRolesList:           admin.AdminDirectoryRolemanagementReadonlyScope,
	OpRoleAssignmentsList: admin.AdminDirectoryRolemanagementReadonlyScope,
	OpGroupsList:          admin.AdminDirectoryGroupReadonlyScope,
	OpMembersList:         admin.AdminDirectoryGroupMemberReadonlyScope,
	OpOrgUnitsList:        admin.AdminDirectoryOrgunitReadonlyScope,
	OpMobileDevicesList:   admin.AdminDirectoryDeviceMobileReadonlyScope,
	OpChromeOSDevicesList: admin.AdminDirectoryDeviceChromeosReadonlyScope,
	OpDomainsList:         admin.AdminDirectoryDomainReadonlyScope,
	OpUsageReportGet:      reports.AdminReportsUsageReadonlyScope,
	OpActivitiesList:      reports.AdminReportsAuditReadonlyScope,
	OpAccessEventsList:    reports.AdminReportsAuditReadonlyScope,
	OpGroupSettingsGet:    groupssettings.AppsGroupsSettingsScope,
	OpSAMLProfilesList:    cloudidentity.CloudIdentityInboundssoReadonlyScope,
	OpPoliciesList:        cloudidentity.CloudIdentityPoliciesReadonlyScope,
	OpAccessPoliciesList:  "accesscontextmanager.policies.list",
	OpAccessLevelsList:    "accesscontextmanager.accessLevels.list",
	OpVaultMattersList:    vault.EdiscoveryReadonlyScope,
	OpVaultHoldsList:      vault.EdiscoveryReadonlyScope,
	OpSignJWT:             "iam.serviceAccounts.signJwt",
	OpImpersonate:         "iam.serviceAccounts.getAccessToken",
}

// Permission returns the permission the call named op needs, or "" for a
// call that needs none.
func Permission(op string) string { return operationPermissions[op] }

// NamesPermission is componentsdk.HTTPOptions.NamesPermission. It reports
// whether a refusal shows that the credential lacks the call's permission.
// Google says so with ACCESS_TOKEN_SCOPE_INSUFFICIENT or
// insufficientPermissions for a token without the scope, and with
// IAM_PERMISSION_DENIED for a missing IAM permission. A Workspace refusal
// for an admin role without the privilege says forbidden, and one for an API
// turned off in the Cloud project says SERVICE_DISABLED. Granting the
// permission lifts neither, so neither names it.
func NamesPermission(_ *http.Response, body []byte) bool {
	var reply struct {
		Error struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return false
	}
	reasons := make([]string, 0, len(reply.Error.Errors)+len(reply.Error.Details))
	for _, item := range reply.Error.Errors {
		reasons = append(reasons, item.Reason)
	}
	for _, item := range reply.Error.Details {
		reasons = append(reasons, item.Reason)
	}
	return permissionReason(reasons)
}

// permissionReason reports whether any of Google's reasons for a refusal
// says the credential lacks the call's permission.
func permissionReason(reasons []string) bool {
	for _, reason := range reasons {
		switch reason {
		case "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "insufficientPermissions", "IAM_PERMISSION_DENIED":
			return true
		}
	}
	return false
}
