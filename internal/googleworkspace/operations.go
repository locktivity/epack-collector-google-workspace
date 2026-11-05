package googleworkspace

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// Operation names. Each client method has one; they key the collector
// result's call ledger.
const (
	OpCustomersGet        = "directory.customers.get"
	OpUsersList           = "directory.users.list"
	OpRolesList           = "directory.roles.list"
	OpRoleAssignmentsList = "directory.role_assignments.list"
	OpGroupsList          = "directory.groups.list"
	OpMembersList         = "directory.members.list"
	OpOrgUnitsList        = "directory.orgunits.list"
	OpMobileDevicesList   = "directory.mobile_devices.list"
	OpChromeOSDevicesList = "directory.chromeos_devices.list"
	OpDomainsList         = "directory.domains.list"
	OpUsageReportGet      = "reports.customer_usage.get"
	OpActivitiesList      = "reports.activities.list"
	OpAccessEventsList    = "reports.context_aware_access.list"
	OpGroupSettingsGet    = "groupssettings.groups.get"
	OpSAMLProfilesList    = "cloudidentity.saml_profiles.list"
	OpPoliciesList        = "cloudidentity.policies.list"
	OpAccessPoliciesList  = "accesscontextmanager.access_policies.list"
	OpAccessLevelsList    = "accesscontextmanager.access_levels.list"
	OpVaultMattersList    = "vault.matters.list"
	OpVaultHoldsList      = "vault.holds.list"

	// Token operations. Each POST only mints a token, so each is safe to
	// repeat.
	OpToken         = "oauth2.token.create"
	OpSignJWT       = "iamcredentials.sign_jwt.create"
	OpImpersonate   = "iamcredentials.access_token.create"
	OpSTSToken      = "sts.token.create"
	OpGitHubIDToken = "github.id_token.get"
)

// named names the call made with ctx and declares the permission it needs.
func named(ctx context.Context, name string) context.Context {
	return componentsdk.WithOperation(ctx, componentsdk.Operation{Name: name, Permission: Permission(name)})
}

// NameOperation names the token requests x/oauth2 sends, which carry no
// operation of their own: the service account assertion exchange, and in OIDC
// mode the Security Token Service exchange and the service account
// impersonation. It is componentsdk.HTTPOptions.NameOperation.
func NameOperation(req *http.Request) (componentsdk.Operation, bool) {
	if req.Method != http.MethodPost || req.URL == nil {
		return componentsdk.Operation{}, false
	}
	host := strings.ToLower(req.URL.Hostname())
	switch {
	case host == stsHost:
		return componentsdk.Operation{Name: OpSTSToken, Safe: true}, true
	case host == iamCredentialsHost && strings.HasSuffix(req.URL.Path, ":generateAccessToken"):
		return componentsdk.Operation{Name: OpImpersonate, Safe: true, Permission: Permission(OpImpersonate)}, true
	case strings.HasSuffix(req.URL.Path, "/token"):
		return componentsdk.Operation{Name: OpToken, Safe: true}, true
	}
	return componentsdk.Operation{}, false
}

const (
	stsHost            = "sts.googleapis.com"
	iamCredentialsHost = "iamcredentials.googleapis.com"
)

// CredentialHosts lists the hosts that may receive credentials in an auth
// mode: the Workspace and Cloud API hosts and Google's token endpoint, plus in
// OIDC mode the token exchange hosts and the runner's identity endpoint.
func CredentialHosts(auth AuthConfig) []string {
	hosts := []string{
		"admin.googleapis.com",
		"www.googleapis.com",
		"cloudidentity.googleapis.com",
		"accesscontextmanager.googleapis.com",
		"vault.googleapis.com",
		"oauth2.googleapis.com",
	}
	if !auth.federated() {
		return hosts
	}
	hosts = append(hosts, stsHost, iamCredentialsHost)
	if parsed, err := url.Parse(os.Getenv(githubRequestURLEnv)); err == nil && parsed.Hostname() != "" {
		hosts = append(hosts, strings.ToLower(parsed.Hostname()))
	}
	return hosts
}
