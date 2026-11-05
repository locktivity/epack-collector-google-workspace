package googleworkspace

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	groupssettings "google.golang.org/api/groupssettings/v1"
	"google.golang.org/api/option"
	vault "google.golang.org/api/vault/v1"
)

// Per-page limits for the paginated list endpoints. The methods that use these
// live in the per-service client_*.go files in this package.
const maxUsersPerPage = 500
const maxActivitiesPerPage = 1000
const maxAccessPoliciesPerPage = 100
const maxAccessLevelsPerPage = 100
const maxRolesPerPage = 100
const maxRoleAssignmentsPerPage = 200
const maxGroupsPerPage = 200
const maxMembersPerPage = 200
const maxDevicesPerPage = 100
const maxSAMLProfilesPerPage = 100
const maxVaultMattersPerPage = 100
const maxVaultHoldsPerPage = 100
const maxPoliciesPerPage = 100

// APIClient wraps the Google Admin SDK Directory, Reports, Groups Settings,
// Cloud Identity, Access Context Manager, and Vault APIs.
//
// Each field is a service client built for exactly one OAuth scope (least
// privilege): a token is only minted for the scopes a surface actually uses,
// and a domain-wide-delegation grant that is missing one scope fails only that
// surface (the collector records a permission diagnostic and skips it) instead
// of aborting the whole run. This keeps a base-scope-only tenant collecting core
// posture and lets customers grant scopes per surface. The list/get methods are
// split by service across the client_*.go files in this package.
type APIClient struct {
	dirCustomer           *admin.Service // admin.directory.customer.readonly
	dirUsers              *admin.Service // admin.directory.user.readonly
	dirRoles              *admin.Service // admin.directory.rolemanagement.readonly
	dirGroups             *admin.Service // admin.directory.group.readonly
	dirGroupMembers       *admin.Service // admin.directory.group.member.readonly
	dirOrgUnits           *admin.Service // admin.directory.orgunit.readonly
	dirMobile             *admin.Service // admin.directory.device.mobile.readonly
	dirChromeOS           *admin.Service // admin.directory.device.chromeos.readonly
	dirDomains            *admin.Service // admin.directory.domain.readonly
	reports               *reports.Service
	auditReports          *reports.Service
	accessContext         *accesscontextmanager.Service
	groupSettings         *groupssettings.Service
	cloudIdentity         *cloudidentity.Service // cloud-identity.inboundsso.readonly
	cloudIdentityPolicies *cloudidentity.Service // cloud-identity.policies.readonly
	vault                 *vault.Service

	// signIn is the user directory scope's token source.
	signIn oauth2.TokenSource
}

// newReadonlyService builds a Google API service authenticated for one subject
// and scope set, optionally impersonating subject via domain-wide delegation
// (pass "" for org-level APIs like Access Context Manager that are not
// delegated to a Workspace user). newService is the package's NewService
// constructor (e.g. vault.NewService). It requests only the given scopes, so the
// resulting client's token is rejected by DWD only if one of those exact scopes
// is ungranted. It also returns the token source, which SignIn uses for the
// user directory scope.
//
// The authenticator decides how the credential becomes a token, so both a
// service account key and a workload identity federation credential reach every
// surface the same way, and every request goes out through the SDK transport.
func newReadonlyService[T any](
	ctx context.Context,
	auth *authenticator,
	subject string,
	newService func(context.Context, ...option.ClientOption) (*T, error),
	scopes ...string,
) (*T, oauth2.TokenSource, error) {
	src, err := auth.source(subject, scopes)
	if err != nil {
		return nil, nil, err
	}
	svc, err := newService(ctx, option.WithHTTPClient(auth.authorized(src)))
	if err != nil {
		return nil, nil, err
	}
	return svc, src, nil
}

// NewClient authenticates and returns a client. Each directory service is
// scoped to a single OAuth scope so a missing domain-wide-delegation grant
// degrades one surface rather than the whole run. transport is the one every
// request, token requests included, goes out through: the collector passes the
// SDK's.
//
// Authenticates with a service account key, or by exchanging the runner's own
// OIDC identity when the profile selects that mode.
func NewClient(ctx context.Context, adminEmail string, authConfig AuthConfig, transport http.RoundTripper) (*APIClient, error) {
	auth, err := newAuthenticator(ctx, authConfig, transport)
	if err != nil {
		return nil, err
	}

	// Build one single-scope directory client per surface. The closure
	// short-circuits on the first error (all share the same credentials, so a
	// parse failure would affect every call identically).
	var dirErr error
	var signIn oauth2.TokenSource
	adminSvc := func(scope string) *admin.Service {
		if dirErr != nil {
			return nil
		}
		svc, src, err := newReadonlyService(ctx, auth, adminEmail, admin.NewService, scope)
		if err != nil {
			dirErr = err
		}
		if scope == admin.AdminDirectoryUserReadonlyScope {
			signIn = src
		}
		return svc
	}

	c := &APIClient{
		dirCustomer:     adminSvc(admin.AdminDirectoryCustomerReadonlyScope),
		dirUsers:        adminSvc(admin.AdminDirectoryUserReadonlyScope),
		dirRoles:        adminSvc(admin.AdminDirectoryRolemanagementReadonlyScope),
		dirGroups:       adminSvc(admin.AdminDirectoryGroupReadonlyScope),
		dirGroupMembers: adminSvc(admin.AdminDirectoryGroupMemberReadonlyScope),
		dirOrgUnits:     adminSvc(admin.AdminDirectoryOrgunitReadonlyScope),
		dirMobile:       adminSvc(admin.AdminDirectoryDeviceMobileReadonlyScope),
		dirChromeOS:     adminSvc(admin.AdminDirectoryDeviceChromeosReadonlyScope),
		dirDomains:      adminSvc(admin.AdminDirectoryDomainReadonlyScope),
	}
	if dirErr != nil {
		return nil, fmt.Errorf("creating directory service: %w", dirErr)
	}
	c.signIn = signIn

	if c.reports, _, err = newReadonlyService(ctx, auth, adminEmail, reports.NewService, reports.AdminReportsUsageReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating usage reports service: %w", err)
	}
	if c.auditReports, _, err = newReadonlyService(ctx, auth, adminEmail, reports.NewService, reports.AdminReportsAuditReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating audit reports service: %w", err)
	}
	// Access Context Manager is an org-level Google Cloud API, not delegated to
	// a Workspace user, so it impersonates no subject.
	if c.accessContext, _, err = newReadonlyService(ctx, auth, "", accesscontextmanager.NewService, accesscontextmanager.CloudPlatformScope); err != nil {
		return nil, fmt.Errorf("creating access context manager service: %w", err)
	}
	if c.groupSettings, _, err = newReadonlyService(ctx, auth, adminEmail, groupssettings.NewService, groupssettings.AppsGroupsSettingsScope); err != nil {
		return nil, fmt.Errorf("creating group settings service: %w", err)
	}
	if c.cloudIdentity, _, err = newReadonlyService(ctx, auth, adminEmail, cloudidentity.NewService, cloudidentity.CloudIdentityInboundssoReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating cloud identity service: %w", err)
	}
	if c.cloudIdentityPolicies, _, err = newReadonlyService(ctx, auth, adminEmail, cloudidentity.NewService, cloudidentity.CloudIdentityPoliciesReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating cloud identity policies service: %w", err)
	}
	if c.vault, _, err = newReadonlyService(ctx, auth, adminEmail, vault.NewService, vault.EdiscoveryReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating vault service: %w", err)
	}

	return c, nil
}

// SignIn mints the token for the user directory scope, which every run reads.
// A credential Google rejects, or a delegation grant without that scope, fails
// here, before any surface is collected.
func (c *APIClient) SignIn(context.Context) error {
	if c.signIn == nil {
		return nil
	}
	_, err := c.signIn.Token()
	return err
}

// Services holds existing services for NewClientWithServices.
type Services struct {
	Directory     *admin.Service
	Reports       *reports.Service
	AccessContext *accesscontextmanager.Service
	GroupSettings *groupssettings.Service
	CloudIdentity *cloudidentity.Service
	Vault         *vault.Service
}

// NewClientWithServices creates a client backed by existing services (for
// testing). The single directory service is shared by every directory surface,
// and the Cloud Identity service by SAML profiles and policies; tests point
// them at one fake transport. SignIn mints nothing.
func NewClientWithServices(s Services) *APIClient {
	return &APIClient{
		dirCustomer:           s.Directory,
		dirUsers:              s.Directory,
		dirRoles:              s.Directory,
		dirGroups:             s.Directory,
		dirGroupMembers:       s.Directory,
		dirOrgUnits:           s.Directory,
		dirMobile:             s.Directory,
		dirChromeOS:           s.Directory,
		dirDomains:            s.Directory,
		reports:               s.Reports,
		auditReports:          s.Reports,
		accessContext:         s.AccessContext,
		groupSettings:         s.GroupSettings,
		cloudIdentity:         s.CloudIdentity,
		cloudIdentityPolicies: s.CloudIdentity,
		vault:                 s.Vault,
	}
}
