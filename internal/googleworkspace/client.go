package googleworkspace

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
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
	dirCustomer     *admin.Service // admin.directory.customer.readonly
	dirUsers        *admin.Service // admin.directory.user.readonly
	dirRoles        *admin.Service // admin.directory.rolemanagement.readonly
	dirGroups       *admin.Service // admin.directory.group.readonly
	dirGroupMembers *admin.Service // admin.directory.group.member.readonly
	dirOrgUnits     *admin.Service // admin.directory.orgunit.readonly
	dirMobile       *admin.Service // admin.directory.device.mobile.readonly
	dirChromeOS     *admin.Service // admin.directory.device.chromeos.readonly
	dirDomains      *admin.Service // admin.directory.domain.readonly
	reports         *reports.Service
	auditReports    *reports.Service
	accessContext   *accesscontextmanager.Service
	groupSettings   *groupssettings.Service
	cloudIdentity   *cloudidentity.Service
	vault           *vault.Service
}

// newReadonlyService builds a Google API service authenticated by the service
// account credentials, optionally impersonating subject via domain-wide
// delegation (pass "" for org-level APIs like Access Context Manager that are
// not delegated to a Workspace user). newService is the package's NewService
// constructor (e.g. vault.NewService). It requests only the given scopes, so the
// resulting client's token is rejected by DWD only if one of those exact scopes
// is ungranted.
func newReadonlyService[T any](
	ctx context.Context,
	creds []byte,
	subject string,
	newService func(context.Context, ...option.ClientOption) (*T, error),
	scopes ...string,
) (*T, error) {
	cfg, err := google.JWTConfigFromJSON(creds, scopes...)
	if err != nil {
		return nil, err
	}
	if subject != "" {
		cfg.Subject = subject
	}
	return newService(ctx, option.WithHTTPClient(cfg.Client(ctx)))
}

// NewClient authenticates with a service account and returns a client. Each
// directory service is scoped to a single OAuth scope so a missing
// domain-wide-delegation grant degrades one surface rather than the whole run.
func NewClient(ctx context.Context, adminEmail, credentialsJSON string) (*APIClient, error) {
	creds := []byte(credentialsJSON)

	// Build one single-scope directory client per surface. The closure
	// short-circuits on the first error (all share the same credentials, so a
	// parse failure would affect every call identically).
	var dirErr error
	adminSvc := func(scope string) *admin.Service {
		if dirErr != nil {
			return nil
		}
		svc, err := newReadonlyService(ctx, creds, adminEmail, admin.NewService, scope)
		if err != nil {
			dirErr = err
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

	var err error
	if c.reports, err = newReadonlyService(ctx, creds, adminEmail, reports.NewService, reports.AdminReportsUsageReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating usage reports service: %w", err)
	}
	if c.auditReports, err = newReadonlyService(ctx, creds, adminEmail, reports.NewService, reports.AdminReportsAuditReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating audit reports service: %w", err)
	}
	// Access Context Manager is an org-level Google Cloud API, not delegated to
	// a Workspace user, so it impersonates no subject.
	if c.accessContext, err = newReadonlyService(ctx, creds, "", accesscontextmanager.NewService, accesscontextmanager.CloudPlatformScope); err != nil {
		return nil, fmt.Errorf("creating access context manager service: %w", err)
	}
	if c.groupSettings, err = newReadonlyService(ctx, creds, adminEmail, groupssettings.NewService, groupssettings.AppsGroupsSettingsScope); err != nil {
		return nil, fmt.Errorf("creating group settings service: %w", err)
	}
	if c.cloudIdentity, err = newReadonlyService(ctx, creds, adminEmail, cloudidentity.NewService, cloudidentity.CloudIdentityInboundssoReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating cloud identity service: %w", err)
	}
	if c.vault, err = newReadonlyService(ctx, creds, adminEmail, vault.NewService, vault.EdiscoveryReadonlyScope); err != nil {
		return nil, fmt.Errorf("creating vault service: %w", err)
	}

	return c, nil
}

// NewClientWithServices creates a client backed by existing services (for
// testing). The single directory service is shared by every directory surface;
// tests point it at one fake transport.
func NewClientWithServices(directory *admin.Service, reportsService *reports.Service, accessContextService *accesscontextmanager.Service) *APIClient {
	return &APIClient{
		dirCustomer:     directory,
		dirUsers:        directory,
		dirRoles:        directory,
		dirGroups:       directory,
		dirGroupMembers: directory,
		dirOrgUnits:     directory,
		dirMobile:       directory,
		dirChromeOS:     directory,
		dirDomains:      directory,
		reports:         reportsService,
		auditReports:    reportsService,
		accessContext:   accessContextService,
	}
}
