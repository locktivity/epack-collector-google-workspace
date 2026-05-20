package googleworkspace

import (
	"context"
	"time"
)

const DefaultCustomerKey = "my_customer"

// User captures the Google Workspace user fields used by the collector. The
// fields beyond the trust-level aggregates (org-unit path, creation time,
// agreed-to-terms, IP-allowlisted, change-password-at-next-login) are populated
// from the same directory.users.list pass and surfaced per-user at audit /
// internal. Per-user passkey / hardware-key registration and password strength
// are intentionally absent: the Directory API exposes those only as org-level
// aggregates (see the usage report), not per user.
type User struct {
	ID                        string
	PrimaryEmail              string
	Suspended                 bool
	Archived                  bool
	IsAdmin                   bool
	IsDelegatedAdmin          bool
	IsEnrolledIn2Sv           bool
	IsEnforcedIn2Sv           bool
	OrgUnitPath               string
	CreationTime              time.Time
	AgreedToTerms             bool
	IPWhitelisted             bool
	ChangePasswordAtNextLogin bool
	LastLoginTime             time.Time
	LastLoginMissing          bool
}

// Customer captures the tenant metadata used by the collector.
type Customer struct {
	ID            string
	PrimaryDomain string
}

// ReportWarning represents a warning returned by the Reports API in a 200 response.
type ReportWarning struct {
	Code    string
	Message string
}

// CustomerUsageReport holds the parsed accounts parameters from a customer usage report.
type CustomerUsageReport struct {
	Date     string
	Warnings []ReportWarning

	NumUsers          int64
	NumSuspendedUsers int64
	NumArchivedUsers  int64

	Num7DayLogins  int64
	Num30DayLogins int64

	NumUsers2SVEnrolled  int64
	NumUsers2SVEnforced  int64
	NumUsers2SVProtected int64

	NumUsersWithPasskeysEnrolled int64
	NumSecurityKeys              int64

	NumUsersPasswordStrengthWeak       int64
	NumUsersPasswordLengthNonCompliant int64

	NumAuthorizedApps int64
	NumLockedUsers    int64
}

// ContextAwareAccessEvent captures the audit fields needed to detect
// Context-Aware Access deny events that cite device state.
type ContextAwareAccessEvent struct {
	OccurredAt             time.Time
	UserEmail              string
	Application            string
	BlockedAPIAccess       string
	AccessLevelApplied     string
	AccessLevelSatisfied   string
	AccessLevelUnsatisfied string
	DeviceID               string
	DeviceState            string
}

// SAMLProfile captures an inbound SAML SSO profile. SSOServiceURI is the full
// IdP single-sign-on URL; the collector emits only its host (never the full
// URL, signing certs, or metadata XML).
type SAMLProfile struct {
	Name          string
	DisplayName   string
	IdpEntityID   string
	SSOServiceURI string
}

// Domain captures a customer domain.
type Domain struct {
	DomainName string
	Verified   bool
	IsPrimary  bool
}

// VaultMatter captures a Vault eDiscovery matter.
type VaultMatter struct {
	MatterID string
	Name     string
	State    string
}

// VaultHold captures a Vault hold's metadata. The hold's search Query and
// account identifiers are never read or mapped (privileged eDiscovery data);
// only the corpus, an account count, and the org-unit-scoped flag are surfaced.
type VaultHold struct {
	HoldID        string
	MatterID      string
	Name          string
	Corpus        string
	AccountCount  int
	OrgUnitScoped bool
	UpdateTime    time.Time
}

// AuditEvent is a single flattened Reports API activity event, shared by the
// audit-log surfaces (admin / login / token / drive). Parameters carries the
// scalar event parameters; MultiParameters the list-valued ones. Forbidden
// payload fields (debug context, message/file contents) are never mapped.
type AuditEvent struct {
	Time            time.Time
	ActorEmail      string
	IPAddress       string
	Application     string
	Name            string
	Parameters      map[string]string
	MultiParameters map[string][]string
}

// AccessPolicy captures the Access Context Manager policy metadata used for
// optional Google Cloud config enrichment.
type AccessPolicy struct {
	Name   string
	Parent string
	Title  string
}

// AccessLevel captures the Access Context Manager access level details needed
// to summarize device-policy configuration.
type AccessLevel struct {
	Name                          string
	Title                         string
	Custom                        bool
	HasDevicePolicy               bool
	RequiresScreenlock            bool
	RequiresAdminApproval         bool
	RequiresCorpOwned             bool
	AllowedDeviceManagementLevels []string
	AllowedEncryptionStatuses     []string
	OSConstraintCount             int

	// Rule details surfaced at internal. IP subnetworks and regions are access
	// gating configuration, not user PII.
	IPSubnetworks        []string
	Regions              []string
	RequiredAccessLevels []string
}

// Role captures an admin role definition. Custom roles are those with
// IsSystem=false (admin-defined rather than Google-provided seed roles).
type Role struct {
	ID             string
	Name           string
	Description    string
	PrivilegeCount int
	IsSystem       bool
	IsSuperAdmin   bool
}

// RoleAssignment captures a single role grant to a user. ScopeType is
// "CUSTOMER" (whole-org) or "ORG_UNIT" (scoped to OrgUnitID).
type RoleAssignment struct {
	AssignedTo string
	RoleID     string
	ScopeType  string
	OrgUnitID  string
}

// Group captures a Google Workspace group. Settings fields (external-members,
// who-can-join/post) are populated separately from the Groups Settings API and
// are only fetched at audit and above.
type Group struct {
	Email              string
	Name               string
	Description        string
	DirectMembersCount int
	AdminCreated       bool
}

// GroupSettings captures the per-group settings relevant to posture.
type GroupSettings struct {
	AllowExternalMembers bool
	WhoCanJoin           string
	WhoCanPostMessage    string
}

// OrgUnit captures an organizational unit. BlockInheritance indicates the OU
// overrides inherited policy (the strongest policy-override signal available
// without the Workspace Policy API).
type OrgUnit struct {
	Path             string
	ParentPath       string
	Name             string
	Description      string
	BlockInheritance bool
}

// Device is a managed endpoint (mobile or Chrome OS). Device-identifying
// hardware fields (serial number, IMEI, MEID) are intentionally never read or
// mapped: compliance evidence about whether devices are managed does not
// require which specific hardware (re-identification / data-minimization).
type Device struct {
	Platform           string // "MOBILE" or "CHROME_OS"
	OS                 string // ANDROID / IOS / ... or CHROME_OS
	OSVersion          string
	Model              string
	OwnerEmail         string
	Status             string
	Compliant          bool
	Encrypted          bool
	ScreenLockEnforced bool
	LastSync           time.Time
	LastSyncMissing    bool
}

// GroupMember captures a single group membership row (internal level).
type GroupMember struct {
	Email            string
	Role             string
	Type             string
	Status           string
	DeliverySettings string
}

// Client defines the Google Workspace operations needed by the collector.
type Client interface {
	GetCustomer(ctx context.Context, customerKey string) (Customer, error)
	GetCustomerUsageReport(ctx context.Context, customerID, date string) (CustomerUsageReport, error)
	ListUsers(ctx context.Context, customerKey string, callback func([]User) error) error
	ListRoles(ctx context.Context, customerID string, callback func([]Role) error) error
	ListRoleAssignments(ctx context.Context, customerID string, callback func([]RoleAssignment) error) error
	ListGroups(ctx context.Context, customerID string, callback func([]Group) error) error
	GetGroupSettings(ctx context.Context, groupEmail string) (GroupSettings, error)
	ListGroupMembers(ctx context.Context, groupEmail string, callback func([]GroupMember) error) error
	ListOrgUnits(ctx context.Context, customerID string) ([]OrgUnit, error)
	ListMobileDevices(ctx context.Context, customerID string, callback func([]Device) error) error
	ListChromeOSDevices(ctx context.Context, customerID string, callback func([]Device) error) error
	ListActivities(ctx context.Context, customerID, applicationName string, eventNames []string, startTime time.Time, callback func([]AuditEvent) error) error
	ListSAMLProfiles(ctx context.Context, callback func([]SAMLProfile) error) error
	ListDomains(ctx context.Context, customerID string) ([]Domain, error)
	ListVaultMatters(ctx context.Context, callback func([]VaultMatter) error) error
	ListVaultHolds(ctx context.Context, matterID string, callback func([]VaultHold) error) error
	ListContextAwareAccessEvents(ctx context.Context, customerID string, startTime time.Time, callback func([]ContextAwareAccessEvent) error) error
	ListAccessPolicies(ctx context.Context, parent string, callback func([]AccessPolicy) error) error
	ListAccessLevels(ctx context.Context, policyName string, callback func([]AccessLevel) error) error
}
