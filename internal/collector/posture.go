package collector

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	// SchemaVersion is the version of the detailed Google Workspace artifact.
	SchemaVersion = "1.0.0"
	// DefaultInactiveDays is the threshold for inactive user detection.
	DefaultInactiveDays = 90
	// DefaultContextAwareAccessLookbackDays is the audit lookback window used
	// to search for Context-Aware Access deny events that cite device state.
	DefaultContextAwareAccessLookbackDays = 90

	// UsersCap bounds the per-user inventory at audit / internal for very large
	// orgs. On cap-hit, rows sort ACTIVE-first then email ascending.
	UsersCap = 50000
	// GroupsCap bounds the per-group inventory; on cap-hit rows sort by member
	// count descending.
	GroupsCap = 10000
	// GroupMembershipsCap bounds the total membership rows across all groups at
	// internal (not per group).
	GroupMembershipsCap = 200000
	// EndpointDevicesCap bounds the per-device inventory (mobile + Chrome OS
	// combined); on cap-hit rows sort by last sync descending.
	EndpointDevicesCap = 5000
	// AuditEventsCap bounds each audit-log event slice (admin / login / drive
	// external sharing / oauth tokens); on cap-hit rows sort by timestamp
	// descending.
	AuditEventsCap = 5000
	// DriveExternalSharingWindowDays is the audit-count window (30d); the
	// internal event slice uses a tighter 7d window.
	DriveExternalSharingCountDays = 30
	// AuditLogWindowDays is the lookback window for the security-relevant
	// audit-log surfaces.
	AuditLogWindowDays = 7
)

// StatusFunc reports indeterminate progress.
type StatusFunc func(message string)

// ProgressFunc reports determinate progress.
type ProgressFunc func(current, total int64, message string)

// Config holds collector configuration.
type Config struct {
	Customer        string `json:"customer,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	AccessPolicy    string `json:"access_policy,omitempty"`
	AdminEmail      string `json:"admin_email"`
	CredentialsJSON string `json:"-"`

	AuthMode                 string `json:"auth_mode,omitempty"`
	WorkloadIdentityProvider string `json:"workload_identity_provider,omitempty"`
	ServiceAccount           string `json:"service_account,omitempty"`

	OnStatus   StatusFunc       `json:"-"`
	OnProgress ProgressFunc     `json:"-"`
	Now        func() time.Time `json:"-"`

	// HTTPClient is the client every request goes out through. Run passes
	// the SDK's.
	HTTPClient *http.Client `json:"-"`
	// Recorder takes a gap for each value the collector leaves out.
	Recorder *componentsdk.Recorder `json:"-"`
}

// OrgPosture is the detailed Google Workspace posture artifact.
type OrgPosture struct {
	SchemaVersion    string               `json:"schema_version"`
	CollectedAt      string               `json:"collected_at"`
	CollectedAtLevel string               `json:"collected_at_level"`
	UsageReportDate  *string              `json:"usage_report_date"`
	Provider         string               `json:"provider"`
	OrgDomain        *string              `json:"org_domain"`
	CustomerID       AuditString          `json:"customer_id,omitzero"`
	Users            UserMetrics          `json:"users"`
	Activity         *ActivityMetrics     `json:"activity,omitempty"`
	Authentication   AuthMetrics          `json:"authentication"`
	Admins           AdminMetrics         `json:"admins"`
	Passwords        PasswordMetrics      `json:"passwords"`
	SignIn           *SignInPolicy        `json:"sign_in,omitempty"`
	Apps             *AppMetrics          `json:"apps,omitempty"`
	DeviceAccess     *DeviceAccessMetrics `json:"device_access,omitempty"`

	// New surfaces (audit / internal scope expansion). Each is a pointer with
	// omitempty so trust-level output omits them entirely.
	Groups               *Groups               `json:"groups,omitempty"`
	OrgUnits             *OrgUnits             `json:"org_units,omitempty"`
	Endpoint             *Endpoint             `json:"endpoint,omitempty"`
	DriveExternalSharing *DriveExternalSharing `json:"drive_external_sharing,omitempty"`
	AdminAuditLog        *AdminAuditLog        `json:"admin_audit_log,omitempty"`
	LoginAuditLog        *LoginAuditLog        `json:"login_audit_log,omitempty"`
	OAuthTokens          *OAuthTokens          `json:"oauth_tokens,omitempty"`
	DomainSettings       *DomainSettings       `json:"domain_settings,omitempty"`
	Vault                *Vault                `json:"vault,omitempty"`

	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`

	// counts holds the counts behind the percentages above. The normalized
	// artifact's percentages are taken from them.
	counts postureCounts
}

// postureCounts holds the user counts that percentages are taken from. A
// count is nil when the read that gives it failed, or when the usage report
// left out its parameter or its total.
type postureCounts struct {
	// From the live Directory scan, out of Users.Active or, for the
	// privileged count, out of Admins.PrivilegedUsersCount.
	inactiveUsers         *int
	enrolled2SVUsers      *int
	enforced2SVUsers      *int
	privileged2SVEnrolled *int

	// From the usage report, out of Users.Total.
	passkeyUsers       *int
	lockedUsers        *int
	weakPasswordUsers  *int
	shortPasswordUsers *int
}

// Vault is the eDiscovery surface. Trust emits the licensed flag plus matter /
// hold counts; audit adds per-matter summaries; internal adds per-hold
// metadata. Hold search queries and contents are never emitted.
type Vault struct {
	Licensed     bool                 `json:"licensed"`
	MattersCount *int                 `json:"matters_count"`
	HoldsCount   *int                 `json:"holds_count"`
	Matters      []VaultMatterSummary `json:"matters,omitempty"`
	Holds        []VaultHoldSummary   `json:"holds,omitempty"`
}

// VaultMatterSummary is a per-matter row (audit and above).
type VaultMatterSummary struct {
	MatterID  string `json:"matter_id"`
	Name      string `json:"name,omitempty"`
	State     string `json:"state,omitempty"`
	HoldCount *int   `json:"hold_count"`
}

// VaultHoldSummary is a per-hold row (internal level). Scope summary only; no
// search query or hold contents.
type VaultHoldSummary struct {
	HoldID        string `json:"hold_id"`
	MatterID      string `json:"matter_id"`
	Corpus        string `json:"corpus,omitempty"`
	AccountCount  int    `json:"account_count"`
	OrgUnitScoped bool   `json:"org_unit_scoped"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// DomainSettings is the domain + SSO surface. Trust emits the SSO-configured
// flag, SAML-profile count, and verified-domain count; audit adds per-profile
// and per-domain inventories; internal adds the SSO service host (host only).
// IdP signing certs, SAML metadata XML, and full SSO URLs are never emitted.
type DomainSettings struct {
	SSOConfigured       *bool                `json:"sso_configured"`
	SAMLProfileCount    *int                 `json:"saml_profile_count"`
	VerifiedDomainCount *int                 `json:"verified_domain_count"`
	PrimaryDomain       string               `json:"primary_domain,omitempty"`
	SAMLProfiles        []SAMLProfileSummary `json:"saml_profiles,omitempty"`
	Domains             []DomainSummary      `json:"domains,omitempty"`
}

// SAMLProfileSummary is a per-SAML-profile row (audit and above).
type SAMLProfileSummary struct {
	DisplayName    string `json:"display_name,omitempty"`
	IdpEntityID    string `json:"idp_entity_id,omitempty"`
	SSOServiceHost string `json:"sso_service_host,omitempty"`
}

// DomainSummary is a per-domain row (audit and above).
type DomainSummary struct {
	DomainName string `json:"domain_name"`
	Verified   bool   `json:"verified"`
	Primary    bool   `json:"primary"`
}

// DriveExternalSharing is the Drive external-sharing audit surface. It emerges
// at audit (counts over a 30-day window); internal adds an event slice over a
// tighter 7-day window. File names and contents are never emitted; recipients
// appear as their email domain only (never the full address).
type DriveExternalSharing struct {
	CountWindowDays     int               `json:"count_window_days"`
	ExternalShareEvents *int              `json:"external_share_events"`
	PublicOnWebEvents   int               `json:"public_on_web_events"`
	EventWindowDays     int               `json:"event_window_days,omitempty"`
	Events              []DriveShareEvent `json:"events,omitempty"`
	Truncated           bool              `json:"truncated_events,omitempty"`
	TruncatedDropped    int               `json:"truncated_events_dropped,omitempty"`
}

// DriveShareEvent is a single external-sharing event (internal level). No file
// name; recipient is a domain only.
type DriveShareEvent struct {
	Time            string `json:"time,omitempty"`
	FileID          string `json:"file_id,omitempty"`
	SharerEmail     string `json:"sharer_email,omitempty"`
	RecipientDomain string `json:"recipient_domain,omitempty"`
	TargetRole      string `json:"target_role,omitempty"`
}

// AdminAuditLog is the admin-action audit surface (7-day, security-relevant).
// Audit emits event counts by category; internal adds the event slice.
type AdminAuditLog struct {
	WindowDays       int             `json:"window_days"`
	CountsByCategory map[string]int  `json:"counts_by_category"`
	Events           []AuditLogEvent `json:"events,omitempty"`
	Truncated        bool            `json:"truncated_events,omitempty"`
	TruncatedDropped int             `json:"truncated_events_dropped,omitempty"`
}

// AuditLogEvent is a single admin audit event (internal level). No event-body /
// debug-context payloads.
type AuditLogEvent struct {
	Time       string `json:"time,omitempty"`
	ActorEmail string `json:"actor_email,omitempty"`
	Name       string `json:"name"`
	Category   string `json:"category,omitempty"`
}

// LoginAuditLog is the login audit surface (7-day, suspicious / failed logins).
// Audit emits counts; internal adds the security-relevant event slice.
type LoginAuditLog struct {
	WindowDays         int          `json:"window_days"`
	SuspiciousLogins   int          `json:"suspicious_logins"`
	FailedLogins       int          `json:"failed_logins"`
	PasswordLeakEvents int          `json:"password_leak_events"`
	Events             []LoginEvent `json:"events,omitempty"`
	Truncated          bool         `json:"truncated_events,omitempty"`
	TruncatedDropped   int          `json:"truncated_events_dropped,omitempty"`
}

// LoginEvent is a single security-relevant login event (internal level). IP is
// for forensic correlation; no geolocation.
type LoginEvent struct {
	Time       string `json:"time,omitempty"`
	ActorEmail string `json:"actor_email,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	Name       string `json:"name"`
}

// OAuthTokens is the OAuth token audit surface (internal only). Emits issuance
// counts, counts by app and scope sensitivity, plus the per-token list. Token
// values are never available via the API and never emitted.
type OAuthTokens struct {
	WindowDays               int            `json:"window_days"`
	TokensIssued             int            `json:"tokens_issued"`
	AppsWithNewTokens        int            `json:"apps_with_new_tokens"`
	CountsByApp              map[string]int `json:"counts_by_app,omitempty"`
	CountsByScopeSensitivity map[string]int `json:"counts_by_scope_sensitivity,omitempty"`
	Tokens                   []OAuthToken   `json:"tokens,omitempty"`
	Truncated                bool           `json:"truncated_tokens,omitempty"`
	TruncatedDropped         int            `json:"truncated_tokens_dropped,omitempty"`
}

// OAuthToken is a single OAuth grant (internal level).
type OAuthToken struct {
	UserEmail   string   `json:"user_email,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	GrantedAt   string   `json:"granted_at,omitempty"`
}

// Endpoint is the managed-device surface (mobile + Chrome OS). Trust emits
// device counts by OS and the not-synced-30d count; audit adds per-OS
// compliant / non-compliant breakdowns; internal adds per-device rows. Device
// serial numbers and IMEIs are never collected.
type Endpoint struct {
	Total            int              `json:"total"`
	ManagedByOS      map[string]int   `json:"managed_by_os"`
	NotSynced30d     int              `json:"not_synced_30d"`
	CompliantByOS    map[string]int   `json:"compliant_by_os,omitempty"`
	NonCompliantByOS map[string]int   `json:"non_compliant_by_os,omitempty"`
	Inventory        []EndpointDevice `json:"inventory,omitempty"`
	Truncated        bool             `json:"truncated_devices,omitempty"`
	TruncatedDropped int              `json:"truncated_devices_dropped,omitempty"`
}

// EndpointDevice is a per-device row (internal level). No serial / IMEI.
type EndpointDevice struct {
	Platform           string `json:"platform"`
	OS                 string `json:"os"`
	OSVersion          string `json:"os_version,omitempty"`
	Model              string `json:"model,omitempty"`
	OwnerEmail         string `json:"owner_email,omitempty"`
	Compliant          bool   `json:"compliant"`
	Encrypted          bool   `json:"encrypted"`
	ScreenLockEnforced bool   `json:"screen_lock_enforced"`
	LastSync           string `json:"last_sync,omitempty"`
}

// OrgUnits is the org-unit surface. Trust emits the count and max hierarchy
// depth; audit adds the per-OU inventory with user counts and the block-
// inheritance (policy-override) flag.
type OrgUnits struct {
	Total     int       `json:"total"`
	MaxDepth  int       `json:"max_depth"`
	Inventory []OrgUnit `json:"inventory,omitempty"`
}

// OrgUnit is a per-OU inventory row (audit and above). BlockInheritance is the
// available policy-override signal; the full per-OU policy-override list
// requires the Workspace Policy API, which has no stable Go binding.
type OrgUnit struct {
	Path             string `json:"path"`
	ParentPath       string `json:"parent_path,omitempty"`
	Description      string `json:"description,omitempty"`
	UserCount        *int   `json:"user_count"`
	BlockInheritance bool   `json:"block_inheritance"`
}

// Groups is the Groups surface. Trust emits counts; audit adds the per-group
// inventory plus the external-members-allowed count; internal adds member lists.
type Groups struct {
	Total                     int     `json:"total"`
	AdminCreated              int     `json:"admin_created"`
	UserCreated               int     `json:"user_created"`
	ExternalMembersAllowed    *int    `json:"external_members_allowed"`
	Inventory                 []Group `json:"inventory,omitempty"`
	TruncatedInventory        bool    `json:"truncated_inventory,omitempty"`
	TruncatedInventoryDropped int     `json:"truncated_inventory_dropped,omitempty"`
	TruncatedMemberships      bool    `json:"truncated_group_memberships,omitempty"`
}

// Group is a per-group inventory row (audit and above).
type Group struct {
	Email                string        `json:"email"`
	Name                 string        `json:"name,omitempty"`
	Description          string        `json:"description,omitempty"`
	MemberCount          int           `json:"member_count"`
	AdminCreated         bool          `json:"admin_created"`
	AllowExternalMembers *bool         `json:"allow_external_members"`
	WhoCanJoin           string        `json:"who_can_join,omitempty"`
	WhoCanPostMessage    string        `json:"who_can_post_message,omitempty"`
	Members              []GroupMember `json:"members,omitempty"`

	settingsErr error
	membersErr  error
}

// GroupMember is a single group membership row (internal level).
type GroupMember struct {
	Email            string `json:"email"`
	Role             string `json:"role,omitempty"`
	Type             string `json:"type,omitempty"`
	Status           string `json:"status,omitempty"`
	DeliverySettings string `json:"delivery_settings,omitempty"`
}

// UserMetrics contains user population counts. Inventory carries the per-user
// rows surfaced at audit and above; it is omitted entirely at trust.
// Total, Suspended, Archived, and LockedPct come from the usage report; Active
// and InactivePct from the live Directory user scan.
type UserMetrics struct {
	Total                     *int     `json:"total"`
	Suspended                 *int     `json:"suspended"`
	Archived                  *int     `json:"archived"`
	Active                    *int     `json:"active"`
	LockedPct                 *float64 `json:"locked_pct"`
	InactivePct               *float64 `json:"inactive_pct"`
	InactiveDays              int      `json:"inactive_days"`
	Inventory                 []User   `json:"inventory,omitempty"`
	TruncatedInventory        bool     `json:"truncated_inventory,omitempty"`
	TruncatedInventoryDropped int      `json:"truncated_inventory_dropped,omitempty"`
}

// User is a per-user inventory row emitted at audit and above. Per-user passkey
// and hardware-security-key registration, and per-user password strength, are
// intentionally absent: the Directory API exposes those only as org-level
// aggregates (carried in the trust-level usage-report metrics), not per user.
type User struct {
	PrimaryEmail  string `json:"primary_email"`
	Suspended     bool   `json:"suspended"`
	Archived      bool   `json:"archived"`
	OrgUnitPath   string `json:"org_unit_path,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	AgreedToTerms bool   `json:"agreed_to_terms"`
	IPAllowlisted bool   `json:"ip_allowlisted"`
	TwoSVEnrolled bool   `json:"2sv_enrolled"`
	TwoSVEnforced bool   `json:"2sv_enforced"`
	Active7d      bool   `json:"active_7d"`
	Active30d     bool   `json:"active_30d"`

	// Internal-level fields. Populated only at internal; omitempty keeps them
	// out of audit-level rows.
	LastLoginAt               string `json:"last_login_at,omitempty"`
	ChangePasswordAtNextLogin bool   `json:"change_password_at_next_login,omitempty"`
}

// ActivityMetrics contains login activity percentages (audit and above).
type ActivityMetrics struct {
	Active7dPct  *float64 `json:"active_7d_pct"`
	Active30dPct *float64 `json:"active_30d_pct"`
}

// AuthMetrics contains two-step verification and passkey metrics.
type AuthMetrics struct {
	TwoSVEnrolledPct  *float64 `json:"2sv_enrolled_pct"`
	TwoSVEnforcedPct  *float64 `json:"2sv_enforced_pct"`
	TwoSVProtectedPct *float64 `json:"2sv_protected_pct"`
	PasskeyUsersPct   *float64 `json:"passkey_users_pct"`
	SecurityKeysTotal *int     `json:"security_keys_total"`
}

// AdminMetrics contains privileged user counts plus 2-step enrollment and
// enforcement. Inventory and CustomRoles carry the per-admin and per-role detail
// surfaced at audit and above; both are omitted at trust.
type AdminMetrics struct {
	PrivilegedUsersCount          *int         `json:"privileged_users_count"`
	SuperAdminCount               *int         `json:"super_admin_count"`
	DelegatedAdminCount           *int         `json:"delegated_admin_count"`
	PrivilegedUsers2SVEnrolledPct *float64     `json:"privileged_users_2sv_enrolled_pct"`
	PrivilegedUsers2SVEnforcedPct *float64     `json:"privileged_users_2sv_enforced_pct"`
	Inventory                     []Admin      `json:"inventory,omitempty"`
	CustomRoles                   []CustomRole `json:"custom_roles,omitempty"`
}

// Admin is a per-privileged-user inventory row emitted at audit and above.
type Admin struct {
	PrimaryEmail   string   `json:"primary_email"`
	SuperAdmin     bool     `json:"super_admin"`
	DelegatedAdmin bool     `json:"delegated_admin"`
	TwoSVEnrolled  bool     `json:"2sv_enrolled"`
	TwoSVEnforced  bool     `json:"2sv_enforced"`
	Roles          []string `json:"roles,omitempty"`

	// Internal-level field: whether any of the admin's role grants are scoped to
	// an org unit rather than the whole org.
	OrgUnitScoped bool `json:"org_unit_scoped,omitempty"`
}

// CustomRole is an admin-defined (non-system) role definition, surfaced at audit.
type CustomRole struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	PrivilegeCount int    `json:"privilege_count"`
}

// PasswordMetrics contains password hygiene metrics.
type PasswordMetrics struct {
	WeakPasswordPct               *float64 `json:"weak_password_pct"`
	PasswordLengthNonCompliantPct *float64 `json:"password_length_non_compliant_pct"`

	Policy *PasswordPolicyConfig `json:"policy,omitempty"`
}

// PasswordPolicyConfig is the weakest password policy in force anywhere in the
// tenant, separated from the outcome percentages above because it states what
// is required rather than what the population currently does.
//
// Google returns a policy per org unit and per group, so a tenant can define
// several. A reviewer needs the value they can rely on everywhere, which is the
// floor: the smallest minimum, strength and enforcement only where universally
// true, reuse permitted if permitted anywhere. DistinctPolicies tells a reader
// whether the tenant is uniform or whether these values are a floor.
//
// The whole object is absent when the Policy API could not be read, so an
// unreadable policy is never confused with a permissive one.
type PasswordPolicyConfig struct {
	MinimumLength              int    `json:"minimum_length"`
	MaximumLength              int    `json:"maximum_length"`
	AllowedStrength            string `json:"allowed_strength"`
	EnforceRequirementsAtLogin bool   `json:"enforce_requirements_at_login"`
	AllowReuse                 bool   `json:"allow_reuse"`
	ExpirationDays             int    `json:"expiration_days"`
	DistinctPolicies           int    `json:"distinct_policies"`
}

// SignInPolicy holds the tenant's sign-in settings from the Policy API, each
// the weakest value any org unit or group gets. A value is left out with a
// gap when its policies could not be read, and the object is left out when
// neither could be.
type SignInPolicy struct {
	WebSessionDurationMaxMinutes *int  `json:"web_session_duration_max_minutes,omitempty"`
	LessSecureAppsAllowed        *bool `json:"less_secure_apps_allowed,omitempty"`
}

// AppMetrics contains application security metrics (internal only).
type AppMetrics struct {
	AuthorizedAppsCount *int `json:"authorized_apps_count"`
}

// DeviceAccessMetrics captures deny-event evidence that Context-Aware Access
// evaluated device-state conditions for Google Workspace resources.
type DeviceAccessMetrics struct {
	LookbackDays                      int                          `json:"lookback_days"`
	ContextAwareAccessDeniedEvents    int                          `json:"context_aware_access_denied_events"`
	DeviceStateDeniedEvents           int                          `json:"device_state_denied_events"`
	ManagedDeviceRequirementEvidenced bool                         `json:"managed_device_requirement_evidenced"`
	AccessContextManager              *AccessContextManagerMetrics `json:"access_context_manager,omitempty"`
}

// AccessContextManagerMetrics summarizes Access Context Manager access-level
// config that is relevant to Workspace device access. The policy's name and
// parent are written from the audit level.
type AccessContextManagerMetrics struct {
	AccessPolicyName                    string   `json:"access_policy_name,omitempty"`
	AccessPolicyParent                  string   `json:"access_policy_parent,omitempty"`
	BasicAccessLevelsCount              int      `json:"basic_access_levels_count"`
	CustomAccessLevelsCount             int      `json:"custom_access_levels_count"`
	BasicDevicePolicyAccessLevelsCount  int      `json:"basic_device_policy_access_levels_count"`
	BasicManagedDeviceAccessLevelsCount int      `json:"basic_managed_device_access_levels_count"`
	BasicDevicePolicyAccessLevelTitles  []string `json:"basic_device_policy_access_level_titles,omitempty"`

	// Levels carries the per-access-level rows surfaced at audit and above;
	// omitted at trust.
	Levels []AccessLevelSummary `json:"levels,omitempty"`
}

// AccessLevelSummary is a per-access-level row emitted at audit and above. Audit
// emits the title + device-policy summary; internal adds the rule details
// (IP subnetworks, regions, required access levels, encryption statuses).
type AccessLevelSummary struct {
	Title                 string `json:"title"`
	Custom                bool   `json:"custom"`
	HasDevicePolicy       bool   `json:"has_device_policy"`
	RequiresScreenlock    bool   `json:"requires_screenlock"`
	RequiresAdminApproval bool   `json:"requires_admin_approval"`
	RequiresCorpOwned     bool   `json:"requires_corp_owned"`
	OSConstraintCount     int    `json:"os_constraint_count"`

	// Internal-level rule details.
	AllowedDeviceManagementLevels []string `json:"allowed_device_management_levels,omitempty"`
	AllowedEncryptionStatuses     []string `json:"allowed_encryption_statuses,omitempty"`
	IPSubnetworks                 []string `json:"ip_subnetworks,omitempty"`
	Regions                       []string `json:"regions,omitempty"`
	RequiredAccessLevels          []string `json:"required_access_levels,omitempty"`
}

// AuditString is a string the detailed artifact writes from the audit level,
// as null when it was not read. Below the audit level Write is false and the
// field is left out.
type AuditString struct {
	Value *string
	Write bool
}

// IsZero reports whether the field is left out, for omitzero.
func (s AuditString) IsZero() bool { return !s.Write }

// MarshalJSON writes the value, or null.
func (s AuditString) MarshalJSON() ([]byte, error) { return json.Marshal(s.Value) }

// UnmarshalJSON reads a written value, or null.
func (s *AuditString) UnmarshalJSON(data []byte) error {
	s.Write = true
	return json.Unmarshal(data, &s.Value)
}

// Diagnostics contains informational gaps and caveats. Scope and admin-role
// denials (a missing permission the customer can grant) are reported under
// PermissionErrors; everything else (licensing gaps, lag caveats, truncation)
// under Warnings.
type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// NewOrgPosture creates an initialized posture document. The customer and the
// usage report fill in their fields as they are read.
func NewOrgPosture(collectedAt time.Time) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   collectedAt.UTC().Format(time.RFC3339),
		Provider:      "google-workspace",
		Users:         UserMetrics{InactiveDays: DefaultInactiveDays},
	}
}
