package collector

import "math"

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     IDPPostureUserSecurity      `json:"user_security"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	DeviceAccess     *IDPPostureDeviceAccess     `json:"device_access,omitempty"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct                float64  `json:"mfa_coverage_pct"`
	MFAPhishingResistantPct       float64  `json:"mfa_phishing_resistant_pct"`
	InactivePct                   float64  `json:"inactive_pct"`
	LockedOutPct                  float64  `json:"locked_out_pct"`
	WeakPasswordPct               *float64 `json:"weak_password_pct,omitempty"`
	PasswordPolicyNoncompliantPct *float64 `json:"password_policy_noncompliant_pct,omitempty"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct                *float64 `json:"sso_coverage_pct,omitempty"`
	ProvisioningEnabledPct        *float64 `json:"provisioning_enabled_pct,omitempty"`
	DeprovisioningEnabledPct      *float64 `json:"deprovisioning_enabled_pct,omitempty"`
	AuthorizedThirdPartyAppsCount *int     `json:"authorized_third_party_apps_count,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersCount           int      `json:"privileged_users_count"`
	SuperAdminCount                int      `json:"super_admin_count"`
	PrivilegedMFACoveragePct       *float64 `json:"privileged_mfa_coverage_pct,omitempty"`
	PrivilegedPhishingResistantPct *float64 `json:"privileged_phishing_resistant_pct,omitempty"`
	StandingPrivilegedUsersCount   *int     `json:"standing_privileged_users_count,omitempty"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired                            bool     `json:"mfa_required"`
	MFARequiredCoveragePct                 *float64 `json:"mfa_required_coverage_pct,omitempty"`
	SessionLifetimeMaxMin                  *int     `json:"session_lifetime_max_min,omitempty"`
	IdleTimeoutMaxMin                      *int     `json:"idle_timeout_max_min,omitempty"`
	LegacyAuthBlocked                      *bool    `json:"legacy_auth_blocked,omitempty"`
	PhishingResistantRequiredForPrivileged *bool    `json:"phishing_resistant_required_for_privileged,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics.
type IDPPostureLifecycle struct {
	SuspendedPct *float64 `json:"suspended_pct,omitempty"`
	ArchivedPct  *float64 `json:"archived_pct,omitempty"`
}

// IDPPostureDeviceAccess contains managed-device posture inferred from
// provider-specific evidence.
type IDPPostureDeviceAccess struct {
	ManagedDeviceRequired          *bool `json:"managed_device_required,omitempty"`
	ManagedDeviceRequiredForAdmins *bool `json:"managed_device_required_for_admins,omitempty"`
}

// ToIDPPosture transforms detailed Google Workspace posture into the shared
// idp-posture@v1 shape.
//
// Returns nil when the usage report contains no user data (Users.Total == 0),
// because all report-backed percentages would be zero and indistinguishable
// from a tenant with genuinely poor posture. Callers should skip emitting the
// normalized artifact in this case.
//
// Fields we can populate from the Reports and Directory APIs:
//   - user_security: MFA coverage, phishing resistance, inactivity, lockouts,
//     weak passwords, and password policy compliance
//   - app_security.authorized_third_party_apps_count
//   - privileged_access: admin counts and privileged MFA coverage
//   - policy.mfa_required / policy.mfa_required_coverage_pct /
//     legacy_auth_blocked
//   - lifecycle: suspended and archived account percentages
//   - device_access.managed_device_required, when Context-Aware Access audit
//     logs show device-state-based deny events
//
// Fields we omit because the APIs do not expose them:
//   - app_security.sso_coverage_pct / provisioning_enabled_pct /
//     deprovisioning_enabled_pct
//   - privileged_access.privileged_phishing_resistant_pct
//   - policy.session_lifetime_max_min / idle_timeout_max_min /
//     phishing_resistant_required_for_privileged
//   - device_access.managed_device_required_for_admins
//
// Caveat: Google Workspace Context-Aware Access audit logs are deny-only and
// do not distinguish clean active-mode enforcement from all monitor-mode
// scenarios, so this field is emitted only as a positive signal when deny
// events cite device state.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.Users.Total == 0 {
		return nil
	}

	mfaCoveragePct := math.Max(o.Authentication.TwoSVProtectedPct, o.Authentication.PasskeyUsersPct)
	weakPasswordPct := o.Passwords.WeakPasswordPct
	passwordPolicyNoncompliantPct := o.Passwords.PasswordLengthNonCompliantPct
	privilegedMFACoveragePct := o.Admins.PrivilegedUsers2SVEnrolledPct
	mfaRequiredCoveragePct := o.Authentication.TwoSVEnforcedPct
	authorizedAppsCount := o.Apps.AuthorizedAppsCount
	suspendedPct := percentFloat(o.Users.Suspended, o.Users.Total)
	archivedPct := percentFloat(o.Users.Archived, o.Users.Total)
	standingPrivilegedUsersCount := o.Admins.PrivilegedUsersCount
	legacyAuthBlocked := true

	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   o.CollectedAt,
		Provider:      "google_workspace",
		OrgDomain:     o.OrgDomain,
		UserSecurity: IDPPostureUserSecurity{
			MFACoveragePct:                mfaCoveragePct,
			MFAPhishingResistantPct:       o.Authentication.PasskeyUsersPct,
			InactivePct:                   o.Users.InactivePct,
			LockedOutPct:                  o.Users.LockedPct,
			WeakPasswordPct:               &weakPasswordPct,
			PasswordPolicyNoncompliantPct: &passwordPolicyNoncompliantPct,
		},
		AppSecurity: &IDPPostureAppSecurity{
			AuthorizedThirdPartyAppsCount: &authorizedAppsCount,
		},
		PrivilegedAccess: &IDPPosturePrivilegedAccess{
			PrivilegedUsersCount:         o.Admins.PrivilegedUsersCount,
			SuperAdminCount:              o.Admins.SuperAdminCount,
			PrivilegedMFACoveragePct:     &privilegedMFACoveragePct,
			StandingPrivilegedUsersCount: &standingPrivilegedUsersCount,
		},
		Policy: &IDPPosturePolicy{
			MFARequired:            o.Authentication.TwoSVEnforcedPct == 100,
			MFARequiredCoveragePct: &mfaRequiredCoveragePct,
			LegacyAuthBlocked:      &legacyAuthBlocked,
		},
		Lifecycle: &IDPPostureLifecycle{
			SuspendedPct: &suspendedPct,
			ArchivedPct:  &archivedPct,
		},
	}

	if o.DeviceAccess != nil && o.DeviceAccess.ManagedDeviceRequirementEvidenced {
		managedDeviceRequired := true
		posture.DeviceAccess = &IDPPostureDeviceAccess{
			ManagedDeviceRequired: &managedDeviceRequired,
		}
	}

	return posture
}
