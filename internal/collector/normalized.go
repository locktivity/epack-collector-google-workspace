package collector

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
type IDPPosture struct {
	SchemaVersion string                 `json:"schema_version"`
	CollectedAt   string                 `json:"collected_at"`
	Provider      string                 `json:"provider"`
	OrgDomain     string                 `json:"org_domain"`
	UserSecurity  IDPPostureUserSecurity `json:"user_security"`
	AppSecurity   *IDPPostureAppSecurity `json:"app_security,omitempty"`
	Policy        *IDPPosturePolicy      `json:"policy,omitempty"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct          float64 `json:"mfa_coverage_pct"`
	MFAPhishingResistantPct float64 `json:"mfa_phishing_resistant_pct"`
	InactivePct             float64 `json:"inactive_pct"`
	LockedOutPct            float64 `json:"locked_out_pct"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct         float64 `json:"sso_coverage_pct"`
	ProvisioningEnabledPct float64 `json:"provisioning_enabled_pct"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired           bool `json:"mfa_required"`
	SessionLifetimeMaxMin *int `json:"session_lifetime_max_min,omitempty"`
	IdleTimeoutMaxMin     *int `json:"idle_timeout_max_min,omitempty"`
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
//   - mfa_coverage_pct: 2SV protected percentage (effective MFA coverage)
//   - mfa_phishing_resistant_pct: passkey adoption percentage
//   - inactive_pct: users inactive 90+ days
//   - locked_out_pct: locked user percentage
//   - policy.mfa_required: true when 2SV is enforced for 100% of users
//
// Fields we omit because the APIs do not expose them:
//   - app_security: SSO coverage and provisioning require app-level config
//     data not available through the Reports or Directory APIs
//   - policy.session_lifetime_max_min / idle_timeout_max_min: require
//     tenant-level session settings not exposed by these APIs
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.Users.Total == 0 {
		return nil
	}

	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   o.CollectedAt,
		Provider:      "google_workspace",
		OrgDomain:     o.OrgDomain,
		UserSecurity: IDPPostureUserSecurity{
			MFACoveragePct:          o.Authentication.TwoSVProtectedPct,
			MFAPhishingResistantPct: o.Authentication.PasskeyUsersPct,
			InactivePct:             o.Users.InactivePct,
			LockedOutPct:            o.Users.LockedPct,
		},
	}

	// Infer MFA policy from enforcement coverage. Only set mfa_required=true
	// when 100% of users have 2SV enforced by policy; partial enforcement
	// cannot honestly map to a boolean "required" signal.
	if o.Authentication.TwoSVEnforcedPct == 100 {
		posture.Policy = &IDPPosturePolicy{MFARequired: true}
	}

	return posture
}
