package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
// A value the detailed artifact left out is absent here too, with the same
// gap. A percentage over an empty population is null. The counts behind the
// percentages are written from the audit level, as the schema marks them,
// and the present flags at every level.
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     *IDPPostureUserSecurity     `json:"user_security,omitempty"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	DeviceAccess     *IDPPostureDeviceAccess     `json:"device_access,omitempty"`
}

// Percentage is a normalized percentage. It is left out when Read is false.
// Otherwise it is written as Value, which is nil over an empty population.
type Percentage struct {
	Value *float64
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p Percentage) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p Percentage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

// IDPPostureUserSecurity contains user security metrics. Its users are the
// active users of the live Directory scan. The usage report percentages are
// taken over the report's total users, so their counts are not written. See
// ToIDPPosture.
type IDPPostureUserSecurity struct {
	UsersPresent                  *bool      `json:"users_present,omitempty"`
	UserCount                     *int       `json:"user_count,omitempty"`
	InactiveUserCount             *int       `json:"inactive_user_count,omitempty"`
	MFACoveragePct                Percentage `json:"mfa_coverage_pct,omitzero"`
	MFAPhishingResistantPct       Percentage `json:"mfa_phishing_resistant_pct,omitzero"`
	InactivePct                   Percentage `json:"inactive_pct,omitzero"`
	LockedOutPct                  Percentage `json:"locked_out_pct,omitzero"`
	WeakPasswordPct               Percentage `json:"weak_password_pct,omitzero"`
	PasswordPolicyNoncompliantPct Percentage `json:"password_policy_noncompliant_pct,omitzero"`
}

// IDPPostureAppSecurity contains application security metrics. Per-app SSO
// and provisioning settings are not in the Google Workspace APIs, so those
// values are left out with an unsupported gap. See idpPostureLeftOut.
type IDPPostureAppSecurity struct {
	AuthorizedThirdPartyAppsCount *int `json:"authorized_third_party_apps_count,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
// An admin role can be assigned until a set time, and the collector does not
// read those times. So the standing values are written only for a tenant with
// no admins. See recordIDPPostureGaps.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersPresent         *bool      `json:"privileged_users_present,omitempty"`
	PrivilegedUsersCount           *int       `json:"privileged_users_count,omitempty"`
	SuperAdminCount                *int       `json:"super_admin_count,omitempty"`
	PrivilegedMFAUserCount         *int       `json:"privileged_mfa_user_count,omitempty"`
	PrivilegedMFACoveragePct       Percentage `json:"privileged_mfa_coverage_pct,omitzero"`
	StandingPrivilegedUsersPresent *bool      `json:"standing_privileged_users_present,omitempty"`
	StandingPrivilegedUsersCount   *int       `json:"standing_privileged_users_count,omitempty"`
}

// IDPPosturePolicy contains aggregated policy settings. The session length
// comes from the Policy API's sign-in settings. Google stopped supporting
// less secure apps on May 1, 2025, so their setting has no effect on legacy
// sign-in. Users with 2-step verification can still sign in to mail and
// calendar apps with an app password, which no API reports. So
// legacy_auth_blocked is left out. See idpPostureLeftOut.
type IDPPosturePolicy struct {
	MFARequired            *bool      `json:"mfa_required,omitempty"`
	MFARequiredUserCount   *int       `json:"mfa_required_user_count,omitempty"`
	MFARequiredCoveragePct Percentage `json:"mfa_required_coverage_pct,omitzero"`
	SessionLifetimeMaxMin  *int       `json:"session_lifetime_max_min,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics. Its
// accounts are the usage report's total users, in every state.
type IDPPostureLifecycle struct {
	AccountsPresent       *bool      `json:"accounts_present,omitempty"`
	AccountCount          *int       `json:"account_count,omitempty"`
	SuspendedAccountCount *int       `json:"suspended_account_count,omitempty"`
	ArchivedAccountCount  *int       `json:"archived_account_count,omitempty"`
	SuspendedPct          Percentage `json:"suspended_pct,omitzero"`
	ArchivedPct           Percentage `json:"archived_pct,omitzero"`
}

// IDPPostureDeviceAccess contains managed-device posture inferred from
// provider-specific evidence.
type IDPPostureDeviceAccess struct {
	ManagedDeviceRequired *bool `json:"managed_device_required,omitempty"`
}

// ToIDPPosture transforms detailed Google Workspace posture into the shared
// idp-posture@v1 shape.
//
// It returns nil when the tenant's primary domain is unknown, because the
// shared shape requires it. A normalized value is left out when a value it
// comes from was left out. Each percentage is taken from its counts and
// rounded as the idp-posture schema says. Where more is worse, as with
// inactive users, it rounds up.
//
// user_security.user_count is the active users of the live Directory scan,
// and inactive_pct is taken over it. mfa_coverage_pct takes its 2-step
// verification share over it too. The other user_security percentages come
// from the usage report and are taken over its total users, which include
// suspended and archived ones. They are written without their counts. They
// are left out when the scan failed, since users_present comes from the scan.
//
// device_access.managed_device_required is written only as a positive
// signal, when Context-Aware Access deny events cite device state. Those
// audit logs record only denials, and a denial in monitor mode looks the
// same as one in active mode.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.OrgDomain == nil {
		return nil
	}
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	atAudit := func(count *int) *int {
		if audit {
			return count
		}
		return nil
	}
	n := o.counts
	active, reportUsers := o.Users.Active, o.Users.Total

	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   o.CollectedAt,
		Provider:      "google_workspace",
		OrgDomain:     *o.OrgDomain,
	}

	usersPresent := present(active)
	reported := func(count *int, rounding componentsdk.Rounding) Percentage {
		return over(usersPresent, count, reportUsers, rounding)
	}
	userSecurity := IDPPostureUserSecurity{
		UsersPresent:                  usersPresent,
		UserCount:                     atAudit(active),
		InactiveUserCount:             atAudit(n.inactiveUsers),
		MFACoveragePct:                mfaCoverage(usersPresent, n.enrolled2SVUsers, active, n.passkeyUsers, reportUsers),
		MFAPhishingResistantPct:       reported(n.passkeyUsers, componentsdk.RoundDown),
		InactivePct:                   share(n.inactiveUsers, active, componentsdk.RoundUp),
		LockedOutPct:                  reported(n.lockedUsers, componentsdk.RoundUp),
		WeakPasswordPct:               reported(n.weakPasswordUsers, componentsdk.RoundUp),
		PasswordPolicyNoncompliantPct: reported(n.shortPasswordUsers, componentsdk.RoundUp),
	}
	if o.thirdPartySSO != nil {
		userSecurity.MFACoveragePct, userSecurity.MFAPhishingResistantPct = Percentage{}, Percentage{}
	}
	if userSecurity != (IDPPostureUserSecurity{}) {
		posture.UserSecurity = &userSecurity
	}

	if o.Apps != nil && o.Apps.AuthorizedAppsCount != nil {
		posture.AppSecurity = &IDPPostureAppSecurity{
			AuthorizedThirdPartyAppsCount: atAudit(o.Apps.AuthorizedAppsCount),
		}
	}

	privileged := n.privileged
	privilegedPresent := present(privileged)
	if n.privilegedErr != nil && o.Admins.SuperAdminCount != nil && *o.Admins.SuperAdminCount > 0 {
		privilegedPresent = boolPtr(true)
	}
	privilegedAccess := IDPPosturePrivilegedAccess{
		PrivilegedUsersPresent:   privilegedPresent,
		PrivilegedUsersCount:     atAudit(privileged),
		SuperAdminCount:          atAudit(o.Admins.SuperAdminCount),
		PrivilegedMFAUserCount:   atAudit(n.privileged2SVEnrolled),
		PrivilegedMFACoveragePct: share(n.privileged2SVEnrolled, privileged, componentsdk.RoundDown),
	}
	if privileged != nil && *privileged == 0 {
		privilegedAccess.StandingPrivilegedUsersPresent = boolPtr(false)
		privilegedAccess.StandingPrivilegedUsersCount = atAudit(privileged)
	}
	if o.thirdPartySSO != nil && delegatedPrivileged(o) {
		privilegedAccess.PrivilegedMFAUserCount, privilegedAccess.PrivilegedMFACoveragePct = nil, Percentage{}
	}
	if privilegedAccess != (IDPPosturePrivilegedAccess{}) {
		posture.PrivilegedAccess = &privilegedAccess
	}

	policy := IDPPosturePolicy{
		MFARequired:            all(n.enforced2SVUsers, active),
		MFARequiredUserCount:   atAudit(n.enforced2SVUsers),
		MFARequiredCoveragePct: share(n.enforced2SVUsers, active, componentsdk.RoundDown),
	}
	if o.thirdPartySSO != nil {
		policy.MFARequired, policy.MFARequiredUserCount, policy.MFARequiredCoveragePct = nil, nil, Percentage{}
	}
	if o.SignIn != nil {
		policy.SessionLifetimeMaxMin = o.SignIn.WebSessionDurationMaxMinutes
	}
	if policy != (IDPPosturePolicy{}) {
		posture.Policy = &policy
	}

	lifecycle := IDPPostureLifecycle{
		AccountsPresent:       present(reportUsers),
		AccountCount:          atAudit(reportUsers),
		SuspendedAccountCount: atAudit(o.Users.Suspended),
		ArchivedAccountCount:  atAudit(o.Users.Archived),
		SuspendedPct:          share(o.Users.Suspended, reportUsers, componentsdk.RoundUp),
		ArchivedPct:           share(o.Users.Archived, reportUsers, componentsdk.RoundUp),
	}
	if lifecycle != (IDPPostureLifecycle{}) {
		posture.Lifecycle = &lifecycle
	}

	if o.DeviceAccess != nil && o.DeviceAccess.ManagedDeviceRequirementEvidenced {
		posture.DeviceAccess = &IDPPostureDeviceAccess{ManagedDeviceRequired: boolPtr(true)}
	}
	return posture
}

// share returns count as a percentage of total, rounded as rounding says.
// It is null when total is 0, and left out when count or total was not read.
func share(count, total *int, rounding componentsdk.Rounding) Percentage {
	if total != nil && *total == 0 {
		return Percentage{Read: true}
	}
	if count == nil || total == nil {
		return Percentage{}
	}
	return Percentage{Value: floatOf(componentsdk.Percent(*count, *total, rounding)), Read: true}
}

// over returns a usage report percentage for the user_security section,
// whose users_present is usersPresent. It is null when the section has no
// users, and left out when usersPresent was not read. It is also left out
// when the report has 0 users. recordIDPPostureGaps records a gap for that
// case.
func over(usersPresent *bool, count, reportUsers *int, rounding componentsdk.Rounding) Percentage {
	switch {
	case usersPresent == nil:
		return Percentage{}
	case !*usersPresent:
		return Percentage{Read: true}
	case reportUsers != nil && *reportUsers == 0:
		return Percentage{}
	}
	return share(count, reportUsers, rounding)
}

// mfaCoverage is the larger of two shares, rounded down. One is the active
// users enrolled in 2-step verification, out of all active users. Suspended
// and archived users are not in it. The other is the usage report's users
// with a passkey, out of its total users. A passkey does not turn on 2-step
// verification, and the report is the only count of passkey users. The value
// is left out when the passkey share is.
func mfaCoverage(usersPresent *bool, enrolled, active, passkeys, reportUsers *int) Percentage {
	passkey := over(usersPresent, passkeys, reportUsers, componentsdk.RoundDown)
	if passkey.Value == nil {
		return passkey
	}
	twoSV := share(enrolled, active, componentsdk.RoundDown)
	if twoSV.Value != nil && *twoSV.Value > *passkey.Value {
		return twoSV
	}
	return passkey
}

// all returns whether count is all of total, or nil when either was not read
// or total is 0.
func all(count, total *int) *bool {
	if count == nil || total == nil || *total == 0 {
		return nil
	}
	return boolPtr(*count == *total)
}

// present returns whether a population of count has any members, or nil
// when count could not be read.
func present(count *int) *bool {
	if count == nil {
		return nil
	}
	return boolPtr(*count > 0)
}

func floatOf(v *int) *float64 {
	if v == nil {
		return nil
	}
	f := float64(*v)
	return &f
}

func boolPtr(v bool) *bool { return &v }

// idpSources maps each normalized value to the detailed values it comes from,
// so a value left out carries its source's gap. A count the detailed
// artifact holds only as a percentage comes from that percentage.
var idpSources = []struct {
	to   string
	from []string
}{
	{"/user_security/users_present", []string{"/users/active"}},
	{"/user_security/user_count", []string{"/users/active"}},
	{"/user_security/inactive_user_count", []string{"/users/inactive_pct"}},
	{"/user_security/mfa_coverage_pct", []string{"/users/active", "/authentication/2sv_enrolled_pct", "/authentication/passkey_users_pct"}},
	{"/user_security/mfa_phishing_resistant_pct", []string{"/users/active", "/authentication/passkey_users_pct"}},
	{"/user_security/inactive_pct", []string{"/users/active", "/users/inactive_pct"}},
	{"/user_security/locked_out_pct", []string{"/users/active", "/users/locked_pct"}},
	{"/user_security/weak_password_pct", []string{"/users/active", "/passwords/weak_password_pct"}},
	{"/user_security/password_policy_noncompliant_pct", []string{"/users/active", "/passwords/password_length_non_compliant_pct"}},
	{"/app_security/authorized_third_party_apps_count", []string{"/apps/authorized_apps_count"}},
	{"/privileged_access/privileged_users_present", []string{"/admins/privileged_users_count"}},
	{"/privileged_access/privileged_users_count", []string{"/admins/privileged_users_count"}},
	{"/privileged_access/super_admin_count", []string{"/admins/super_admin_count"}},
	{"/privileged_access/privileged_mfa_user_count", []string{"/admins/privileged_users_2sv_enrolled_pct"}},
	{"/privileged_access/privileged_mfa_coverage_pct", []string{"/admins/privileged_users_count", "/admins/privileged_users_2sv_enrolled_pct"}},
	{"/privileged_access/standing_privileged_users_present", []string{"/admins/privileged_users_count"}},
	{"/privileged_access/standing_privileged_users_count", []string{"/admins/privileged_users_count"}},
	{"/policy/mfa_required", []string{"/users/active", "/authentication/2sv_enforced_pct"}},
	{"/policy/mfa_required_user_count", []string{"/authentication/2sv_enforced_pct"}},
	{"/policy/mfa_required_coverage_pct", []string{"/users/active", "/authentication/2sv_enforced_pct"}},
	{"/policy/session_lifetime_max_min", []string{webSessionPointer}},
	{"/lifecycle/accounts_present", []string{"/users/total"}},
	{"/lifecycle/account_count", []string{"/users/total"}},
	{"/lifecycle/suspended_account_count", []string{"/users/suspended"}},
	{"/lifecycle/archived_account_count", []string{"/users/archived"}},
	{"/lifecycle/suspended_pct", []string{"/users/total", "/users/suspended"}},
	{"/lifecycle/archived_pct", []string{"/users/total", "/users/archived"}},
	{"/device_access/managed_device_required", []string{"/device_access"}},
}

// reportPercentages are the user_security percentages taken from the usage
// report, over its total users.
var reportPercentages = []string{
	"/user_security/mfa_coverage_pct",
	"/user_security/mfa_phishing_resistant_pct",
	"/user_security/locked_out_pct",
	"/user_security/weak_password_pct",
	"/user_security/password_policy_noncompliant_pct",
}

// idpPostureLeftOut lists the normalized values the collector leaves out,
// with the gap code and the reason. Google Workspace has no data for the
// unsupported ones. Google reports the not_read ones through reads the
// collector does not make. The audit ones are audit-level counts.
var idpPostureLeftOut = []struct {
	pointer string
	code    componentsdk.Code
	reason  string
	audit   bool
}{
	{"/app_security/apps_present", componentsdk.CodeUnsupported, perAppSettings, false},
	{"/app_security/app_count", componentsdk.CodeUnsupported, perAppSettings, true},
	{"/app_security/sso_app_count", componentsdk.CodeUnsupported, perAppSettings, true},
	{"/app_security/provisioning_app_count", componentsdk.CodeUnsupported, perAppSettings, true},
	{"/app_security/deprovisioning_app_count", componentsdk.CodeUnsupported, perAppSettings, true},
	{"/app_security/sso_coverage_pct", componentsdk.CodeUnsupported, perAppSettings, false},
	{"/app_security/provisioning_enabled_pct", componentsdk.CodeUnsupported, perAppSettings, false},
	{"/app_security/deprovisioning_enabled_pct", componentsdk.CodeUnsupported, perAppSettings, false},
	{"/privileged_access/privileged_phishing_resistant_user_count", componentsdk.CodeNotRead, perUserPasskeys, true},
	{"/privileged_access/privileged_phishing_resistant_pct", componentsdk.CodeNotRead, perUserPasskeys, false},
	{"/policy/idle_timeout_max_min", componentsdk.CodeUnsupported, idleTimeout, false},
	{"/policy/legacy_auth_blocked", componentsdk.CodeUnsupported, appPasswords, false},
	{"/policy/phishing_resistant_required_for_privileged", componentsdk.CodeNotRead, adminFactors, false},
	{"/device_access/managed_device_required_for_admins", componentsdk.CodeUnsupported, adminDevices, false},
}

const (
	perAppSettings  = "No Google Workspace API lists the apps set up for SSO or their provisioning settings."
	perUserPasskeys = "The Reports API's user usage report gives each user's passkeys as accounts:num_passkeys_enrolled, which this collector does not read. It needs the admin.reports.usage.readonly scope."
	idleTimeout     = "Google Workspace has no idle timeout for sign-in sessions. The Policy API's session controls set only a web session length."
	adminFactors    = "The Policy API gives each org unit's and group's allowed 2-Step Verification methods in security.two_step_verification_enforcement_factor, which this collector does not read. It needs the cloud-identity.policies.readonly scope."
	adminDevices    = "No Google Workspace API reports the Context-Aware Access levels assigned to apps."
	roleExpiration  = "The Directory API gives the time an admin role assignment ends in expirationDetails.expireTime, which this collector does not read. It needs the admin.directory.rolemanagement.readonly scope."
	appPasswords    = "Google Workspace does not report whether users can sign in to mail and calendar apps with app passwords."
)

// recordIDPPostureGaps records, at each normalized value, the gap of the
// detailed value it comes from. It also records the gap of each value in
// idpPostureLeftOut, and a gap at each usage report percentage when the
// report has 0 users. For a tenant with admins, it also records a gap at the
// standing values. The count gets one only at the audit level.
func idpLocation(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: idpPosturePath, Pointer: pointer}
}

// delegatedPrivileged reports whether a privileged user may be a delegated
// admin. Super admins always sign in with Google, never through a SAML
// profile.
func delegatedPrivileged(o *OrgPosture) bool {
	super := o.Admins.SuperAdminCount
	return o.counts.privileged == nil || super == nil || *o.counts.privileged > *super
}

// thirdPartyMFA lists the normalized MFA values that leave out users who
// sign in through a third-party SAML identity provider. The counts are
// audit-level fields.
var thirdPartyMFA = []struct {
	pointer string
	audit   bool
}{
	{"/user_security/mfa_coverage_pct", false},
	{"/user_security/mfa_phishing_resistant_pct", false},
	{"/policy/mfa_required", false},
	{"/policy/mfa_required_user_count", true},
	{"/policy/mfa_required_coverage_pct", false},
}

func (c *Collector) recordIDPPostureGaps(posture *OrgPosture, level componentsdk.Level) {
	for _, source := range idpSources {
		c.gaps.mirror(source.to, source.from...)
	}
	audit := level.AtLeast(componentsdk.LevelAudit)
	n := posture.counts
	superAdmins := posture.Admins.SuperAdminCount != nil && *posture.Admins.SuperAdminCount > 0
	standing := []string{"/privileged_access/standing_privileged_users_present"}
	if audit {
		standing = append(standing, "/privileged_access/standing_privileged_users_count")
	}
	if n.privilegedErr != nil {
		unknown := []string{"/privileged_access/privileged_mfa_coverage_pct"}
		if audit {
			unknown = append(unknown, "/privileged_access/privileged_users_count", "/privileged_access/privileged_mfa_user_count")
		}
		if !superAdmins {
			unknown = append(unknown, "/privileged_access/privileged_users_present")
			unknown = append(unknown, standing...)
		}
		for _, pointer := range unknown {
			c.gaps.rec.Partial(idpLocation(pointer), n.privilegedUnread, n.privilegedErr)
		}
	}
	if why := posture.thirdPartySSO; why != nil {
		for _, v := range thirdPartyMFA {
			if !v.audit || level.AtLeast(componentsdk.LevelAudit) {
				c.gaps.record(idpLocation(v.pointer), why, 0)
			}
		}
		if delegatedPrivileged(posture) {
			c.gaps.record(idpLocation("/privileged_access/privileged_mfa_coverage_pct"), why, 0)
			if level.AtLeast(componentsdk.LevelAudit) {
				c.gaps.record(idpLocation("/privileged_access/privileged_mfa_user_count"), why, 0)
			}
		}
	}
	for _, u := range idpPostureLeftOut {
		if u.audit && !level.AtLeast(componentsdk.LevelAudit) {
			continue
		}
		c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: u.pointer}, u.code, u.reason)
	}
	if privileged := n.privileged; (privileged != nil && *privileged > 0) || (n.privilegedErr != nil && superAdmins) {
		for _, pointer := range standing {
			c.gaps.rec.NotCollectedCode(idpLocation(pointer), componentsdk.CodeNotRead, roleExpiration)
		}
	}
	if active := posture.Users.Active; active == nil || *active == 0 {
		return
	}
	if total := posture.Users.Total; total != nil && *total == 0 {
		for _, pointer := range reportPercentages {
			c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: pointer}, componentsdk.CodeVendorError,
				"The usage report lists 0 users.")
		}
	}
}
