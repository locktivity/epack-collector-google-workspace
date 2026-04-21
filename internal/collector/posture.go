package collector

import "time"

const (
	// SchemaVersion is the version of the detailed Google Workspace artifact.
	SchemaVersion = "1.0.0"
	// DefaultInactiveDays is the threshold for inactive user detection.
	DefaultInactiveDays = 90
)

// StatusFunc reports indeterminate progress.
type StatusFunc func(message string)

// ProgressFunc reports determinate progress.
type ProgressFunc func(current, total int64, message string)

// Config holds collector configuration.
type Config struct {
	Customer        string `json:"customer,omitempty"`
	AdminEmail      string `json:"admin_email"`
	CredentialsJSON string `json:"-"`

	OnStatus   StatusFunc       `json:"-"`
	OnProgress ProgressFunc     `json:"-"`
	Now        func() time.Time `json:"-"`
}

// OrgPosture is the detailed Google Workspace posture artifact.
type OrgPosture struct {
	SchemaVersion   string          `json:"schema_version"`
	CollectedAt     string          `json:"collected_at"`
	UsageReportDate string          `json:"usage_report_date"`
	Provider        string          `json:"provider"`
	OrgDomain       string          `json:"org_domain"`
	CustomerID      string          `json:"customer_id"`
	Users           UserMetrics     `json:"users"`
	Activity        ActivityMetrics `json:"activity"`
	Authentication  AuthMetrics     `json:"authentication"`
	Admins          AdminMetrics    `json:"admins"`
	Passwords       PasswordMetrics `json:"passwords"`
	Apps            AppMetrics      `json:"apps"`
	Diagnostics     *Diagnostics    `json:"diagnostics,omitempty"`
}

// UserMetrics contains user population counts.
type UserMetrics struct {
	Total        int     `json:"total"`
	Suspended    int     `json:"suspended"`
	Archived     int     `json:"archived"`
	LockedPct    float64 `json:"locked_pct"`
	InactivePct  float64 `json:"inactive_pct"`
	InactiveDays int     `json:"inactive_days"`
}

// ActivityMetrics contains login activity percentages.
type ActivityMetrics struct {
	Active7dPct  float64 `json:"active_7d_pct"`
	Active30dPct float64 `json:"active_30d_pct"`
}

// AuthMetrics contains two-step verification and passkey metrics.
type AuthMetrics struct {
	TwoSVEnrolledPct  float64 `json:"2sv_enrolled_pct"`
	TwoSVEnforcedPct  float64 `json:"2sv_enforced_pct"`
	TwoSVProtectedPct float64 `json:"2sv_protected_pct"`
	PasskeyUsersPct   float64 `json:"passkey_users_pct"`
	SecurityKeysTotal int     `json:"security_keys_total"`
}

// AdminMetrics contains privileged user counts and enforcement.
type AdminMetrics struct {
	SuperAdminCount               int     `json:"super_admin_count"`
	DelegatedAdminCount           int     `json:"delegated_admin_count"`
	PrivilegedUsers2SVEnforcedPct float64 `json:"privileged_users_2sv_enforced_pct"`
}

// PasswordMetrics contains password hygiene metrics.
type PasswordMetrics struct {
	WeakPasswordPct               float64 `json:"weak_password_pct"`
	PasswordLengthNonCompliantPct float64 `json:"password_length_non_compliant_pct"`
}

// AppMetrics contains application security metrics.
type AppMetrics struct {
	AuthorizedAppsCount int `json:"authorized_apps_count"`
}

// Diagnostics contains informational gaps and caveats.
type Diagnostics struct {
	Warnings []string `json:"warnings,omitempty"`
}

// NewOrgPosture creates an initialized posture document.
func NewOrgPosture(domain, customerID, reportDate string, collectedAt time.Time) *OrgPosture {
	return &OrgPosture{
		SchemaVersion:   SchemaVersion,
		CollectedAt:     collectedAt.UTC().Format(time.RFC3339),
		UsageReportDate: reportDate,
		Provider:        "google-workspace",
		OrgDomain:       domain,
		CustomerID:      customerID,
	}
}
