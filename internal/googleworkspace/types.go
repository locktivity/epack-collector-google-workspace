package googleworkspace

import (
	"context"
	"time"
)

const DefaultCustomerKey = "my_customer"

// User captures the Google Workspace user fields used by the collector.
type User struct {
	PrimaryEmail     string
	Suspended        bool
	Archived         bool
	IsAdmin          bool
	IsDelegatedAdmin bool
	IsEnrolledIn2Sv  bool
	IsEnforcedIn2Sv  bool
	LastLoginTime    time.Time
	LastLoginMissing bool
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
}

// Client defines the Google Workspace operations needed by the collector.
type Client interface {
	GetCustomer(ctx context.Context, customerKey string) (Customer, error)
	GetCustomerUsageReport(ctx context.Context, customerID, date string) (CustomerUsageReport, error)
	ListUsers(ctx context.Context, customerKey string, callback func([]User) error) error
	ListContextAwareAccessEvents(ctx context.Context, customerID string, startTime time.Time, callback func([]ContextAwareAccessEvent) error) error
	ListAccessPolicies(ctx context.Context, parent string, callback func([]AccessPolicy) error) error
	ListAccessLevels(ctx context.Context, policyName string, callback func([]AccessLevel) error) error
}
