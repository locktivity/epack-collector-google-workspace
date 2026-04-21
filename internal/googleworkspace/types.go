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

// Client defines the Google Workspace operations needed by the collector.
type Client interface {
	GetCustomer(ctx context.Context, customerKey string) (Customer, error)
	GetCustomerUsageReport(ctx context.Context, customerID, date string) (CustomerUsageReport, error)
	ListUsers(ctx context.Context, customerKey string, callback func([]User) error) error
}
