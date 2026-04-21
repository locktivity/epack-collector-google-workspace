package googleworkspace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const maxUsersPerPage = 500

// reportParameters is the comma-separated list of accounts parameters to request.
var reportParameters = strings.Join([]string{
	"accounts:num_users",
	"accounts:num_suspended_users",
	"accounts:num_archived_users",
	"accounts:num_7day_logins",
	"accounts:num_30day_logins",
	"accounts:num_users_2sv_enrolled",
	"accounts:num_users_2sv_enforced",
	"accounts:num_users_2sv_protected",
	"accounts:num_users_with_passkeys_enrolled",
	"accounts:num_security_keys",
	"accounts:num_users_password_strength_weak",
	"accounts:num_users_password_length_non_compliant",
	"accounts:num_authorized_apps",
	"accounts:num_locked_users",
}, ",")

// APIClient wraps the Google Admin SDK Directory and Reports APIs.
type APIClient struct {
	directory *admin.Service
	reports   *reports.Service
}

// NewClient authenticates with a service account and returns a client.
func NewClient(ctx context.Context, adminEmail, credentialsJSON string) (*APIClient, error) {
	creds := []byte(credentialsJSON)
	jwtConfig, err := google.JWTConfigFromJSON(
		creds,
		admin.AdminDirectoryCustomerReadonlyScope,
		admin.AdminDirectoryUserReadonlyScope,
		reports.AdminReportsUsageReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("creating JWT config: %w", err)
	}
	jwtConfig.Subject = adminEmail

	httpClient := jwtConfig.Client(ctx)

	dirService, err := admin.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating directory service: %w", err)
	}

	reportsService, err := reports.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating reports service: %w", err)
	}

	return &APIClient{directory: dirService, reports: reportsService}, nil
}

// NewClientWithServices creates a client backed by existing services (for testing).
func NewClientWithServices(directory *admin.Service, reportsService *reports.Service) *APIClient {
	return &APIClient{directory: directory, reports: reportsService}
}

// GetCustomer fetches tenant metadata for the configured customer.
func (c *APIClient) GetCustomer(ctx context.Context, customerKey string) (Customer, error) {
	if customerKey == "" {
		customerKey = DefaultCustomerKey
	}

	resp, err := c.directory.Customers.Get(customerKey).Context(ctx).Do()
	if err != nil {
		return Customer{}, fmt.Errorf("getting customer %s: %w", customerKey, err)
	}

	return Customer{
		ID:            resp.Id,
		PrimaryDomain: resp.CustomerDomain,
	}, nil
}

// GetCustomerUsageReport fetches the accounts usage report for the given date.
func (c *APIClient) GetCustomerUsageReport(ctx context.Context, customerID, date string) (CustomerUsageReport, error) {
	resp, err := c.reports.CustomerUsageReports.Get(date).
		CustomerId(customerID).
		Parameters(reportParameters).
		Context(ctx).
		Do()
	if err != nil {
		return CustomerUsageReport{}, fmt.Errorf("getting customer usage report for %s: %w", date, err)
	}

	report := CustomerUsageReport{Date: date}

	for _, w := range resp.Warnings {
		report.Warnings = append(report.Warnings, ReportWarning{
			Code:    w.Code,
			Message: w.Message,
		})
	}

	if len(resp.UsageReports) == 0 {
		return report, nil
	}

	for _, p := range resp.UsageReports[0].Parameters {
		switch p.Name {
		case "accounts:num_users":
			report.NumUsers = p.IntValue
		case "accounts:num_suspended_users":
			report.NumSuspendedUsers = p.IntValue
		case "accounts:num_archived_users":
			report.NumArchivedUsers = p.IntValue
		case "accounts:num_7day_logins":
			report.Num7DayLogins = p.IntValue
		case "accounts:num_30day_logins":
			report.Num30DayLogins = p.IntValue
		case "accounts:num_users_2sv_enrolled":
			report.NumUsers2SVEnrolled = p.IntValue
		case "accounts:num_users_2sv_enforced":
			report.NumUsers2SVEnforced = p.IntValue
		case "accounts:num_users_2sv_protected":
			report.NumUsers2SVProtected = p.IntValue
		case "accounts:num_users_with_passkeys_enrolled":
			report.NumUsersWithPasskeysEnrolled = p.IntValue
		case "accounts:num_security_keys":
			report.NumSecurityKeys = p.IntValue
		case "accounts:num_users_password_strength_weak":
			report.NumUsersPasswordStrengthWeak = p.IntValue
		case "accounts:num_users_password_length_non_compliant":
			report.NumUsersPasswordLengthNonCompliant = p.IntValue
		case "accounts:num_authorized_apps":
			report.NumAuthorizedApps = p.IntValue
		case "accounts:num_locked_users":
			report.NumLockedUsers = p.IntValue
		}
	}

	return report, nil
}

// ListUsers lists all users for the customer and maps them to the local user type.
func (c *APIClient) ListUsers(ctx context.Context, customerKey string, callback func([]User) error) error {
	if customerKey == "" {
		customerKey = DefaultCustomerKey
	}

	call := c.directory.Users.List().
		Customer(customerKey).
		MaxResults(maxUsersPerPage).
		Projection("full").
		ViewType("admin_view").
		Fields(googleapi.Field("nextPageToken,users(primaryEmail,suspended,archived,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime)"))

	return call.Pages(ctx, func(resp *admin.Users) error {
		users := make([]User, 0, len(resp.Users))
		for _, user := range resp.Users {
			users = append(users, mapUser(user))
		}
		return callback(users)
	})
}

func mapUser(user *admin.User) User {
	mapped := User{
		PrimaryEmail:     user.PrimaryEmail,
		Suspended:        user.Suspended,
		Archived:         user.Archived,
		IsAdmin:          user.IsAdmin,
		IsDelegatedAdmin: user.IsDelegatedAdmin,
		IsEnrolledIn2Sv:  user.IsEnrolledIn2Sv,
		IsEnforcedIn2Sv:  user.IsEnforcedIn2Sv,
	}

	if ts, ok := parseLastLogin(user.LastLoginTime); ok {
		mapped.LastLoginTime = ts
	} else {
		mapped.LastLoginMissing = true
	}

	return mapped
}

func parseLastLogin(raw string) (time.Time, bool) {
	switch raw {
	case "", "1970-01-01T00:00:00.000Z":
		return time.Time{}, false
	}

	ts, err := time.Parse(time.RFC3339, raw)
	if err == nil {
		return ts, true
	}

	ts, err = time.Parse("2006-01-02T15:04:05.000Z", raw)
	if err == nil {
		return ts, true
	}

	return time.Time{}, false
}
