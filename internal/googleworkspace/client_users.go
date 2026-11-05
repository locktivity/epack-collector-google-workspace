package googleworkspace

import (
	"context"
	"fmt"
	"strings"
	"time"

	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/googleapi"
)

// reportParameterNames lists the accounts parameters requested.
var reportParameterNames = []string{
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
}

// reportParameters is the comma-separated list of accounts parameters to request.
var reportParameters = strings.Join(reportParameterNames, ",")

// GetCustomer fetches tenant metadata for the configured customer.
func (c *APIClient) GetCustomer(ctx context.Context, customerKey string) (Customer, error) {
	if customerKey == "" {
		customerKey = DefaultCustomerKey
	}

	resp, err := c.dirCustomer.Customers.Get(customerKey).Context(named(ctx, OpCustomersGet)).Do()
	if err != nil {
		return Customer{}, fmt.Errorf("getting customer %s: %w", customerKey, apiError(OpCustomersGet, err))
	}
	if resp.Kind == "" {
		return Customer{}, invalidResponse("customer %s response has no kind", customerKey)
	}

	return Customer{
		ID:            resp.Id,
		PrimaryDomain: resp.CustomerDomain,
	}, nil
}

// GetCustomerUsageReport fetches the accounts usage report for the given date.
// A parameter the report leaves out is listed in Missing rather than read as 0.
func (c *APIClient) GetCustomerUsageReport(ctx context.Context, customerID, date string) (CustomerUsageReport, error) {
	call := c.reports.CustomerUsageReports.Get(date).Parameters(reportParameters)
	if reportsCustomer(customerID) {
		call = call.CustomerId(customerID)
	}
	resp, err := call.Context(named(ctx, OpUsageReportGet)).Do()
	if err != nil {
		return CustomerUsageReport{}, fmt.Errorf("getting customer usage report for %s: %w", date, apiError(OpUsageReportGet, err))
	}
	if resp.Kind == "" {
		return CustomerUsageReport{}, invalidResponse("customer usage report for %s has no kind", date)
	}

	report := CustomerUsageReport{Date: date}

	for _, w := range resp.Warnings {
		report.Warnings = append(report.Warnings, ReportWarning{
			Code:    w.Code,
			Message: w.Message,
		})
	}

	var parameters []*reports.UsageReportParameters
	if len(resp.UsageReports) > 0 && resp.UsageReports[0] != nil {
		parameters = resp.UsageReports[0].Parameters
	}
	seen := map[string]bool{}
	for _, p := range parameters {
		if p == nil {
			continue
		}
		seen[p.Name] = true
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
	for _, name := range reportParameterNames {
		if !seen[name] {
			report.Missing = append(report.Missing, name)
		}
	}

	return report, nil
}

// reportsCustomer reports whether a customer ID goes in a Reports API request.
// The Reports API takes no my_customer alias, and leaving customerId out
// means the caller's own customer, which is what the alias means.
func reportsCustomer(customerID string) bool {
	return customerID != "" && customerID != DefaultCustomerKey
}

// ListUsers lists all users for the customer and maps them to the local user type.
func (c *APIClient) ListUsers(ctx context.Context, customerKey string, callback func([]User) error) error {
	if customerKey == "" {
		customerKey = DefaultCustomerKey
	}

	call := c.dirUsers.Users.List().
		Customer(customerKey).
		MaxResults(maxUsersPerPage).
		Projection("full").
		ViewType("admin_view").
		Fields(googleapi.Field("kind,nextPageToken,users(id,primaryEmail,suspended,archived,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,orgUnitPath,creationTime,agreedToTerms,ipWhitelisted,changePasswordAtNextLogin)"))

	err := call.Pages(named(ctx, OpUsersList), func(resp *admin.Users) error {
		if resp.Kind == "" {
			return invalidResponse("users page has no kind")
		}
		users := make([]User, 0, len(resp.Users))
		for _, user := range resp.Users {
			users = append(users, mapUser(user))
		}
		return callback(users)
	})
	return listError(OpUsersList, "listing users", err)
}

func mapUser(user *admin.User) User {
	mapped := User{
		ID:                        user.Id,
		PrimaryEmail:              user.PrimaryEmail,
		Suspended:                 user.Suspended,
		Archived:                  user.Archived,
		IsAdmin:                   user.IsAdmin,
		IsDelegatedAdmin:          user.IsDelegatedAdmin,
		IsEnrolledIn2Sv:           user.IsEnrolledIn2Sv,
		IsEnforcedIn2Sv:           user.IsEnforcedIn2Sv,
		OrgUnitPath:               user.OrgUnitPath,
		AgreedToTerms:             user.AgreedToTerms,
		IPWhitelisted:             user.IpWhitelisted,
		ChangePasswordAtNextLogin: user.ChangePasswordAtNextLogin,
	}

	if ts, err := time.Parse(time.RFC3339, user.CreationTime); err == nil {
		mapped.CreationTime = ts
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
