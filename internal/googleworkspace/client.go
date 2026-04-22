package googleworkspace

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const maxUsersPerPage = 500
const maxActivitiesPerPage = 1000
const maxAccessPoliciesPerPage = 100
const maxAccessLevelsPerPage = 100

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
	directory     *admin.Service
	reports       *reports.Service
	auditReports  *reports.Service
	accessContext *accesscontextmanager.Service
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

	auditJWTConfig, err := google.JWTConfigFromJSON(
		creds,
		reports.AdminReportsAuditReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("creating audit JWT config: %w", err)
	}
	auditJWTConfig.Subject = adminEmail

	auditReportsService, err := reports.NewService(ctx, option.WithHTTPClient(auditJWTConfig.Client(ctx)))
	if err != nil {
		return nil, fmt.Errorf("creating audit reports service: %w", err)
	}

	accessContextJWTConfig, err := google.JWTConfigFromJSON(
		creds,
		accesscontextmanager.CloudPlatformScope,
	)
	if err != nil {
		return nil, fmt.Errorf("creating access context manager JWT config: %w", err)
	}

	accessContextService, err := accesscontextmanager.NewService(ctx, option.WithHTTPClient(accessContextJWTConfig.Client(ctx)))
	if err != nil {
		return nil, fmt.Errorf("creating access context manager service: %w", err)
	}

	return &APIClient{
		directory:     dirService,
		reports:       reportsService,
		auditReports:  auditReportsService,
		accessContext: accessContextService,
	}, nil
}

// NewClientWithServices creates a client backed by existing services (for testing).
func NewClientWithServices(directory *admin.Service, reportsService *reports.Service, accessContextService *accesscontextmanager.Service) *APIClient {
	return &APIClient{
		directory:     directory,
		reports:       reportsService,
		auditReports:  reportsService,
		accessContext: accessContextService,
	}
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

// ListContextAwareAccessEvents lists Context-Aware Access deny events since the
// provided start time. This is used to detect deny events that explicitly cite
// device-state conditions.
func (c *APIClient) ListContextAwareAccessEvents(ctx context.Context, customerID string, startTime time.Time, callback func([]ContextAwareAccessEvent) error) error {
	call := c.auditReports.Activities.List("all", "context_aware_access").
		CustomerId(customerID).
		EventName("ACCESS_DENY_EVENT").
		StartTime(startTime.UTC().Format(time.RFC3339)).
		MaxResults(maxActivitiesPerPage).
		Fields(
			googleapi.Field("nextPageToken,items(actor/email,id/time,events(name,parameters(name,value,multiValue,intValue,boolValue)))"),
		)

	return call.Pages(ctx, func(resp *reports.Activities) error {
		events := make([]ContextAwareAccessEvent, 0, len(resp.Items))
		for _, activity := range resp.Items {
			events = append(events, mapContextAwareAccessEvents(activity)...)
		}
		if len(events) == 0 {
			return nil
		}
		return callback(events)
	})
}

// ListAccessPolicies lists Access Context Manager policies under a GCP
// organization for optional device-access config enrichment.
func (c *APIClient) ListAccessPolicies(ctx context.Context, parent string, callback func([]AccessPolicy) error) error {
	call := c.accessContext.AccessPolicies.List().
		Parent(parent).
		PageSize(maxAccessPoliciesPerPage).
		Fields(googleapi.Field("nextPageToken,accessPolicies(name,parent,title)"))

	return call.Pages(ctx, func(resp *accesscontextmanager.ListAccessPoliciesResponse) error {
		policies := make([]AccessPolicy, 0, len(resp.AccessPolicies))
		for _, policy := range resp.AccessPolicies {
			if policy == nil {
				continue
			}
			policies = append(policies, AccessPolicy{
				Name:   policy.Name,
				Parent: policy.Parent,
				Title:  policy.Title,
			})
		}
		if len(policies) == 0 {
			return nil
		}
		return callback(policies)
	})
}

// ListAccessLevels lists Access Context Manager access levels for a policy.
func (c *APIClient) ListAccessLevels(ctx context.Context, policyName string, callback func([]AccessLevel) error) error {
	call := c.accessContext.AccessPolicies.AccessLevels.List(policyName).
		PageSize(maxAccessLevelsPerPage).
		Fields(googleapi.Field("nextPageToken,accessLevels(name,title,basic(conditions(devicePolicy(allowedDeviceManagementLevels,allowedEncryptionStatuses,osConstraints,requireAdminApproval,requireCorpOwned,requireScreenlock))),custom)"))

	return call.Pages(ctx, func(resp *accesscontextmanager.ListAccessLevelsResponse) error {
		levels := make([]AccessLevel, 0, len(resp.AccessLevels))
		for _, level := range resp.AccessLevels {
			if level == nil {
				continue
			}
			levels = append(levels, mapAccessLevel(level))
		}
		if len(levels) == 0 {
			return nil
		}
		return callback(levels)
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

func mapContextAwareAccessEvents(activity *reports.Activity) []ContextAwareAccessEvent {
	if activity == nil {
		return nil
	}

	var occurredAt time.Time
	if activity.Id != nil {
		occurredAt = parseActivityTime(activity.Id.Time)
	}

	userEmail := ""
	if activity.Actor != nil {
		userEmail = activity.Actor.Email
	}

	events := make([]ContextAwareAccessEvent, 0, len(activity.Events))
	for _, event := range activity.Events {
		if event == nil || event.Name != "ACCESS_DENY_EVENT" {
			continue
		}

		mapped := ContextAwareAccessEvent{
			OccurredAt: occurredAt,
			UserEmail:  userEmail,
		}

		for _, parameter := range event.Parameters {
			if parameter == nil {
				continue
			}
			value := parameterStringValue(parameter)
			switch parameter.Name {
			case "BLOCKED_API_ACCESS":
				mapped.BlockedAPIAccess = value
			case "CAA_ACCESS_LEVEL_APPLIED":
				mapped.AccessLevelApplied = value
			case "CAA_ACCESS_LEVEL_SATISFIED":
				mapped.AccessLevelSatisfied = value
			case "CAA_ACCESS_LEVEL_UNSATISFIED":
				mapped.AccessLevelUnsatisfied = value
			case "CAA_APPLICATION":
				mapped.Application = value
			case "CAA_DEVICE_ID":
				mapped.DeviceID = value
			case "CAA_DEVICE_STATE":
				mapped.DeviceState = value
			}
		}

		events = append(events, mapped)
	}

	return events
}

func mapAccessLevel(level *accesscontextmanager.AccessLevel) AccessLevel {
	mapped := AccessLevel{
		Name:   level.Name,
		Title:  level.Title,
		Custom: level.Custom != nil,
	}

	if level.Basic == nil {
		return mapped
	}

	deviceManagementLevels := map[string]struct{}{}
	encryptionStatuses := map[string]struct{}{}

	for _, condition := range level.Basic.Conditions {
		if condition == nil || condition.DevicePolicy == nil {
			continue
		}

		mapped.HasDevicePolicy = true
		if condition.DevicePolicy.RequireScreenlock {
			mapped.RequiresScreenlock = true
		}
		if condition.DevicePolicy.RequireAdminApproval {
			mapped.RequiresAdminApproval = true
		}
		if condition.DevicePolicy.RequireCorpOwned {
			mapped.RequiresCorpOwned = true
		}
		mapped.OSConstraintCount += len(condition.DevicePolicy.OsConstraints)
		for _, level := range condition.DevicePolicy.AllowedDeviceManagementLevels {
			if level == "" {
				continue
			}
			deviceManagementLevels[level] = struct{}{}
		}
		for _, status := range condition.DevicePolicy.AllowedEncryptionStatuses {
			if status == "" {
				continue
			}
			encryptionStatuses[status] = struct{}{}
		}
	}

	mapped.AllowedDeviceManagementLevels = sortedStringSet(deviceManagementLevels)
	mapped.AllowedEncryptionStatuses = sortedStringSet(encryptionStatuses)
	return mapped
}

func parameterStringValue(parameter *reports.ActivityEventsParameters) string {
	if parameter == nil {
		return ""
	}
	if parameter.Value != "" {
		return parameter.Value
	}
	if len(parameter.MultiValue) > 0 {
		return strings.Join(parameter.MultiValue, ",")
	}
	if parameter.IntValue != 0 {
		return strconv.FormatInt(parameter.IntValue, 10)
	}
	if parameter.BoolValue {
		return "true"
	}
	return ""
}

func sortedStringSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
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

func parseActivityTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}

	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(seconds, 0).UTC()
}
