package googleworkspace

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/option"
)

func TestAPIClientGetCustomer(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/admin/directory/v1/customers/my_customer"
		if r.URL.Path != wantPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, wantPath)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             "C123",
			"customerDomain": "example.com",
		})
	})

	customer, err := client.GetCustomer(context.Background(), "")
	if err != nil {
		t.Fatalf("GetCustomer() error = %v", err)
	}

	if customer.ID != "C123" {
		t.Fatalf("customer.ID = %q, want C123", customer.ID)
	}
	if customer.PrimaryDomain != "example.com" {
		t.Fatalf("customer.PrimaryDomain = %q, want example.com", customer.PrimaryDomain)
	}
}

func TestAPIClientGetCustomerUsageReport(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/admin/reports/v1/usage/dates/2026-04-07"
		if r.URL.Path != wantPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, wantPath)
		}
		if got := r.URL.Query().Get("customerId"); got != "C123" {
			t.Fatalf("customerId = %q, want C123", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"usageReports": []map[string]any{
				{
					"date": "2026-04-07",
					"parameters": []map[string]any{
						{"name": "accounts:num_users", "intValue": "100"},
						{"name": "accounts:num_suspended_users", "intValue": "5"},
						{"name": "accounts:num_archived_users", "intValue": "3"},
						{"name": "accounts:num_7day_logins", "intValue": "80"},
						{"name": "accounts:num_30day_logins", "intValue": "90"},
						{"name": "accounts:num_users_2sv_enrolled", "intValue": "75"},
						{"name": "accounts:num_users_2sv_enforced", "intValue": "60"},
						{"name": "accounts:num_users_2sv_protected", "intValue": "70"},
						{"name": "accounts:num_users_with_passkeys_enrolled", "intValue": "10"},
						{"name": "accounts:num_security_keys", "intValue": "25"},
						{"name": "accounts:num_users_password_strength_weak", "intValue": "8"},
						{"name": "accounts:num_users_password_length_non_compliant", "intValue": "4"},
						{"name": "accounts:num_authorized_apps", "intValue": "42"},
						{"name": "accounts:num_locked_users", "intValue": "3"},
					},
				},
			},
		})
	})

	report, err := client.GetCustomerUsageReport(context.Background(), "C123", "2026-04-07")
	if err != nil {
		t.Fatalf("GetCustomerUsageReport() error = %v", err)
	}

	if report.Date != "2026-04-07" {
		t.Fatalf("Date = %q, want 2026-04-07", report.Date)
	}
	if report.NumUsers != 100 {
		t.Fatalf("NumUsers = %d, want 100", report.NumUsers)
	}
	if report.NumSuspendedUsers != 5 {
		t.Fatalf("NumSuspendedUsers = %d, want 5", report.NumSuspendedUsers)
	}
	if report.NumArchivedUsers != 3 {
		t.Fatalf("NumArchivedUsers = %d, want 3", report.NumArchivedUsers)
	}
	if report.Num7DayLogins != 80 {
		t.Fatalf("Num7DayLogins = %d, want 80", report.Num7DayLogins)
	}
	if report.Num30DayLogins != 90 {
		t.Fatalf("Num30DayLogins = %d, want 90", report.Num30DayLogins)
	}
	if report.NumUsers2SVEnrolled != 75 {
		t.Fatalf("NumUsers2SVEnrolled = %d, want 75", report.NumUsers2SVEnrolled)
	}
	if report.NumUsers2SVEnforced != 60 {
		t.Fatalf("NumUsers2SVEnforced = %d, want 60", report.NumUsers2SVEnforced)
	}
	if report.NumUsers2SVProtected != 70 {
		t.Fatalf("NumUsers2SVProtected = %d, want 70", report.NumUsers2SVProtected)
	}
	if report.NumUsersWithPasskeysEnrolled != 10 {
		t.Fatalf("NumUsersWithPasskeysEnrolled = %d, want 10", report.NumUsersWithPasskeysEnrolled)
	}
	if report.NumSecurityKeys != 25 {
		t.Fatalf("NumSecurityKeys = %d, want 25", report.NumSecurityKeys)
	}
	if report.NumUsersPasswordStrengthWeak != 8 {
		t.Fatalf("NumUsersPasswordStrengthWeak = %d, want 8", report.NumUsersPasswordStrengthWeak)
	}
	if report.NumUsersPasswordLengthNonCompliant != 4 {
		t.Fatalf("NumUsersPasswordLengthNonCompliant = %d, want 4", report.NumUsersPasswordLengthNonCompliant)
	}
	if report.NumAuthorizedApps != 42 {
		t.Fatalf("NumAuthorizedApps = %d, want 42", report.NumAuthorizedApps)
	}
	if report.NumLockedUsers != 3 {
		t.Fatalf("NumLockedUsers = %d, want 3", report.NumLockedUsers)
	}
}

func TestAPIClientGetCustomerUsageReportEmpty(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"usageReports": []map[string]any{},
		})
	})

	report, err := client.GetCustomerUsageReport(context.Background(), "C123", "2026-04-07")
	if err != nil {
		t.Fatalf("GetCustomerUsageReport() error = %v", err)
	}
	if report.NumUsers != 0 {
		t.Fatalf("NumUsers = %d, want 0", report.NumUsers)
	}
}

func TestAPIClientListUsersPaginatesAndMaps(t *testing.T) {
	requests := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/directory/v1/users" {
			return // let reports requests pass through
		}
		if got := r.URL.Query().Get("customer"); got != DefaultCustomerKey {
			t.Fatalf("customer query = %q, want %q", got, DefaultCustomerKey)
		}
		if got := r.URL.Query().Get("projection"); got != "full" {
			t.Fatalf("projection = %q, want full", got)
		}
		if got := r.URL.Query().Get("maxResults"); got != "500" {
			t.Fatalf("maxResults = %q, want 500", got)
		}

		requests++
		switch requests {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{
						"primaryEmail":    "a@example.com",
						"isEnrolledIn2Sv": true,
						"isEnforcedIn2Sv": true,
						"isAdmin":         true,
						"lastLoginTime":   "2026-04-08T12:00:00Z",
					},
				},
				"nextPageToken": "page-2",
			})
		case 2:
			if got := r.URL.Query().Get("pageToken"); got != "page-2" {
				t.Fatalf("pageToken = %q, want page-2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{
						"primaryEmail":     "b@example.com",
						"suspended":        true,
						"isDelegatedAdmin": true,
						"lastLoginTime":    "1970-01-01T00:00:00.000Z",
					},
					{
						"primaryEmail":  "c@example.com",
						"archived":      true,
						"lastLoginTime": "not-a-time",
					},
				},
			})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	})

	var got []User
	err := client.ListUsers(context.Background(), "", func(users []User) error {
		got = append(got, users...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len(users) = %d, want 3", len(got))
	}
	if got[0].PrimaryEmail != "a@example.com" || !got[0].IsEnrolledIn2Sv || !got[0].IsEnforcedIn2Sv || !got[0].IsAdmin {
		t.Fatalf("first user = %+v, want enrolled+enforced admin", got[0])
	}
	if got[0].LastLoginMissing {
		t.Fatal("first user LastLoginMissing = true, want false")
	}
	if got[0].LastLoginTime.Format(time.RFC3339) != "2026-04-08T12:00:00Z" {
		t.Fatalf("first user LastLoginTime = %q, want 2026-04-08T12:00:00Z", got[0].LastLoginTime.Format(time.RFC3339))
	}
	if !got[1].Suspended || !got[1].IsDelegatedAdmin {
		t.Fatalf("second user = %+v, want suspended delegated admin", got[1])
	}
	if !got[1].LastLoginMissing {
		t.Fatal("second user LastLoginMissing = false, want true (epoch)")
	}
	if !got[2].Archived {
		t.Fatalf("third user = %+v, want archived user", got[2])
	}
	if !got[2].LastLoginMissing {
		t.Fatal("third user LastLoginMissing = false, want true (unparseable)")
	}
}

func TestAPIClientListContextAwareAccessEventsPaginatesAndMaps(t *testing.T) {
	firstEventTime := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	secondEventTime := time.Date(2026, 4, 7, 18, 30, 0, 0, time.UTC)

	requests := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/reports/v1/activity/users/all/applications/context_aware_access" {
			return
		}
		if got := r.URL.Query().Get("customerId"); got != "C123" {
			t.Fatalf("customerId = %q, want C123", got)
		}
		if got := r.URL.Query().Get("eventName"); got != "ACCESS_DENY_EVENT" {
			t.Fatalf("eventName = %q, want ACCESS_DENY_EVENT", got)
		}
		if got := r.URL.Query().Get("startTime"); got != "2026-04-01T00:00:00Z" {
			t.Fatalf("startTime = %q, want 2026-04-01T00:00:00Z", got)
		}
		if got := r.URL.Query().Get("maxResults"); got != "1000" {
			t.Fatalf("maxResults = %q, want 1000", got)
		}

		requests++
		switch requests {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"actor": map[string]any{
							"email": "admin@example.com",
						},
						"id": map[string]any{
							"time": strconv.FormatInt(firstEventTime.Unix(), 10),
						},
						"events": []map[string]any{
							{
								"name": "ACCESS_DENY_EVENT",
								"parameters": []map[string]any{
									{"name": "CAA_APPLICATION", "value": "Gmail"},
									{"name": "CAA_DEVICE_STATE", "value": "Unmanaged"},
									{"name": "CAA_ACCESS_LEVEL_UNSATISFIED", "value": "Corp managed device"},
								},
							},
							{
								"name": "IGNORED_EVENT",
							},
						},
					},
				},
				"nextPageToken": "page-2",
			})
		case 2:
			if got := r.URL.Query().Get("pageToken"); got != "page-2" {
				t.Fatalf("pageToken = %q, want page-2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"actor": map[string]any{
							"email": "user@example.com",
						},
						"id": map[string]any{
							"time": strconv.FormatInt(secondEventTime.Unix(), 10),
						},
						"events": []map[string]any{
							{
								"name": "ACCESS_DENY_EVENT",
								"parameters": []map[string]any{
									{"name": "BLOCKED_API_ACCESS", "value": "Drive API"},
									{"name": "CAA_APPLICATION", "value": "Drive"},
								},
							},
						},
					},
				},
			})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	})

	var got []ContextAwareAccessEvent
	err := client.ListContextAwareAccessEvents(
		context.Background(),
		"C123",
		time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		func(events []ContextAwareAccessEvent) error {
			got = append(got, events...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ListContextAwareAccessEvents() error = %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(got))
	}
	if got[0].UserEmail != "admin@example.com" {
		t.Fatalf("first event UserEmail = %q, want admin@example.com", got[0].UserEmail)
	}
	if got[0].Application != "Gmail" {
		t.Fatalf("first event Application = %q, want Gmail", got[0].Application)
	}
	if got[0].DeviceState != "Unmanaged" {
		t.Fatalf("first event DeviceState = %q, want Unmanaged", got[0].DeviceState)
	}
	if got[0].AccessLevelUnsatisfied != "Corp managed device" {
		t.Fatalf("first event AccessLevelUnsatisfied = %q, want Corp managed device", got[0].AccessLevelUnsatisfied)
	}
	if !got[0].OccurredAt.Equal(firstEventTime) {
		t.Fatalf("first event OccurredAt = %s, want %s", got[0].OccurredAt, firstEventTime)
	}
	if got[1].BlockedAPIAccess != "Drive API" {
		t.Fatalf("second event BlockedAPIAccess = %q, want Drive API", got[1].BlockedAPIAccess)
	}
	if got[1].Application != "Drive" {
		t.Fatalf("second event Application = %q, want Drive", got[1].Application)
	}
	if got[1].DeviceState != "" {
		t.Fatalf("second event DeviceState = %q, want empty", got[1].DeviceState)
	}
	if !got[1].OccurredAt.Equal(secondEventTime) {
		t.Fatalf("second event OccurredAt = %s, want %s", got[1].OccurredAt, secondEventTime)
	}
}

func TestAPIClientListAccessPoliciesPaginatesAndMaps(t *testing.T) {
	requests := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accessPolicies" {
			return
		}
		if got := r.URL.Query().Get("parent"); got != "organizations/123456" {
			t.Fatalf("parent = %q, want organizations/123456", got)
		}

		requests++
		switch requests {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessPolicies": []map[string]any{
					{
						"name":   "accessPolicies/111",
						"parent": "organizations/123456",
						"title":  "Corp policy",
					},
				},
				"nextPageToken": "page-2",
			})
		case 2:
			if got := r.URL.Query().Get("pageToken"); got != "page-2" {
				t.Fatalf("pageToken = %q, want page-2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessPolicies": []map[string]any{
					{
						"name":   "accessPolicies/222",
						"parent": "organizations/123456",
						"title":  "Scoped policy",
					},
				},
			})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	})

	var got []AccessPolicy
	err := client.ListAccessPolicies(context.Background(), "organizations/123456", func(policies []AccessPolicy) error {
		got = append(got, policies...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListAccessPolicies() error = %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(policies) = %d, want 2", len(got))
	}
	if got[0].Name != "accessPolicies/111" || got[0].Title != "Corp policy" {
		t.Fatalf("first policy = %+v, want accessPolicies/111 / Corp policy", got[0])
	}
	if got[1].Name != "accessPolicies/222" || got[1].Parent != "organizations/123456" {
		t.Fatalf("second policy = %+v, want accessPolicies/222 under organizations/123456", got[1])
	}
}

func TestAPIClientListAccessLevelsPaginatesAndMaps(t *testing.T) {
	requests := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accessPolicies/111/accessLevels" {
			return
		}

		requests++
		switch requests {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessLevels": []map[string]any{
					{
						"name":  "accessPolicies/111/accessLevels/device_trust",
						"title": "Device Trust",
						"basic": map[string]any{
							"conditions": []map[string]any{
								{
									"devicePolicy": map[string]any{
										"allowedDeviceManagementLevels": []string{"BASIC", "COMPLETE"},
										"allowedEncryptionStatuses":     []string{"ENCRYPTED"},
										"requireScreenlock":             true,
										"requireCorpOwned":              true,
										"osConstraints": []map[string]any{
											{"osType": "DESKTOP_MAC"},
										},
									},
								},
							},
						},
					},
				},
				"nextPageToken": "page-2",
			})
		case 2:
			if got := r.URL.Query().Get("pageToken"); got != "page-2" {
				t.Fatalf("pageToken = %q, want page-2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessLevels": []map[string]any{
					{
						"name":   "accessPolicies/111/accessLevels/custom_expr",
						"title":  "Custom Expr",
						"custom": map[string]any{"expr": map[string]any{"expression": "true"}},
					},
				},
			})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	})

	var got []AccessLevel
	err := client.ListAccessLevels(context.Background(), "accessPolicies/111", func(levels []AccessLevel) error {
		got = append(got, levels...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListAccessLevels() error = %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(levels) = %d, want 2", len(got))
	}
	if got[0].Title != "Device Trust" || !got[0].HasDevicePolicy {
		t.Fatalf("first level = %+v, want basic device policy level", got[0])
	}
	if !got[0].RequiresScreenlock || !got[0].RequiresCorpOwned {
		t.Fatalf("first level policy flags = %+v, want screenlock+corp-owned", got[0])
	}
	if got[0].OSConstraintCount != 1 {
		t.Fatalf("first level OSConstraintCount = %d, want 1", got[0].OSConstraintCount)
	}
	if len(got[0].AllowedDeviceManagementLevels) != 2 {
		t.Fatalf("first level AllowedDeviceManagementLevels = %#v, want 2 values", got[0].AllowedDeviceManagementLevels)
	}
	if !got[1].Custom {
		t.Fatalf("second level = %+v, want custom level", got[1])
	}
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *APIClient {
	t.Helper()

	httpClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			recorder := &responseRecorder{
				header: make(http.Header),
			}
			handler(recorder, r)
			if recorder.statusCode == 0 {
				recorder.statusCode = http.StatusOK
			}
			return &http.Response{
				StatusCode: recorder.statusCode,
				Header:     recorder.header,
				Body:       io.NopCloser(strings.NewReader(recorder.body.String())),
				Request:    r,
			}, nil
		}),
	}

	dirService, err := admin.NewService(
		context.Background(),
		option.WithHTTPClient(httpClient),
		option.WithEndpoint("https://unit.test/"),
	)
	if err != nil {
		t.Fatalf("admin.NewService() error = %v", err)
	}

	reportsService, err := reports.NewService(
		context.Background(),
		option.WithHTTPClient(httpClient),
		option.WithEndpoint("https://unit.test/"),
	)
	if err != nil {
		t.Fatalf("reports.NewService() error = %v", err)
	}

	accessContextService, err := accesscontextmanager.NewService(
		context.Background(),
		option.WithHTTPClient(httpClient),
		option.WithEndpoint("https://unit.test/"),
	)
	if err != nil {
		t.Fatalf("accesscontextmanager.NewService() error = %v", err)
	}

	return NewClientWithServices(dirService, reportsService, accessContextService)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type responseRecorder struct {
	header     http.Header
	body       strings.Builder
	statusCode int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}
