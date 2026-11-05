package collector

import (
	"slices"
	"testing"
)

func adminActivityBody(names ...string) string {
	events := ""
	for i, name := range names {
		if i > 0 {
			events += ","
		}
		events += `{"name":"` + name + `"}`
	}
	return `{"kind":"admin#reports#activities","items":[{"actor":{"email":"admin@example.com"},"id":{"time":"2026-04-06T10:00:00.000Z","applicationName":"admin","uniqueQualifier":"1"},"events":[` + events + `]}]}`
}

// A request for one admin event gets back each activity that holds it, with
// all of the activity's events.
func TestScanAdminAuditLogCountsEachRequestedActionOnce(t *testing.T) {
	both := adminActivityBody("SUSPEND_USER", "GRANT_ADMIN_PRIVILEGE")
	tests := []struct {
		name       string
		activities map[string]string
		want       []string
	}{
		{
			name:       "an action that is not counted is left out",
			activities: map[string]string{"SUSPEND_USER": adminActivityBody("SUSPEND_USER", "MOVE_USER_TO_ORG_UNIT")},
			want:       []string{"SUSPEND_USER"},
		},
		{
			name:       "an activity with one action",
			activities: map[string]string{"SUSPEND_USER": adminActivityBody("SUSPEND_USER")},
			want:       []string{"SUSPEND_USER"},
		},
		{
			name:       "one activity with two counted actions, returned for both",
			activities: map[string]string{"SUSPEND_USER": both, "GRANT_ADMIN_PRIVILEGE": both},
			want:       []string{"GRANT_ADMIN_PRIVILEGE", "SUSPEND_USER"},
		},
		{
			name: "two activities with one counted action each",
			activities: map[string]string{
				"SUSPEND_USER":          adminActivityBody("SUSPEND_USER"),
				"GRANT_ADMIN_PRIVILEGE": adminActivityBody("GRANT_ADMIN_PRIVILEGE"),
			},
			want: []string{"GRANT_ADMIN_PRIVILEGE", "SUSPEND_USER"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := cleanTenant()
			tenant.activities = map[string]map[string]string{"admin": tt.activities}
			log := runKitTenant(t, tenant).AdminAuditLog
			if log == nil {
				t.Fatal("the run left out admin_audit_log")
			}

			if len(log.CountsByCategory) != 1 || log.CountsByCategory["USER_SETTINGS"] != len(tt.want) {
				t.Errorf("counts_by_category = %v, want only USER_SETTINGS:%d", log.CountsByCategory, len(tt.want))
			}
			var names []string
			for _, e := range log.Events {
				names = append(names, e.Name)
				if e.Category != "USER_SETTINGS" {
					t.Errorf("event %s has category %q, want USER_SETTINGS", e.Name, e.Category)
				}
			}
			slices.Sort(names)
			if !slices.Equal(names, tt.want) {
				t.Errorf("events = %v, want %v", names, tt.want)
			}
		})
	}
}
