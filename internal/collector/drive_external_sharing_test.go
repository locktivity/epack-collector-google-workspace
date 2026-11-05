package collector

import (
	"context"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

var driveTestNow = time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

func collectDriveSharing(t *testing.T, level componentsdk.Level, events ...googleworkspace.AuditEvent) *DriveExternalSharing {
	t.Helper()
	client := &mockClient{
		customer:        googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport:     googleworkspace.CustomerUsageReport{NumUsers: 5},
		users:           []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: driveTestNow}},
		activitiesByApp: map[string][]googleworkspace.AuditEvent{"drive": events},
	}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return driveTestNow }}, client)
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error = %v", level, err)
	}
	if posture.DriveExternalSharing == nil {
		t.Fatalf("DriveExternalSharing is nil at %s", level)
	}
	return posture.DriveExternalSharing
}

func userAccessEvent(target, role string) googleworkspace.AuditEvent {
	return googleworkspace.AuditEvent{
		Time:            driveTestNow.AddDate(0, 0, -1),
		ActorEmail:      "u@example.com",
		Name:            driveEventChangeUserAccess,
		Parameters:      map[string]string{"target_user": target, "doc_id": "doc1"},
		MultiParameters: map[string][]string{"new_value": {role}},
	}
}

func visibilityEvent(visibility string) googleworkspace.AuditEvent {
	return googleworkspace.AuditEvent{
		Time:       driveTestNow.AddDate(0, 0, -1),
		ActorEmail: "u@example.com",
		Name:       driveEventChangeDocumentVisbility,
		Parameters: map[string]string{"visibility": visibility, "new_value": visibility, "doc_id": "doc2"},
	}
}

func TestScanDriveExternalSharingCountsOnlyPublicVisibilities(t *testing.T) {
	got := collectDriveSharing(t, componentsdk.LevelAudit,
		visibilityEvent("public_on_the_web"),
		visibilityEvent("people_with_link"),
		visibilityEvent("public_in_the_domain"),
		visibilityEvent("people_within_domain_with_link"),
		visibilityEvent("private"),
	)
	if got.PublicOnWebEvents != 2 {
		t.Fatalf("PublicOnWebEvents = %d, want 2 for public_on_the_web and people_with_link", got.PublicOnWebEvents)
	}
}

func TestScanDriveExternalSharingCountsSharesOutsideThePrimaryDomain(t *testing.T) {
	tests := []struct {
		name           string
		event          googleworkspace.AuditEvent
		wantExternal   int
		wantDomain     string
		wantTargetRole string
	}{
		{name: "an outside address", event: userAccessEvent("bob@vendor.com", "can_view"), wantExternal: 1, wantDomain: "vendor.com", wantTargetRole: "can_view"},
		{name: "an outside domain", event: userAccessEvent("partner.example", "can_view"), wantExternal: 1, wantDomain: "partner.example", wantTargetRole: "can_view"},
		{name: "access taken away", event: userAccessEvent("bob@vendor.com", "none")},
		{name: "an address in the primary domain", event: userAccessEvent("carol@example.com", "can_view")},
		{name: "the primary domain", event: userAccessEvent("example.com", "can_edit")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectDriveSharing(t, componentsdk.LevelInternal, tt.event)
			if got.ExternalShareEvents == nil || *got.ExternalShareEvents != tt.wantExternal {
				t.Fatalf("ExternalShareEvents = %v, want %d", got.ExternalShareEvents, tt.wantExternal)
			}
			if tt.wantExternal == 0 {
				if len(got.Events) != 0 {
					t.Fatalf("events = %+v, want none", got.Events)
				}
				return
			}
			if len(got.Events) != 1 || got.Events[0].RecipientDomain != tt.wantDomain || got.Events[0].TargetRole != tt.wantTargetRole {
				t.Fatalf("events = %+v, want one row to %s with role %s", got.Events, tt.wantDomain, tt.wantTargetRole)
			}
		})
	}
}

// On a visibility change, new_value holds the new link visibility.
func TestScanDriveExternalSharingLeavesTheRoleOffVisibilityRows(t *testing.T) {
	got := collectDriveSharing(t, componentsdk.LevelInternal, visibilityEvent("people_with_link"))
	if len(got.Events) != 1 || got.Events[0].TargetRole != "" {
		t.Fatalf("events = %+v, want one visibility row with no target role", got.Events)
	}
}
