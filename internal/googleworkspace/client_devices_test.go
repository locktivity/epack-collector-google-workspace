package googleworkspace

import (
	"context"
	"net/http"
	"testing"
)

func TestMobileOS(t *testing.T) {
	tests := []struct {
		osStr, deviceType, want string
	}{
		{"iOS 17.1.2", "IOS_SYNC", "IOS"},
		{"Android 14", "ANDROID", "ANDROID"},
		{"", "IOS_SYNC", "IOS"},       // no OS string: strip the _SYNC management suffix
		{"", "GOOGLE_SYNC", "GOOGLE"}, // ActiveSync device, OS unknown
		{"Windows 11", "WINDOWS_SYNC", "WINDOWS"},
		{"macOS 14", "MAC_SYNC", "MAC_OS"},
	}
	for _, tt := range tests {
		if got := mobileOS(tt.osStr, tt.deviceType); got != tt.want {
			t.Errorf("mobileOS(%q, %q) = %q, want %q", tt.osStr, tt.deviceType, got, tt.want)
		}
	}
}

// annotatedUser is a note an admin writes about the device's user.
func TestListChromeOSDevicesKeepsTheOwnerOnlyWhenItIsAnEmail(t *testing.T) {
	tests := []struct{ annotatedUser, want string }{
		{"eve@example.com", "eve@example.com"},
		{"Front desk kiosk", ""},
		{"Eve <eve@example.com>", ""},
		{"", ""},
	}
	for _, tt := range tests {
		client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"kind":"admin#directory#chromeosdevices","chromeosdevices":[{"osVersion":"120.0","model":"Chromebook","annotatedUser":"` + tt.annotatedUser + `","status":"ACTIVE","lastSync":"2026-04-06T10:00:00.000Z"}]}`))
		})
		var got []Device
		err := client.ListChromeOSDevices(context.Background(), "C123", func(batch []Device) error {
			got = append(got, batch...)
			return nil
		})
		if err != nil {
			t.Fatalf("ListChromeOSDevices() error = %v", err)
		}
		if len(got) != 1 || got[0].OwnerEmail != tt.want {
			t.Errorf("annotatedUser %q gave devices %+v, want one with owner %q", tt.annotatedUser, got, tt.want)
		}
	}
}

// A mobile device with no compromise status has no compliance verdict.
func TestListMobileDevicesLeavesComplianceUnknownWithoutACompromiseStatus(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"admin#directory#mobiledevices","mobiledevices":[
			{"type":"ANDROID","os":"Android 14","deviceCompromisedStatus":"No compromise detected"},
			{"type":"ANDROID","os":"Android 13","deviceCompromisedStatus":"Compromise detected"},
			{"type":"IOS_SYNC","os":"iOS 17.1"}
		]}`))
	})
	var got []Device
	err := client.ListMobileDevices(context.Background(), "C123", func(batch []Device) error {
		got = append(got, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListMobileDevices() error = %v", err)
	}
	if len(got) != 3 || got[0].Compliant == nil || !*got[0].Compliant || got[1].Compliant == nil || *got[1].Compliant || got[2].Compliant != nil {
		t.Fatalf("devices = %+v, want compliant, not compliant, and unknown", got)
	}
}

// A user's own role assignments include those of the groups they are in,
// which Google lists only when asked about one user.
func TestListUserRoleAssignmentsAsksForGroupRoles(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("userKey") != "u2" || q.Get("includeIndirectRoleAssignments") != "true" {
			t.Errorf("query = %s, want userKey u2 and includeIndirectRoleAssignments true", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"kind":"admin#directory#roleAssignments","items":[{"assignedTo":"g1","roleId":"2","scopeType":"CUSTOMER"}]}`))
	})
	var got []RoleAssignment
	err := client.ListUserRoleAssignments(context.Background(), "C123", "u2", func(batch []RoleAssignment) error {
		got = append(got, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListUserRoleAssignments() error = %v", err)
	}
	if len(got) != 1 || got[0].RoleID != "2" {
		t.Fatalf("assignments = %+v, want the group's role 2", got)
	}
}
