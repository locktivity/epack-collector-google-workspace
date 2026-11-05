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
