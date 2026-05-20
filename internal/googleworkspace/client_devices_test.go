package googleworkspace

import "testing"

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
