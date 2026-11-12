package googleworkspace

import (
	"context"
	"net/mail"
	"strings"
	"time"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

// ListMobileDevices lists managed mobile devices. Serial numbers and IMEIs are
// deliberately excluded from the field mask and never mapped.
func (c *APIClient) ListMobileDevices(ctx context.Context, customerID string, callback func([]Device) error) error {
	call := c.dirMobile.Mobiledevices.List(customerID).
		MaxResults(maxDevicesPerPage).
		Projection("BASIC").
		Fields(googleapi.Field("kind,nextPageToken,mobiledevices(type,os,model,email,status,lastSync,encryptionStatus,deviceCompromisedStatus,devicePasswordStatus)"))

	err := call.Pages(named(ctx, OpMobileDevicesList), func(resp *admin.MobileDevices) error {
		if resp.Kind == "" {
			return invalidResponse("mobile devices page has no kind")
		}
		devices := make([]Device, 0, len(resp.Mobiledevices))
		for _, d := range resp.Mobiledevices {
			if d == nil {
				continue
			}
			device := Device{
				Platform:           "MOBILE",
				OS:                 mobileOS(d.Os, d.Type),
				OSVersion:          d.Os,
				Model:              d.Model,
				Status:             d.Status,
				Compliant:          compromiseVerdict(d.DeviceCompromisedStatus),
				Encrypted:          strings.EqualFold(d.EncryptionStatus, "encrypted"),
				ScreenLockEnforced: strings.EqualFold(d.DevicePasswordStatus, "on"),
			}
			if len(d.Email) > 0 {
				device.OwnerEmail = d.Email[0]
			}
			if ts, err := time.Parse(time.RFC3339, d.LastSync); err == nil {
				device.LastSync = ts
			} else {
				device.LastSyncMissing = true
			}
			devices = append(devices, device)
		}
		if len(devices) == 0 {
			return nil
		}
		return callback(devices)
	})
	return listError(OpMobileDevicesList, "listing mobile devices", err)
}

// compromiseVerdict is whether a mobile device with this compromise status
// counts as compliant, or nil when Google reported none for the device.
func compromiseVerdict(status string) *bool {
	if status == "" {
		return nil
	}
	compliant := strings.EqualFold(status, "No compromise detected")
	return &compliant
}

// mobileOS returns a normalized OS family for a mobile device. The directory
// API's device Type carries the management protocol (e.g. IOS_SYNC,
// GOOGLE_SYNC), not a clean OS name, so we prefer the OS string ("iOS 17.1",
// "Android 14") and fall back to the type with the "_SYNC" management suffix
// stripped.
func mobileOS(osStr, deviceType string) string {
	switch o := strings.ToLower(osStr); {
	case strings.Contains(o, "ios"):
		return "IOS"
	case strings.Contains(o, "android"):
		return "ANDROID"
	case strings.Contains(o, "windows"):
		return "WINDOWS"
	case strings.Contains(o, "mac"):
		return "MAC_OS"
	}
	return strings.TrimSuffix(deviceType, "_SYNC")
}

// ListChromeOSDevices lists managed Chrome OS devices. Serial numbers are
// deliberately excluded from the field mask and never mapped.
func (c *APIClient) ListChromeOSDevices(ctx context.Context, customerID string, callback func([]Device) error) error {
	call := c.dirChromeOS.Chromeosdevices.List(customerID).
		MaxResults(maxDevicesPerPage).
		Projection("BASIC").
		Fields(googleapi.Field("kind,nextPageToken,chromeosdevices(osVersion,model,annotatedUser,status,lastSync)"))

	err := call.Pages(named(ctx, OpChromeOSDevicesList), func(resp *admin.ChromeOsDevices) error {
		if resp.Kind == "" {
			return invalidResponse("ChromeOS devices page has no kind")
		}
		devices := make([]Device, 0, len(resp.Chromeosdevices))
		for _, d := range resp.Chromeosdevices {
			if d == nil {
				continue
			}
			active := strings.EqualFold(d.Status, "active")
			device := Device{
				Platform:   "CHROME_OS",
				OS:         "CHROME_OS",
				OSVersion:  d.OsVersion,
				Model:      d.Model,
				OwnerEmail: annotatedEmail(d.AnnotatedUser),
				Status:     d.Status,
				Compliant:  &active,
				Encrypted:  true, // Chrome OS storage is always encrypted.
			}
			if ts, err := time.Parse(time.RFC3339, d.LastSync); err == nil {
				device.LastSync = ts
			} else {
				device.LastSyncMissing = true
			}
			devices = append(devices, device)
		}
		if len(devices) == 0 {
			return nil
		}
		return callback(devices)
	})
	return listError(OpChromeOSDevicesList, "listing ChromeOS devices", err)
}

// annotatedEmail returns a Chrome OS device's annotatedUser when it is an
// email address, and "" otherwise. annotatedUser is a note an admin writes
// about the device's user, so it can hold any text.
func annotatedEmail(note string) string {
	note = strings.TrimSpace(note)
	addr, err := mail.ParseAddress(note)
	if err != nil || addr.Address != note {
		return ""
	}
	return note
}
