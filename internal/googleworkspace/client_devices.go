package googleworkspace

import (
	"context"
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
		Fields(googleapi.Field("nextPageToken,mobiledevices(type,os,model,email,status,lastSync,encryptionStatus,deviceCompromisedStatus,devicePasswordStatus)"))

	return call.Pages(ctx, func(resp *admin.MobileDevices) error {
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
				Compliant:          d.DeviceCompromisedStatus == "" || strings.EqualFold(d.DeviceCompromisedStatus, "No compromise detected"),
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
		Fields(googleapi.Field("nextPageToken,chromeosdevices(osVersion,model,annotatedUser,status,lastSync)"))

	return call.Pages(ctx, func(resp *admin.ChromeOsDevices) error {
		devices := make([]Device, 0, len(resp.Chromeosdevices))
		for _, d := range resp.Chromeosdevices {
			if d == nil {
				continue
			}
			device := Device{
				Platform:   "CHROME_OS",
				OS:         "CHROME_OS",
				OSVersion:  d.OsVersion,
				Model:      d.Model,
				OwnerEmail: d.AnnotatedUser,
				Status:     d.Status,
				Compliant:  strings.EqualFold(d.Status, "active"),
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
}
