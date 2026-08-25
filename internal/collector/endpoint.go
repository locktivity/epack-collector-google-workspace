package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// scanEndpoint collects the Endpoint surface (audit and above) across mobile and
// Chrome OS devices. Audit emits device counts by OS, the not-synced-30d count,
// and per-OS compliant / non-compliant breakdowns; internal adds per-device rows
// (capped, sorted by last sync descending). Device serials / IMEIs are never
// collected. Returns nil at trust or if both device lists fail.
func (c *Collector) scanEndpoint(ctx context.Context, scope scanScope) *Endpoint {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	var devices []googleworkspace.Device
	gather := func(batch []googleworkspace.Device) error {
		devices = append(devices, batch...)
		return nil
	}

	mobileErr := c.client.ListMobileDevices(ctx, scope.customerID, gather)
	if mobileErr != nil {
		c.warnSurfaceScan("endpoint:mobile", "admin.directory.device.mobile.readonly", "Mobile Admin (or Super Admin)", mobileErr)
	}
	chromeErr := c.client.ListChromeOSDevices(ctx, scope.customerID, gather)
	if chromeErr != nil {
		c.warnSurfaceScan("endpoint:chromeos", "admin.directory.device.chromeos.readonly", "Services Admin (or Super Admin)", chromeErr)
	}
	if mobileErr != nil && chromeErr != nil {
		return nil
	}

	result := &Endpoint{ManagedByOS: map[string]int{}}
	notSyncedThreshold := scope.collectedAt.AddDate(0, 0, -30)
	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeRows := scope.level.AtLeast(componentsdk.LevelInternal)
	if collectInventory {
		result.CompliantByOS = map[string]int{}
		result.NonCompliantByOS = map[string]int{}
	}

	var inventory []EndpointDevice
	for _, d := range devices {
		result.Total++
		result.ManagedByOS[d.OS]++
		if d.LastSyncMissing || d.LastSync.Before(notSyncedThreshold) {
			result.NotSynced30d++
		}
		if collectInventory {
			if d.Compliant {
				result.CompliantByOS[d.OS]++
			} else {
				result.NonCompliantByOS[d.OS]++
			}
		}
		if includeRows {
			row := EndpointDevice{
				Platform:           d.Platform,
				OS:                 d.OS,
				OSVersion:          d.OSVersion,
				Model:              d.Model,
				OwnerEmail:         d.OwnerEmail,
				Compliant:          d.Compliant,
				Encrypted:          d.Encrypted,
				ScreenLockEnforced: d.ScreenLockEnforced,
			}
			if !d.LastSyncMissing {
				row.LastSync = d.LastSync.UTC().Format(time.RFC3339)
			}
			inventory = append(inventory, row)
		}
	}

	if includeRows {
		result.Inventory, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, inventory, EndpointDevicesCap, "endpoint device inventory", func(a, b EndpointDevice) bool {
			return a.LastSync > b.LastSync
		})
	}
	return result
}
