package collector

import (
	"context"
	"errors"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// errMembershipCapReached stops member pagination once the global membership
// cap is hit. It never escapes scanGroups.
var errMembershipCapReached = errors.New("group membership cap reached")

// scanGroups collects the Groups surface (audit and above). Audit emits counts
// (total, admin- vs user-created), the count of groups allowing external
// members, and the per-group inventory with settings (external-members flag,
// who-can-join/post). Internal adds each group's member list, bounded by the
// global membership cap. Returns nil at trust or on scope / role denial.
func (c *Collector) scanGroups(ctx context.Context, scope scanScope) *Groups {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	result := &Groups{}
	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeMembers := scope.level.AtLeast(componentsdk.LevelInternal)

	var inventory []Group
	settingsWarned := false

	err := c.client.ListGroups(ctx, scope.customerID, func(groups []googleworkspace.Group) error {
		for _, g := range groups {
			result.Total++
			if g.AdminCreated {
				result.AdminCreated++
			} else {
				result.UserCreated++
			}
			if !collectInventory {
				continue
			}

			row := Group{
				Email:        g.Email,
				Name:         g.Name,
				Description:  g.Description,
				MemberCount:  g.DirectMembersCount,
				AdminCreated: g.AdminCreated,
			}
			settings, serr := c.client.GetGroupSettings(ctx, g.Email)
			if serr != nil {
				if !settingsWarned {
					if isAPINotEnabled(serr) {
						c.recordAPINotEnabled("groups:settings", serr)
					} else {
						c.warn("groups: group settings unavailable for one or more groups; external-members and who-can-* fields omitted: %v", serr)
					}
					settingsWarned = true
				}
			} else {
				row.AllowExternalMembers = settings.AllowExternalMembers
				row.WhoCanJoin = settings.WhoCanJoin
				row.WhoCanPostMessage = settings.WhoCanPostMessage
				if settings.AllowExternalMembers {
					result.ExternalMembersAllowed++
				}
			}
			inventory = append(inventory, row)
		}
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("groups", "admin.directory.group.readonly", "Groups Admin (or Super Admin)", err)
		return nil
	}

	if !collectInventory {
		return result
	}

	inventory, result.TruncatedInventoryDropped, result.TruncatedInventory = truncateAndWarn(c, inventory, GroupsCap, "group inventory", func(a, b Group) bool {
		return a.MemberCount > b.MemberCount
	})

	if includeMembers {
		c.collectGroupMembers(ctx, result, inventory)
	}

	result.Inventory = inventory
	return result
}

// collectGroupMembers fetches each group's members, bounded by the global
// membership cap (counted across all groups, not per group).
func (c *Collector) collectGroupMembers(ctx context.Context, result *Groups, inventory []Group) {
	total := 0
	for i := range inventory {
		if total >= GroupMembershipsCap {
			result.TruncatedMemberships = true
			break
		}
		var members []GroupMember
		err := c.client.ListGroupMembers(ctx, inventory[i].Email, func(batch []googleworkspace.GroupMember) error {
			for _, m := range batch {
				if total >= GroupMembershipsCap {
					result.TruncatedMemberships = true
					return errMembershipCapReached
				}
				members = append(members, GroupMember{
					Email:            m.Email,
					Role:             m.Role,
					Type:             m.Type,
					Status:           m.Status,
					DeliverySettings: m.DeliverySettings,
				})
				total++
			}
			return nil
		})
		if err != nil && !errors.Is(err, errMembershipCapReached) {
			c.warn("groups: member list unavailable for %s: %v", inventory[i].Email, err)
			continue
		}
		inventory[i].Members = members
	}
	if result.TruncatedMemberships {
		c.warn("group membership inventory truncated at the %d total-row cap", GroupMembershipsCap)
	}
}

// warnSurfaceScan records the right degradation diagnostic for a failed surface
// scan, distinguishing missing scope from insufficient role; other errors are
// surfaced verbatim. Shared by the new directory-backed surfaces.
func (c *Collector) warnSurfaceScan(surface, missingScope, requiredRole string, err error) {
	switch {
	case isAPINotEnabled(err):
		c.recordAPINotEnabled(surface, err)
	case isScopeDenied(err):
		c.recordScopeDenied(surface, missingScope)
	case isRoleInsufficient(err):
		c.recordRoleInsufficient(surface, requiredRole)
	default:
		c.warn("surface %s: scan failed: %v", surface, err)
	}
}
