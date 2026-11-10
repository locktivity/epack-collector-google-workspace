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
// global membership cap. Returns nil at trust or when the group list cannot be
// read. A group whose settings or members cannot be read keeps its row with
// those values left out.
func (c *Collector) scanGroups(ctx context.Context, scope scanScope) *Groups {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	result := &Groups{}
	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeMembers := scope.level.AtLeast(componentsdk.LevelInternal)

	var inventory []Group
	settingsWarned := false
	externalAllowed := 0
	settingsFailed := 0
	var settingsErr error

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
				row.settingsErr = serr
				settingsFailed++
				if settingsErr == nil {
					settingsErr = serr
				}
			} else {
				allow := settings.AllowExternalMembers
				row.AllowExternalMembers = &allow
				row.WhoCanJoin = settings.WhoCanJoin
				row.WhoCanPostMessage = settings.WhoCanPostMessage
				if allow {
					externalAllowed++
				}
			}
			inventory = append(inventory, row)
		}
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("groups", "admin.directory.group.readonly", "Groups Admin (or Super Admin)", err)
		c.gaps.leaveOut(failed(err), "/groups")
		return nil
	}
	if settingsFailed > 0 {
		c.gaps.partial(settingsFailed, failed(settingsErr), "/groups/external_members_allowed")
	} else {
		result.ExternalMembersAllowed = &externalAllowed
	}

	if !collectInventory {
		return result
	}

	inventory, result.TruncatedInventoryDropped, result.TruncatedInventory = truncateAndWarn(c, inventory, GroupsCap, "group inventory", "/groups/inventory", func(a, b Group) bool {
		return a.MemberCount > b.MemberCount
	})

	if includeMembers {
		c.collectGroupMembers(ctx, result, inventory)
	}

	for i, row := range inventory {
		if row.settingsErr != nil {
			c.gaps.leaveOut(failed(row.settingsErr),
				itemPointer("/groups/inventory", i, "allow_external_members"),
				itemPointer("/groups/inventory", i, "who_can_join"),
				itemPointer("/groups/inventory", i, "who_can_post_message"))
		}
		if row.membersErr != nil {
			c.gaps.leaveOut(failed(row.membersErr), itemPointer("/groups/inventory", i, "members"))
		}
	}
	result.Inventory = inventory
	return result
}

// collectGroupMembers fetches each group's members, bounded by the global
// membership cap (counted across all groups, not per group). A member list
// cut short at the cap gets a too_large partial gap. A list not read because
// of the cap gets a too_large gap.
func (c *Collector) collectGroupMembers(ctx context.Context, result *Groups, inventory []Group) {
	total := 0
	capped := failed(tooLarge("group membership inventory", GroupMembershipsCap))
	for i := range inventory {
		if total >= GroupMembershipsCap {
			result.TruncatedMemberships = true
			for j := i; j < len(inventory); j++ {
				c.gaps.leaveOut(capped, itemPointer("/groups/inventory", j, "members"))
			}
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
			inventory[i].membersErr = err
			continue
		}
		if errors.Is(err, errMembershipCapReached) {
			c.gaps.partial(max(1, inventory[i].MemberCount-len(members)), capped, itemPointer("/groups/inventory", i, "members"))
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
		c.warn("surface %s: scan failed: %s", surface, c.errorText(err))
	}
}
