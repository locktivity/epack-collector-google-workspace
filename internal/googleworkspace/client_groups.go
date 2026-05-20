package googleworkspace

import (
	"context"
	"strings"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

// ListGroups lists all groups for the customer.
func (c *APIClient) ListGroups(ctx context.Context, customerID string, callback func([]Group) error) error {
	call := c.dirGroups.Groups.List().
		Customer(customerID).
		MaxResults(maxGroupsPerPage).
		Fields(googleapi.Field("nextPageToken,groups(email,name,description,directMembersCount,adminCreated)"))

	return call.Pages(ctx, func(resp *admin.Groups) error {
		groups := make([]Group, 0, len(resp.Groups))
		for _, g := range resp.Groups {
			if g == nil {
				continue
			}
			groups = append(groups, Group{
				Email:              g.Email,
				Name:               g.Name,
				Description:        g.Description,
				DirectMembersCount: int(g.DirectMembersCount),
				AdminCreated:       g.AdminCreated,
			})
		}
		if len(groups) == 0 {
			return nil
		}
		return callback(groups)
	})
}

// GetGroupSettings fetches the per-group settings relevant to posture.
func (c *APIClient) GetGroupSettings(ctx context.Context, groupEmail string) (GroupSettings, error) {
	resp, err := c.groupSettings.Groups.Get(groupEmail).Context(ctx).Do()
	if err != nil {
		return GroupSettings{}, err
	}
	return GroupSettings{
		AllowExternalMembers: strings.EqualFold(resp.AllowExternalMembers, "true"),
		WhoCanJoin:           resp.WhoCanJoin,
		WhoCanPostMessage:    resp.WhoCanPostMessage,
	}, nil
}

// ListGroupMembers lists the members of a group (internal level).
func (c *APIClient) ListGroupMembers(ctx context.Context, groupEmail string, callback func([]GroupMember) error) error {
	call := c.dirGroupMembers.Members.List(groupEmail).
		MaxResults(maxMembersPerPage).
		Fields(googleapi.Field("nextPageToken,members(email,role,type,status,delivery_settings)"))

	return call.Pages(ctx, func(resp *admin.Members) error {
		members := make([]GroupMember, 0, len(resp.Members))
		for _, m := range resp.Members {
			if m == nil {
				continue
			}
			members = append(members, GroupMember{
				Email:            m.Email,
				Role:             m.Role,
				Type:             m.Type,
				Status:           m.Status,
				DeliverySettings: m.DeliverySettings,
			})
		}
		if len(members) == 0 {
			return nil
		}
		return callback(members)
	})
}
