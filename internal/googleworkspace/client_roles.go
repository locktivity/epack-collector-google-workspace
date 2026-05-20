package googleworkspace

import (
	"context"
	"strconv"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

// ListRoles lists admin role definitions for the customer.
func (c *APIClient) ListRoles(ctx context.Context, customerID string, callback func([]Role) error) error {
	call := c.dirRoles.Roles.List(customerID).
		MaxResults(maxRolesPerPage).
		Fields(googleapi.Field("nextPageToken,items(roleId,roleName,roleDescription,isSystemRole,isSuperAdminRole,rolePrivileges)"))

	return call.Pages(ctx, func(resp *admin.Roles) error {
		roles := make([]Role, 0, len(resp.Items))
		for _, role := range resp.Items {
			if role == nil {
				continue
			}
			roles = append(roles, Role{
				ID:             strconv.FormatInt(role.RoleId, 10),
				Name:           role.RoleName,
				Description:    role.RoleDescription,
				PrivilegeCount: len(role.RolePrivileges),
				IsSystem:       role.IsSystemRole,
				IsSuperAdmin:   role.IsSuperAdminRole,
			})
		}
		if len(roles) == 0 {
			return nil
		}
		return callback(roles)
	})
}

// ListRoleAssignments lists role grants for the customer.
func (c *APIClient) ListRoleAssignments(ctx context.Context, customerID string, callback func([]RoleAssignment) error) error {
	call := c.dirRoles.RoleAssignments.List(customerID).
		MaxResults(maxRoleAssignmentsPerPage).
		Fields(googleapi.Field("nextPageToken,items(assignedTo,roleId,scopeType,orgUnitId)"))

	return call.Pages(ctx, func(resp *admin.RoleAssignments) error {
		assignments := make([]RoleAssignment, 0, len(resp.Items))
		for _, a := range resp.Items {
			if a == nil {
				continue
			}
			assignments = append(assignments, RoleAssignment{
				AssignedTo: a.AssignedTo,
				RoleID:     strconv.FormatInt(a.RoleId, 10),
				ScopeType:  a.ScopeType,
				OrgUnitID:  a.OrgUnitId,
			})
		}
		if len(assignments) == 0 {
			return nil
		}
		return callback(assignments)
	})
}
