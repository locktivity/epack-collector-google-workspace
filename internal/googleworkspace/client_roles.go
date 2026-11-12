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
		Fields(googleapi.Field("kind,nextPageToken,items(roleId,roleName,roleDescription,isSystemRole,isSuperAdminRole,rolePrivileges)"))

	err := call.Pages(named(ctx, OpRolesList), func(resp *admin.Roles) error {
		if resp.Kind == "" {
			return invalidResponse("admin roles page has no kind")
		}
		roles := make([]Role, 0, len(resp.Items))
		for _, role := range resp.Items {
			if role == nil {
				continue
			}
			privileges := make([]string, 0, len(role.RolePrivileges))
			for _, p := range role.RolePrivileges {
				if p != nil {
					privileges = append(privileges, p.PrivilegeName)
				}
			}
			roles = append(roles, Role{
				ID:             strconv.FormatInt(role.RoleId, 10),
				Name:           role.RoleName,
				Description:    role.RoleDescription,
				PrivilegeCount: len(role.RolePrivileges),
				IsSystem:       role.IsSystemRole,
				IsSuperAdmin:   role.IsSuperAdminRole,
				Privileges:     privileges,
			})
		}
		if len(roles) == 0 {
			return nil
		}
		return callback(roles)
	})
	return listError(OpRolesList, "listing admin roles", err)
}

// ListRoleAssignments lists role grants for the customer.
func (c *APIClient) ListRoleAssignments(ctx context.Context, customerID string, callback func([]RoleAssignment) error) error {
	call := c.dirRoles.RoleAssignments.List(customerID).
		MaxResults(maxRoleAssignmentsPerPage).
		Fields(googleapi.Field(roleAssignmentFields))

	err := call.Pages(named(ctx, OpRoleAssignmentsList), roleAssignmentPage(callback))
	return listError(OpRoleAssignmentsList, "listing role assignments", err)
}

// ListUserRoleAssignments lists the role grants a user holds, both their own
// and those of the groups they are in. Google lists a group's grants for its
// members only when asked about one user.
func (c *APIClient) ListUserRoleAssignments(ctx context.Context, customerID, userKey string, callback func([]RoleAssignment) error) error {
	call := c.dirRoles.RoleAssignments.List(customerID).
		UserKey(userKey).
		IncludeIndirectRoleAssignments(true).
		MaxResults(maxRoleAssignmentsPerPage).
		Fields(googleapi.Field(roleAssignmentFields))

	err := call.Pages(named(ctx, OpUserAssignmentsList), roleAssignmentPage(callback))
	return listError(OpUserAssignmentsList, "listing a user's role assignments", err)
}

const roleAssignmentFields = "kind,nextPageToken,items(assignedTo,roleId,scopeType,orgUnitId)"

func roleAssignmentPage(callback func([]RoleAssignment) error) func(*admin.RoleAssignments) error {
	return func(resp *admin.RoleAssignments) error {
		if resp.Kind == "" {
			return invalidResponse("role assignments page has no kind")
		}
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
	}
}
