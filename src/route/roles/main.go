package roles

import (
	"net/http"
	dbpkg "sso-server/src/db"
	"sso-server/src/middleware"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CreateRoleRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

type UpdateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type AssignPermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

func RegisterRoleRoutes(router *gin.Engine) {
	group := router.Group("/roles")
	group.Use(middleware.RequireRole("admin"))
	group.GET("", listRolesHandler)
	group.POST("", createRoleHandler)
	group.GET("/:id", getRoleHandler)
	group.PUT("/:id", updateRoleHandler)
	group.DELETE("/:id", deleteRoleHandler)
	group.POST("/:id/permissions", assignPermissionsHandler)
	group.GET("/:id/permissions", getRolePermissionsHandler)
}

// @Summary List roles
// @Description List all roles with their permissions
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Success 200 {array} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [get]
func listRolesHandler(c *gin.Context) {
	ctx := c.Request.Context()
	roles, err := dbpkg.Client.Role.Query().WithPermissions().All(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query roles"})
		return
	}

	response := make([]gin.H, 0, len(roles))
	for _, r := range roles {
		response = append(response, roleResponse(r))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get role by ID
// @Description Get details of a specific role with permissions
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param id path string true "Role ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id} [get]
func getRoleHandler(c *gin.Context) {
	roleUUID, ok := parseRoleID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	r, err := dbpkg.Client.Role.Query().Where(role.IDEQ(roleUUID)).WithPermissions().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query role"})
		}
		return
	}

	c.JSON(http.StatusOK, roleResponse(r))
}

// @Summary Create role
// @Description Create a new role
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateRoleRequest true "Role creation request"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles [post]
func createRoleHandler(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.Role.Create().SetName(req.Name)

	if req.Description != nil {
		builder.SetDescription(*req.Description)
	}

	r, err := builder.Save(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}

	c.JSON(http.StatusCreated, roleResponse(r))
}

// @Summary Update role
// @Description Update an existing role
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Role ID (UUID)"
// @Param body body UpdateRoleRequest true "Role update request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id} [put]
func updateRoleHandler(c *gin.Context) {
	roleUUID, ok := parseRoleID(c)
	if !ok {
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.Role.UpdateOneID(roleUUID)

	if req.Name != nil {
		builder.SetName(*req.Name)
	}
	if req.Description != nil {
		builder.SetDescription(*req.Description)
	}

	r, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		}
		return
	}

	c.JSON(http.StatusOK, roleResponse(r))
}

// @Summary Delete role
// @Description Delete an existing role
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param id path string true "Role ID (UUID)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id} [delete]
func deleteRoleHandler(c *gin.Context) {
	roleUUID, ok := parseRoleID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	err := dbpkg.Client.Role.DeleteOneID(roleUUID).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}

// @Summary Assign permissions to role
// @Description Assign multiple permissions to a role (replaces existing permissions)
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Role ID (UUID)"
// @Param body body AssignPermissionsRequest true "Permission assignment request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id}/permissions [post]
func assignPermissionsHandler(c *gin.Context) {
	roleUUID, ok := parseRoleID(c)
	if !ok {
		return
	}

	var req AssignPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	permissionUUIDs := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, id := range req.PermissionIDs {
		permissionUUID, err := uuid.Parse(id)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID: " + id})
			return
		}
		permissionUUIDs = append(permissionUUIDs, permissionUUID)
	}

	ctx := c.Request.Context()
	r, err := dbpkg.Client.Role.UpdateOneID(roleUUID).
		ClearPermissions().
		AddPermissionIDs(permissionUUIDs...).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Role or permission not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign permissions"})
		}
		return
	}

	c.JSON(http.StatusOK, roleResponse(r))
}

// @Summary Get role permissions
// @Description Get all permissions assigned to a role
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param id path string true "Role ID (UUID)"
// @Success 200 {array} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /roles/{id}/permissions [get]
func getRolePermissionsHandler(c *gin.Context) {
	roleUUID, ok := parseRoleID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	permissions, err := dbpkg.Client.Role.Query().
		Where(role.IDEQ(roleUUID)).
		QueryPermissions().
		All(ctx)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query permissions"})
		return
	}

	response := make([]gin.H, 0, len(permissions))
	for _, perm := range permissions {
		response = append(response, gin.H{
			"id":          perm.ID.String(),
			"key":         perm.Key,
			"description": perm.Description,
		})
	}

	c.JSON(http.StatusOK, response)
}

func parseRoleID(c *gin.Context) (uuid.UUID, bool) {
	idStr := c.Param("id")
	roleUUID, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return uuid.UUID{}, false
	}
	return roleUUID, true
}

func roleResponse(r *ent.Role) gin.H {
	response := gin.H{
		"id":          r.ID.String(),
		"name":        r.Name,
		"description": r.Description,
	}

	if r.Edges.Permissions != nil {
		permissions := make([]gin.H, 0, len(r.Edges.Permissions))
		for _, perm := range r.Edges.Permissions {
			permissions = append(permissions, gin.H{
				"id":          perm.ID.String(),
				"key":         perm.Key,
				"description": perm.Description,
			})
		}
		response["permissions"] = permissions
	}

	return response
}
