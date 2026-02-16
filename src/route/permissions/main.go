package permissions

import (
	"net/http"
	dbpkg "sso-server/src/db"
	"sso-server/src/middleware"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/permission"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CreatePermissionRequest struct {
	Key         string  `json:"key" binding:"required"`
	Description *string `json:"description"`
}

type UpdatePermissionRequest struct {
	Key         *string `json:"key"`
	Description *string `json:"description"`
}

func RegisterPermissionRoutes(router *gin.Engine) {
	group := router.Group("/permissions")
	group.Use(middleware.RequireRole("admin"))
	group.GET("", listPermissionsHandler)
	group.POST("", createPermissionHandler)
	group.GET("/:id", getPermissionHandler)
	group.PUT("/:id", updatePermissionHandler)
	group.DELETE("/:id", deletePermissionHandler)
}

// @Summary List permissions
// @Description List all permissions
// @Tags permissions
// @Security BearerAuth
// @Produce json
// @Success 200 {array} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [get]
func listPermissionsHandler(c *gin.Context) {
	ctx := c.Request.Context()
	permissions, err := dbpkg.Client.Permission.Query().All(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query permissions"})
		return
	}

	response := make([]gin.H, 0, len(permissions))
	for _, p := range permissions {
		response = append(response, permissionResponse(p))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get permission by ID
// @Description Get details of a specific permission
// @Tags permissions
// @Security BearerAuth
// @Produce json
// @Param id path string true "Permission ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions/{id} [get]
func getPermissionHandler(c *gin.Context) {
	permissionUUID, ok := parsePermissionID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	p, err := dbpkg.Client.Permission.Query().Where(permission.IDEQ(permissionUUID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query permission"})
		}
		return
	}

	c.JSON(http.StatusOK, permissionResponse(p))
}

// @Summary Create permission
// @Description Create a new permission
// @Tags permissions
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreatePermissionRequest true "Permission creation request"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions [post]
func createPermissionHandler(c *gin.Context) {
	var req CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.Permission.Create().SetKey(req.Key)

	if req.Description != nil {
		builder.SetDescription(*req.Description)
	}

	p, err := builder.Save(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create permission"})
		return
	}

	c.JSON(http.StatusCreated, permissionResponse(p))
}

// @Summary Update permission
// @Description Update an existing permission
// @Tags permissions
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Permission ID (UUID)"
// @Param body body UpdatePermissionRequest true "Permission update request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions/{id} [put]
func updatePermissionHandler(c *gin.Context) {
	permissionUUID, ok := parsePermissionID(c)
	if !ok {
		return
	}

	var req UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.Permission.UpdateOneID(permissionUUID)

	if req.Key != nil {
		builder.SetKey(*req.Key)
	}
	if req.Description != nil {
		builder.SetDescription(*req.Description)
	}

	p, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update permission"})
		}
		return
	}

	c.JSON(http.StatusOK, permissionResponse(p))
}

// @Summary Delete permission
// @Description Delete an existing permission
// @Tags permissions
// @Security BearerAuth
// @Produce json
// @Param id path string true "Permission ID (UUID)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /permissions/{id} [delete]
func deletePermissionHandler(c *gin.Context) {
	permissionUUID, ok := parsePermissionID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	err := dbpkg.Client.Permission.DeleteOneID(permissionUUID).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete permission"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Permission deleted successfully"})
}

func parsePermissionID(c *gin.Context) (uuid.UUID, bool) {
	idStr := c.Param("id")
	permissionUUID, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
		return uuid.UUID{}, false
	}
	return permissionUUID, true
}

func permissionResponse(p *ent.Permission) gin.H {
	return gin.H{
		"id":          p.ID.String(),
		"key":         p.Key,
		"description": p.Description,
	}
}
