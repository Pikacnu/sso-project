package users

import (
	"net/http"
	"sso-server/src/auth"
	dbpkg "sso-server/src/db"
	"sso-server/src/middleware"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/user"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CreateUserRequest struct {
	Email    string  `json:"email" binding:"required"`
	Username string  `json:"username" binding:"required"`
	Avatar   *string `json:"avatar"`
	Password *string `json:"password"`
}

type UpdateUserRequest struct {
	Email    *string `json:"email"`
	Username *string `json:"username"`
	Avatar   *string `json:"avatar"`
	Password *string `json:"password"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type AssignRolesRequest struct {
	RoleIDs []string `json:"role_ids" binding:"required"`
}

func RegisterUserRoutes(router *gin.Engine) {
	group := router.Group("/users")
	group.Use(middleware.RequireRole("admin"))
	group.GET("", listUsersHandler)
	group.POST("", createUserHandler)
	group.GET("/:id", getUserHandler)
	group.PUT("/:id", updateUserHandler)
	group.DELETE("/:id", deleteUserHandler)
	group.PUT("/:id/password", changePasswordHandler)
	group.POST("/:id/roles", assignRolesHandler)
	group.GET("/:id/roles", getUserRolesHandler)
}

// @Summary List users
// @Description List all users with their roles
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {array} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users [get]
func listUsersHandler(c *gin.Context) {
	ctx := c.Request.Context()
	users, err := dbpkg.Client.User.Query().WithRoles().All(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query users"})
		return
	}

	response := make([]gin.H, 0, len(users))
	for _, u := range users {
		response = append(response, userResponse(u))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get user by ID
// @Description Get details of a specific user with roles
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id} [get]
func getUserHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	u, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).WithRoles().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		}
		return
	}

	c.JSON(http.StatusOK, userResponse(u))
}

// @Summary Create user
// @Description Create a new user
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateUserRequest true "User creation request"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users [post]
func createUserHandler(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.User.Create().
		SetEmail(req.Email).
		SetUsername(req.Username)

	if req.Avatar != nil {
		builder.SetAvatar(*req.Avatar)
	}

	if req.Password != nil && *req.Password != "" {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		builder.SetPassword(hash)
	}

	u, err := builder.Save(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, userResponse(u))
}

// @Summary Update user
// @Description Update an existing user
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Param body body UpdateUserRequest true "User update request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id} [put]
func updateUserHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	builder := dbpkg.Client.User.UpdateOneID(userUUID)

	if req.Email != nil {
		builder.SetEmail(*req.Email)
	}
	if req.Username != nil {
		builder.SetUsername(*req.Username)
	}
	if req.Avatar != nil {
		builder.SetAvatar(*req.Avatar)
	}
	if req.Password != nil && *req.Password != "" {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		builder.SetPassword(hash)
	}

	u, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		}
		return
	}

	c.JSON(http.StatusOK, userResponse(u))
}

// @Summary Delete user
// @Description Delete an existing user
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id} [delete]
func deleteUserHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	err := dbpkg.Client.User.DeleteOneID(userUUID).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// @Summary Change user password
// @Description Change password for a user (admin can change any user, users can change own)
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Param body body ChangePasswordRequest true "Password change request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id}/password [put]
func changePasswordHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Old password and new password are required"})
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Old password and new password are required"})
		return
	}

	ctx := c.Request.Context()
	u, err := dbpkg.Client.User.Get(ctx, userUUID)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		}
		return
	}

	// Verify old password
	if u.Password == nil || !auth.CheckPasswordHash(req.OldPassword, *u.Password) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
		return
	}

	// Hash new password
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update password
	updatedUser, err := dbpkg.Client.User.UpdateOneID(userUUID).SetPassword(newHash).Save(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully", "user": userResponse(updatedUser)})
}

// @Summary Assign roles to user
// @Description Assign multiple roles to a user (replaces existing roles)
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Param body body AssignRolesRequest true "Role assignment request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id}/roles [post]
func assignRolesHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req AssignRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	roleUUIDs := make([]uuid.UUID, 0, len(req.RoleIDs))
	for _, id := range req.RoleIDs {
		roleUUID, err := uuid.Parse(id)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID: " + id})
			return
		}
		roleUUIDs = append(roleUUIDs, roleUUID)
	}

	ctx := c.Request.Context()
	u, err := dbpkg.Client.User.UpdateOneID(userUUID).
		ClearRoles().
		AddRoleIDs(roleUUIDs...).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User or role not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign roles"})
		}
		return
	}

	c.JSON(http.StatusOK, userResponse(u))
}

// @Summary Get user roles
// @Description Get all roles assigned to a user
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID (UUID)"
// @Success 200 {array} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /users/{id}/roles [get]
func getUserRolesHandler(c *gin.Context) {
	userUUID, ok := parseUserID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	roles, err := dbpkg.Client.User.Query().
		Where(user.IDEQ(userUUID)).
		QueryRoles().
		All(ctx)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query roles"})
		return
	}

	response := make([]gin.H, 0, len(roles))
	for _, role := range roles {
		response = append(response, gin.H{
			"id":          role.ID.String(),
			"name":        role.Name,
			"description": role.Description,
		})
	}

	c.JSON(http.StatusOK, response)
}

func parseUserID(c *gin.Context) (uuid.UUID, bool) {
	idStr := c.Param("id")
	userUUID, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return uuid.UUID{}, false
	}
	return userUUID, true
}

func userResponse(u *ent.User) gin.H {
	response := gin.H{
		"id":       u.ID.String(),
		"email":    u.Email,
		"username": u.Username,
		"avatar":   u.Avatar,
	}

	if u.Edges.Roles != nil {
		roles := make([]gin.H, 0, len(u.Edges.Roles))
		for _, role := range u.Edges.Roles {
			roles = append(roles, gin.H{
				"id":          role.ID.String(),
				"name":        role.Name,
				"description": role.Description,
			})
		}
		response["roles"] = roles
	}

	return response
}
