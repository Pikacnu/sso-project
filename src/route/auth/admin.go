package auth

import (
	"context"
	"net/http"
	"strings"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"
	"sso-server/ent/generated/permission"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
)

type AdminInitRequest struct {
	Email    string `json:"email" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AdminInitResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	AdminUser *gin.H `json:"admin_user,omitempty"`
	AdminRole *gin.H `json:"admin_role,omitempty"`
}

// @Summary Initialize admin account
// @Description Initialize admin account on first setup
// @Tags auth
// @Accept json
// @Produce json
// @Param body body AdminInitRequest true "Admin initialization request"
// @Success 200 {object} AdminInitResponse
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/admin/init [post]
func adminInitHandler(c *gin.Context) {
	var req AdminInitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Email, username, and password are required"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Username == "" || req.Password == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Email, username, and password cannot be empty"})
		return
	}

	ctx := context.Background()

	// Check if admin role exists
	adminRole, err := db.Client.Role.Query().Where(role.NameEQ("admin")).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query roles"})
		return
	}

	// If admin role exists, check if there are any admin users
	if err == nil {
		adminUsers, err := db.Client.Role.Query().
			Where(role.IDEQ(adminRole.ID)).
			QueryUsers().
			All(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query admin users"})
			return
		}

		if len(adminUsers) > 0 {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Admin account already initialized"})
			return
		}
	}

	// Create admin role if it doesn't exist
	if err != nil && ent.IsNotFound(err) {
		adminRole, err = db.Client.Role.Create().
			SetName("admin").
			SetDescription("Administrator with full system access").
			Save(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin role"})
			return
		}
	}

	// Hash password
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create admin user
	adminUser, err := db.Client.User.Create().
		SetEmail(req.Email).
		SetUsername(req.Username).
		SetPassword(hash).
		SetEmailVerified(true).
		AddRoles(adminRole).
		Save(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin user"})
		return
	}

	// Create default permissions
	permissions := []struct {
		key         string
		description string
	}{
		{"oauth:register", "Permission to register OAuth applications"},
		{"users:manage", "Permission to manage users"},
		{"roles:manage", "Permission to manage roles"},
		{"scopes:manage", "Permission to manage scopes"},
		{"permissions:manage", "Permission to manage permissions"},
	}

	for _, perm := range permissions {
		p, err := db.Client.Permission.Create().
			SetKey(perm.key).
			SetDescription(perm.description).
			Save(ctx)
		if err != nil && !strings.Contains(err.Error(), "unique constraint") {
			// Log error but continue
			continue
		}

		// Assign permission to admin role
		if err == nil {
			_ = db.Client.Role.UpdateOne(adminRole).AddPermissions(p).Exec(ctx)
		}
	}

	// Ensure a default 'user' role exists and grant it minimal permissions (e.g., oauth:register)
	userRole, err := db.Client.Role.Query().Where(role.NameEQ("user")).Only(ctx)
	if err != nil && ent.IsNotFound(err) {
		userRole, err = db.Client.Role.Create().SetName("user").SetDescription("Default non-admin user").Save(ctx)
		if err == nil {
			// Attach oauth:register permission if exists
			p, err := db.Client.Permission.Query().Where(permission.KeyEQ("oauth:register")).Only(ctx)
			if err == nil {
				_ = db.Client.Role.UpdateOne(userRole).AddPermissions(p).Exec(ctx)
			}
		}
	}

	response := AdminInitResponse{
		Success: true,
		Message: "Admin account initialized successfully",
		AdminUser: &gin.H{
			"id":       adminUser.ID.String(),
			"email":    adminUser.Email,
			"username": adminUser.Username,
		},
		AdminRole: &gin.H{
			"id":   adminRole.ID.String(),
			"name": adminRole.Name,
		},
	}

	c.JSON(http.StatusOK, response)
}
