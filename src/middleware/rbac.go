package middleware

import (
	"net/http"

	"sso-server/ent/generated/user"
	"sso-server/ent/generated/permission"
	"sso-server/ent/generated/role"
	dbpkg "sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequireRole ensures the authenticated user has the specified role.
func RequireRole(roleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDRaw, ok := c.Get("user_id")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
			return
		}

		userIDStr, ok := userIDRaw.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
			return
		}

		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		ctx := c.Request.Context()
		roles, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).QueryRoles().All(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to load roles"})
			return
		}

		for _, role := range roles {
			if role.Name == roleName {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
	}
}

// RequirePermission ensures the authenticated user has the specified permission key.
func RequirePermission(permissionKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDRaw, ok := c.Get("user_id")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
			return
		}

		userIDStr, ok := userIDRaw.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
			return
		}

		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		ctx := c.Request.Context()
		// Check permission existence via roles -> permissions
		hasPerm, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).
			QueryRoles().
			QueryPermissions().
			Where(permission.KeyEQ(permissionKey)).
			Exist(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if !hasPerm {
			// Also allow admin role implicitly
			isAdmin, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).QueryRoles().Where(role.NameEQ("admin")).Exist(ctx)
			if err == nil && isAdmin {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		c.Next()
	}
}
