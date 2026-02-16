package middleware

import (
	"net/http"

	"sso-server/ent/generated/user"
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
