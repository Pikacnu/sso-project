package middleware

import (
	"context"
	"net/http"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/oauthclient"
	dbpkg "sso-server/src/db"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ClientMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		urlPath := c.Request.URL.Path

		if IsPublicPath(urlPath) {
			c.Next()
			return
		}

		if _, ok := c.Get("user_id"); ok {
			c.Next()
			return
		}

		isProtected := IsProtectedPaths(urlPath)
		if !isProtected {
			c.Next()
			return
		}

		secret := c.GetHeader("Authorization")
		clientID := c.GetHeader("X-Client-ID")

		if strings.HasPrefix(strings.TrimSpace(secret), "Bearer ") {
			c.Next()
			return
		}

		if strings.TrimSpace(secret) == "" || strings.TrimSpace(clientID) == "" {
			if !isProtected {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}

		clientUUID, err := uuid.Parse(clientID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client ID format"})
			return
		}

		ctxBg := context.Background()
		clientEnt, err := dbpkg.Client.OAuthClient.Query().Where(
			oauthclient.IDEQ(clientUUID),
			oauthclient.SecretEQ(secret),
			oauthclient.IsActiveEQ(true),
		).Only(ctxBg)
		if err != nil {
			if ent.IsNotFound(err) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials"})
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query client"})
			}
			return
		}
		c.Set("client_id", clientEnt.ID)
		c.Set("client", clientEnt)
		c.Next()
	}
}
