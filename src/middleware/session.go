package middleware

import (
	"context"
	"net/http"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/session"
	"sso-server/src/auth"
	dbpkg "sso-server/src/db"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func SessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		urlPath := c.Request.URL.Path

		if IsPublicPath(urlPath) {
			c.Next()
			return
		}

		isProtected := false
		for _, protectedPath := range ProtectedPaths {
			if strings.HasPrefix(urlPath, protectedPath) {
				isProtected = true
				break
			}
		}

		if c.Request.Header.Get("Authorization") != "" {
			c.Next()
			// Skip session middleware for token-based auth
			return
		}

		if !isProtected {
			c.Next()
			return
		}

		tokenString, err := c.Cookie("session_token")
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			return
		}

		// 1. JWT Stateless Validation
		claims, err := auth.ValidateJWT(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// 2. Server-side Session Validation
		sid := claims.Sid
		if sid == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session data"})
			return
		}

		// Parse session ID to UUID
		sessionUUID, err := uuid.Parse(sid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session ID format"})
			return
		}

		ctxBg := context.Background()
		sessionEnt, err := dbpkg.Client.Session.Query().Where(
			session.IDEQ(sessionUUID),
			session.IsRevokedEQ(false),
			session.ExpiresAtGT(time.Now()),
		).Only(ctxBg)
		if err != nil {
			if ent.IsNotFound(err) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session expired or revoked"})
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query session"})
			}
			return
		}
		_ = sessionEnt // Use sessionEnt to avoid unused variable

		c.Set("user_id", claims.Sub)
		c.Set("user_claims", claims)
		c.Set("session_id", sid)
		c.Next()
	}
}
