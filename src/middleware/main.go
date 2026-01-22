package middleware

import (
	"net/http"
	"sso-server/src/auth"
	"sso-server/src/db"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var ProtectedPaths = []string{
	"/api/",
	"/user/",
}

func RegistryMiddleware(router *gin.Engine) {
	middlewares := []gin.HandlerFunc{
		gin.Logger(),
		gin.Recovery(),
		ConfigMiddleware(),
		SessionMiddleware(),
		ClientMiddleware(),
	}
	router.Use(middlewares...)
}

func SessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		urlPath := c.Request.URL.Path

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

		var session db.Session
		err = db.DBConnection.Where("id = ? AND is_revoked = ? AND expires_at > ?", sid, false, time.Now()).First(&session).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session expired or revoked"})
			return
		}

		c.Set("user_id", claims.Sub)
		c.Set("user_claims", claims)
		c.Set("session_id", sid)
		c.Next()
	}
}

func ClientMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := c.GetHeader("Authorization")
		clientID := c.GetHeader("X-Client-ID")

		if strings.TrimSpace(secret) == "" || strings.TrimSpace(clientID) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}

		var client db.OAuthClient
		err := db.DBConnection.Where("id = ? AND secret = ? AND is_active = ?", clientID, secret, true).First(&client).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials"})
			return
		}
		c.Next()
	}
}
