package auth

import (
	"sso-server/src/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

func userInfoHandler(c *gin.Context) {
	rawToken := c.Request.Header.Get("Authorization")
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || !strings.HasPrefix(rawToken, "Bearer ") {
		c.AbortWithStatusJSON(401, gin.H{"error": "Missing Authorization header"})
		return
	}
	tokenString := strings.TrimPrefix(rawToken, "Bearer ")

	claims, err := auth.ValidateJWT(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		return
	}
	c.JSON(200, gin.H{
		"sub":   claims.Sub,
		"email": claims.Email,
		"exp":   claims.ExpiresAt,
	})

}
