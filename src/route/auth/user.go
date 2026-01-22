package auth

import (
	"slices"
	"sso-server/src/auth"
	. "sso-server/src/db"
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

	var accessToken AccessToken
	result := DBConnection.Where("token = ?", tokenString).First(&accessToken)
	if result.Error != nil {
		c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		return
	}

	scopes := strings.Split(strings.TrimSpace(accessToken.Scope), ",")
	if !slices.Contains(scopes, "sso.profile") {
		c.AbortWithStatusJSON(403, gin.H{"error": "Insufficient scope"})
		return
	}

	c.JSON(200, gin.H{
		"sub":   claims.Sub,
		"email": claims.Email,
		"exp":   claims.ExpiresAt,
	})
}
