package auth

import (
	"context"
	"slices"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/accesstoken"
	"sso-server/src/auth"
	dbpkg "sso-server/src/db"
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

	ctxBg := context.Background()
	atEnt, err := dbpkg.Client.AccessToken.Query().Where(accesstoken.TokenEQ(tokenString)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		} else {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		}
		return
	}

	scopeStr := ""
	if atEnt.Scope != nil {
		scopeStr = *atEnt.Scope
	}
	scopes := strings.Split(strings.TrimSpace(scopeStr), ",")
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
