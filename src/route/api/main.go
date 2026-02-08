package api

import (
	"context"
	"net/http"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/session"
	dbpkg "sso-server/src/db"

	"github.com/gin-gonic/gin"
)

func RegisterAPIRoutes(router *gin.Engine) {
	apiGroup := router.Group("/api")
	{
		apiGroup.GET("/user", GetUserData)
	}
}

func GetUserData(c *gin.Context) {
	sessionID := c.MustGet("session_id").(string)
	ctxBg := context.Background()

	// Load session by ID to get user_id
	sessionEnt, err := dbpkg.Client.Session.Query().Where(session.IDEQ(sessionID)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Load user by ID
	userEnt, err := dbpkg.Client.User.Get(ctxBg, sessionEnt.UserID)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	avatarStr := ""
	if userEnt.Avatar != nil {
		avatarStr = *userEnt.Avatar
	}

	c.JSON(200, gin.H{
		"id":       userEnt.ID,
		"email":    userEnt.Email,
		"username": userEnt.Username,
		"avatar":   avatarStr,
	})
}
