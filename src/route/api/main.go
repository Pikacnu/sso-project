package api

import (
	"net/http"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
)

func RegisterAPIRoutes(router *gin.Engine) {
	apiGroup := router.Group("/api")
	{
		apiGroup.GET("/user", GetUserData)
	}
}

func GetUserData(c *gin.Context) {
	session := c.MustGet("session_id").(string)
	var user db.User
	result := db.DBConnection.Joins("JOIN sessions ON sessions.user_id = users.id").
		Where("sessions.id = ?", session).
		Limit(1).Find(&user)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(200, gin.H{
		"id":       user.ID,
		"email":    user.Email,
		"username": user.Username,
		"avatar":   user.Avatar,
	})
}
