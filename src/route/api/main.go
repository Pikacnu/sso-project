package api

import (
	"context"
	"net/http"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"
	"sso-server/ent/generated/session"
	"sso-server/ent/generated/user"
	dbpkg "sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func RegisterAPIRoutes(router *gin.Engine) {
	apiGroup := router.Group("/api")
	{
		apiGroup.GET("/user", GetUserData)
	}
}

// @Summary Get current user data
// @Description Get the authenticated user's data from session
// @Tags api
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/user [get]
func GetUserData(c *gin.Context) {
	sessionID := c.MustGet("session_id").(string)
	ctxBg := context.Background()

	// Parse session ID to UUID
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	// Load session by ID to get user_id
	sessionEnt, err := dbpkg.Client.Session.Query().Where(session.IDEQ(sessionUUID)).Only(ctxBg)
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

	// Fetch roles and permissions for the user
	ctx := ctxBg
	roles := make([]string, 0)
	permsSet := map[string]struct{}{}

	roleObjs, err := dbpkg.Client.User.Query().Where(user.IDEQ(userEnt.ID)).QueryRoles().All(ctx)
	if err == nil {
		for _, r := range roleObjs {
			roles = append(roles, r.Name)
			permObjs, err := dbpkg.Client.Role.Query().Where(role.IDEQ(r.ID)).QueryPermissions().All(ctx)
			if err == nil {
				for _, p := range permObjs {
					permsSet[p.Key] = struct{}{}
				}
			}
		}
	}

	perms := make([]string, 0, len(permsSet))
	for k := range permsSet {
		perms = append(perms, k)
	}

	c.JSON(200, gin.H{
		"id":          userEnt.ID,
		"email":       userEnt.Email,
		"username":    userEnt.Username,
		"avatar":      avatarStr,
		"roles":       roles,
		"permissions": perms,
	})
}
