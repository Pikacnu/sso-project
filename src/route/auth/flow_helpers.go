package auth

import (
	"context"
	"net/http"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/oauthflow"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func attachUserToFlowAndRedirect(ctx *gin.Context, flowID string, userID uuid.UUID) bool {
	flowUUID, err := uuid.Parse(flowID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid flow_id format"})
		return true
	}

	ctxBg := context.Background()
	flowEnt, err := db.Client.OAuthFlow.Query().Where(oauthflow.IDEQ(flowUUID), oauthflow.ExpiresAtGT(time.Now())).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid or expired flow"})
			return true
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query oauth flow"})
		return true
	}

	if _, err := db.Client.OAuthFlow.UpdateOneID(flowEnt.ID).SetUserID(userID).Save(ctxBg); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to update oauth flow"})
		return true
	}

	protocol := "http"
	if ctx.Request.TLS != nil {
		protocol = "https"
	}
	redirectURL := protocol + "://" + ctx.Request.Host + "/auth/callback?code=" + flowID + "&state=" + flowEnt.ClientState
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
	return true
}
