package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/user"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
)

type emailRegisterRequest struct {
	Email       string `json:"email" form:"email" binding:"required"`
	Password    string `json:"password" form:"password" binding:"required"`
	Username    string `json:"username" form:"username"`
	FlowID      string `json:"flow_id" form:"flow_id"`
	RedirectURL string `json:"redirect_url" form:"redirect_url"`
	ReturnToken bool   `json:"return_token" form:"return_token"`
}

type emailLoginRequest struct {
	Email       string `json:"email" form:"email" binding:"required"`
	Password    string `json:"password" form:"password" binding:"required"`
	FlowID      string `json:"flow_id" form:"flow_id"`
	RedirectURL string `json:"redirect_url" form:"redirect_url"`
	ReturnToken bool   `json:"return_token" form:"return_token"`
}

// @Summary Email register
// @Tags auth
// @Accept json
// @Produce json
// @Param body body emailRegisterRequest true "Email register request"
// @Success 200 {object} emailVerificationResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 409 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/email/register [post]
func emailRegisterHandler(ctx *gin.Context) {
	var req emailRegisterRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required"})
		return
	}

	email := strings.TrimSpace(req.Email)
	password := strings.TrimSpace(req.Password)
	if email == "" || password == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required"})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = email
	}

	ctxBg := context.Background()
	_, err := db.Client.User.Query().Where(user.EmailEQ(email)).Only(ctxBg)
	if err == nil {
		ctx.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "conflict", "error_description": "Email already registered"})
		return
	}
	if !ent.IsNotFound(err) {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query user"})
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to hash password"})
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate verification token"})
		return
	}

	expiresAt := time.Now().Add(emailVerificationTTL)
	_, err = db.Client.User.Create().
		SetEmail(email).
		SetUsername(username).
		SetPassword(hash).
		SetEmailVerified(false).
		SetEmailVerificationToken(token).
		SetEmailVerificationExpiresAt(expiresAt).
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to create user"})
		return
	}

	verificationLink := buildVerificationLink(ctx, token, verificationLinkOptions{
		FlowID:      strings.TrimSpace(req.FlowID),
		RedirectURL: strings.TrimSpace(req.RedirectURL),
		ReturnToken: req.ReturnToken,
	})
	if err := sendVerificationEmail(ctx, email, verificationLink); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to send verification email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// @Summary Email login
// @Tags auth
// @Accept json
// @Produce json
// @Param body body emailLoginRequest true "Email login request"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 401 {object} OAuthErrorResponse
// @Failure 403 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/email/login [post]
func emailLoginHandler(ctx *gin.Context) {
	var req emailLoginRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required"})
		return
	}

	email := strings.TrimSpace(req.Email)
	password := strings.TrimSpace(req.Password)
	if email == "" || password == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required"})
		return
	}

	ctxBg := context.Background()
	userEnt, err := db.Client.User.Query().Where(user.EmailEQ(email)).Only(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "error_description": "Invalid email or password"})
		return
	}
	if userEnt.Password == nil || !auth.CheckPasswordHash(password, *userEnt.Password) {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "error_description": "Invalid email or password"})
		return
	}

	if !userEnt.EmailVerified {
		token, err := auth.GenerateSecureToken()
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate verification token"})
			return
		}
		expiresAt := time.Now().Add(emailVerificationTTL)
		if _, err := db.Client.User.UpdateOneID(userEnt.ID).
			SetEmailVerificationToken(token).
			SetEmailVerificationExpiresAt(expiresAt).
			SetEmailVerified(false).
			Save(ctxBg); err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to store verification token"})
			return
		}

		verificationLink := buildVerificationLink(ctx, token, verificationLinkOptions{
			FlowID:      strings.TrimSpace(req.FlowID),
			RedirectURL: strings.TrimSpace(req.RedirectURL),
			ReturnToken: req.ReturnToken,
		})
		if err := sendVerificationEmail(ctx, email, verificationLink); err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to send verification email"})
			return
		}

		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "email_not_verified", "error_description": "Email not verified. Verification email sent"})
		return
	}

	flowID := strings.TrimSpace(req.FlowID)
	if flowID != "" {
		if redirected := attachUserToFlowAndRedirect(ctx, flowID, userEnt.ID); redirected {
			return
		}
	}

	result, err := createSessionToken(ctxBg, userEnt, ctx.GetHeader("User-Agent"), ctx.ClientIP())
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to create session"})
		return
	}

	ctx.SetCookie("session_token", result.Token, int(time.Hour*24*7/time.Second), "/", "", false, true)
	redirectURL := strings.TrimSpace(req.RedirectURL)
	if redirectURL != "" {
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": result.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(result.ExpiresAt).Seconds()),
	})
}
