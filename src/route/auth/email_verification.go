package auth

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sso-server/ent/generated/user"
	"sso-server/src/auth"
	"sso-server/src/config"
	"sso-server/src/db"
	"sso-server/src/middleware"

	"github.com/gin-gonic/gin"
)

const emailVerificationTTL = 24 * time.Hour

type emailVerificationRequest struct {
	Email string `json:"email" form:"email" binding:"required"`
}

type emailVerificationResponse struct {
	Message string `json:"message"`
}

// @Summary Request email verification
// @Tags auth
// @Accept json
// @Produce json
// @Param body body emailVerificationRequest true "Email verification request"
// @Success 200 {object} emailVerificationResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/verify-email/request [post]
func requestEmailVerificationHandler(ctx *gin.Context) {
	var req emailVerificationRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email is required"})
		return
	}

	ctxBg := context.Background()
	userEnt, err := db.Client.User.Query().Where(user.EmailEQ(req.Email)).Only(ctxBg)
	if err != nil {
		// Avoid account enumeration.
		ctx.JSON(http.StatusOK, gin.H{"message": "If the account exists, verification email has been sent"})
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate verification token"})
		return
	}

	expiresAt := time.Now().Add(emailVerificationTTL)
	_, err = db.Client.User.UpdateOneID(userEnt.ID).
		SetEmailVerificationToken(token).
		SetEmailVerificationExpiresAt(expiresAt).
		SetEmailVerified(false).
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to store verification token"})
		return
	}

	verificationLink := buildVerificationLink(ctx, token)
	if err := sendVerificationEmail(ctx, req.Email, verificationLink); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to send verification email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// @Summary Verify email
// @Tags auth
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} emailVerificationResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/verify-email [get]
func verifyEmailHandler(ctx *gin.Context) {
	token := ctx.Query("token")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Missing token"})
		return
	}

	ctxBg := context.Background()
	userEnt, err := db.Client.User.Query().
		Where(
			user.EmailVerificationTokenEQ(token),
			user.EmailVerificationExpiresAtGT(time.Now()),
		).Only(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid or expired token"})
		return
	}

	_, err = db.Client.User.UpdateOneID(userEnt.ID).
		SetEmailVerified(true).
		ClearEmailVerificationToken().
		ClearEmailVerificationExpiresAt().
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to verify email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Email verified"})
}

func buildVerificationLink(ctx *gin.Context, token string) string {
	issuer := config.NewEnvFromEnv().Hostname
	if issuer == "" || issuer == "localhost" {
		issuer = ctx.Request.Host
	}
	protocol := "https"
	if ctx.Request.TLS == nil {
		protocol = "http"
	}
	return protocol + "://" + issuer + "/auth/verify-email?token=" + token
}

func sendVerificationEmail(ctx *gin.Context, to string, link string) error {
	mailCfg := middleware.GetEmailConfigFromContext(ctx)
	if mailCfg == nil {
		mailCfg = &middleware.EmailConfig{
			From:         config.NewEnvFromEnv().EmailFrom,
			SMTPHost:     config.NewEnvFromEnv().EmailSMTPHost,
			SMTPPort:     config.NewEnvFromEnv().EmailSMTPPort,
			SMTPUser:     config.NewEnvFromEnv().EmailSMTPUser,
			SMTPPassword: config.NewEnvFromEnv().EmailSMTPPassword,
		}
	}

	if mailCfg.SMTPHost == "" {
		log.Printf("email not sent (SMTP not configured): to=%s link=%s", to, link)
		return nil
	}

	from := mailCfg.From
	if from == "" {
		from = "no-reply@example.com"
	}

	addr := fmt.Sprintf("%s:%d", mailCfg.SMTPHost, mailCfg.SMTPPort)
	message := buildVerificationEmailMessage(from, to, link)

	var auth smtp.Auth
	if mailCfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", mailCfg.SMTPUser, mailCfg.SMTPPassword, mailCfg.SMTPHost)
	}

	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(message)); err != nil {
		return err
	}
	return nil
}

func buildVerificationEmailMessage(from string, to string, link string) string {
	subject := "Verify your email"
	body, isHTML := renderVerificationEmailHTML(link)
	contentType := "text/plain; charset=UTF-8"
	if isHTML {
		contentType = "text/html; charset=UTF-8"
	}
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\n\r\n%s\r\n", from, to, subject, contentType, body)
}

func renderVerificationEmailHTML(link string) (string, bool) {
	templatePath := filepath.FromSlash("templates/email/verify_email.html")
	tplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "Click the link to verify your email: " + link, false
	}

	tpl, err := template.New("verify_email").Parse(string(tplBytes))
	if err != nil {
		return "Click the link to verify your email: " + link, false
	}

	var out strings.Builder
	if err := tpl.Execute(&out, map[string]string{"VerifyLink": link}); err != nil {
		return "Click the link to verify your email: " + link, false
	}
	return out.String(), true
}
