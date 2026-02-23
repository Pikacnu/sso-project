package auth

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
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

const passwordResetTTL = 24 * time.Hour

type passwordResetRequest struct {
	Email       string `json:"email" form:"email" binding:"required"`
	FlowID      string `json:"flow_id" form:"flow_id"`
	RedirectURL string `json:"redirect_url" form:"redirect_url"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token" form:"token" binding:"required"`
	NewPassword string `json:"new_password" form:"new_password" binding:"required"`
	RedirectURL string `json:"redirect_url" form:"redirect_url"`
}

type passwordResetResponse struct {
	Message string `json:"message"`
}

// @Summary Request password reset
// @Tags auth
// @Accept json
// @Produce json
// @Param body body passwordResetRequest true "Password reset request"
// @Success 200 {object} passwordResetResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/email/forgot-password [post]
func forgotPasswordHandler(ctx *gin.Context) {
	var req passwordResetRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email is required"})
		return
	}

	ctxBg := context.Background()
	userEnt, err := db.Client.User.Query().Where(user.EmailEQ(req.Email)).Only(ctxBg)
	if err != nil {
		// Avoid account enumeration.
		ctx.JSON(http.StatusOK, gin.H{"message": "If the account exists, password reset email has been sent"})
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate reset token"})
		return
	}

	expiresAt := time.Now().Add(passwordResetTTL)
	_, err = db.Client.User.UpdateOneID(userEnt.ID).
		SetPasswordResetToken(token).
		SetPasswordResetExpiresAt(expiresAt).
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to store reset token"})
		return
	}

	resetLink := buildPasswordResetLink(ctx, token, resetLinkOptions{
		FlowID:      strings.TrimSpace(req.FlowID),
		RedirectURL: strings.TrimSpace(req.RedirectURL),
	})
	if err := sendPasswordResetEmail(ctx, req.Email, resetLink); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to send reset email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

// @Summary Reset password with token
// @Tags auth
// @Accept json
// @Produce json
// @Param body body passwordResetConfirmRequest true "Password reset confirmation"
// @Success 200 {object} passwordResetResponse
// @Failure 400 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/email/reset-password [post]
func resetPasswordHandler(ctx *gin.Context) {
	var req passwordResetConfirmRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Token and new password are required"})
		return
	}

	newPassword := strings.TrimSpace(req.NewPassword)
	if newPassword == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Password cannot be empty"})
		return
	}

	ctxBg := context.Background()
	userEnt, err := db.Client.User.Query().
		Where(
			user.PasswordResetTokenEQ(req.Token),
			user.PasswordResetExpiresAtGT(time.Now()),
		).Only(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid or expired token"})
		return
	}

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to hash password"})
		return
	}

	_, err = db.Client.User.UpdateOneID(userEnt.ID).
		SetPassword(hash).
		ClearPasswordResetToken().
		ClearPasswordResetExpiresAt().
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to reset password"})
		return
	}

	// If redirect URL is provided, create session and redirect
	redirectURL := strings.TrimSpace(req.RedirectURL)
	if redirectURL != "" {
		result, err := createSessionToken(ctxBg, userEnt, ctx.GetHeader("User-Agent"), ctx.ClientIP())
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to create session"})
			return
		}
		ctx.SetCookie("session_token", result.Token, int(time.Hour*24*7/time.Second), "/", "", true, true)
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// @Summary Verify reset token and serve reset password page
// @Tags auth
// @Produce html
// @Param token query string true "Reset token"
// @Param redirect_url query string false "Redirect URL after password reset"
// @Success 200 {string} html "Reset password page"
// @Failure 400 {object} OAuthErrorResponse
// @Router /auth/reset-password [get]
func verifyResetTokenHandler(ctx *gin.Context) {
	token := ctx.Query("token")
	redirectURL := strings.TrimSpace(ctx.Query("redirect_url"))
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Missing token"})
		return
	}

	ctxBg := context.Background()
	_, err := db.Client.User.Query().
		Where(
			user.PasswordResetTokenEQ(token),
			user.PasswordResetExpiresAtGT(time.Now()),
		).Only(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid or expired token"})
		return
	}

	// Read the compiled Astro HTML file
	htmlPath := filepath.FromSlash("web/dist/reset-password/index.html")
	htmlContent, err := os.ReadFile(htmlPath)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to load reset password page"})
		return
	}

	// Inject token and redirect_url into the HTML via window object
	injectedHTML := string(htmlContent)

	// Create a script to inject the token and redirect_url into window object
	injectionScript := fmt.Sprintf(`<script>
window.__resetToken = %q;
window.__redirectUrl = %q;
</script>`, token, redirectURL)

	// Insert the script before the closing </head> tag
	injectedHTML = strings.Replace(injectedHTML, "</head>", injectionScript+"</head>", 1)

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.String(http.StatusOK, injectedHTML)
}

type resetLinkOptions struct {
	FlowID      string
	RedirectURL string
}

func buildPasswordResetLink(ctx *gin.Context, token string, opts resetLinkOptions) string {
	issuer := config.NewEnvFromEnv().Hostname
	if issuer == "" || issuer == "localhost" {
		issuer = ctx.Request.Host
	}
	protocol := "https"
	if ctx.Request.TLS == nil {
		protocol = "http"
	}

	baseURL := protocol + "://" + issuer + "/auth/reset-password"
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + "?token=" + token
	}
	query := parsed.Query()
	query.Set("token", token)
	if opts.FlowID != "" {
		query.Set("flow_id", opts.FlowID)
	}
	if opts.RedirectURL != "" {
		query.Set("redirect_url", opts.RedirectURL)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func sendPasswordResetEmail(ctx *gin.Context, to string, link string) error {
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
	message := buildPasswordResetEmailMessage(from, to, link)

	var auth smtp.Auth
	if mailCfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", mailCfg.SMTPUser, mailCfg.SMTPPassword, mailCfg.SMTPHost)
	}

	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(message)); err != nil {
		return err
	}
	return nil
}

func buildPasswordResetEmailMessage(from string, to string, link string) string {
	subject := "Reset your password"
	body, isHTML := renderPasswordResetEmailHTML(link)
	contentType := "text/plain; charset=UTF-8"
	if isHTML {
		contentType = "text/html; charset=UTF-8"
	}
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\n\r\n%s\r\n", from, to, subject, contentType, body)
}

func renderPasswordResetEmailHTML(link string) (string, bool) {
	templatePath := filepath.FromSlash("templates/email/reset_password.html")
	tplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "Click the link to reset your password: " + link, false
	}

	tpl, err := template.New("reset_password").Parse(string(tplBytes))
	if err != nil {
		return "Click the link to reset your password: " + link, false
	}

	var out strings.Builder
	if err := tpl.Execute(&out, map[string]string{"ResetLink": link}); err != nil {
		return "Click the link to reset your password: " + link, false
	}
	return out.String(), true
}
