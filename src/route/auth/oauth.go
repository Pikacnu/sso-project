package auth

import (
	"net/http"
	. "sso-server/src/db"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func authorizeHandler(ctx *gin.Context) {
	clientId := ctx.Query("client_id")
	redirectUri := ctx.Query("redirect_uri")
	scoope := ctx.Query("scope")
	state := ctx.Query("state")
	providor := ctx.Query("provider")

	if clientId == "" || redirectUri == "" || scoope == "" || state == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	var result *OAuthClient = nil
	// Check if client ID is valid
	err := DBConnection.Model(&OAuthClient{}).Where("client_id = ?", clientId).Take(&result).Error

	if err != nil || result == nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
		return
	}

	allowRedirectUri := strings.Split(result.RedirectURIs, ",")
	isValidRedirectUri := false
	for _, uri := range allowRedirectUri {
		if uri == redirectUri {
			isValidRedirectUri = true
			break
		}
	}

	if !isValidRedirectUri {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid redirect_uri"})
		return
	}

	scoopes := strings.Split(scoope, ",")
	scoopData := &[]Scoop{}
	DBConnection.Model(&Scoop{}).Where("key IN ?", scoopes).Find(scoopData)
	if len(*scoopData) != len(scoopes) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid scope"})
		return
	}

	hostname := ctx.Request.Host
	protocol := "http"
	if ctx.Request.TLS != nil {
		protocol = "https"
	}

	if providor == "" {
		ctx.Redirect(http.StatusTemporaryRedirect, protocol+"://"+hostname+"/auth/login")
	}

	OAuthFlowData := OAuthFlow{
		ClientID:    result.ID,
		RedirectURI: redirectUri,
		Provider:    providor,
		Scope:       scoope,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		ID:          uuid.New().String(),
		//Scope:       scoope,
	}

	err = DBConnection.Model(&OAuthFlow{}).Create(&OAuthFlowData).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization code"})
		return
	}

	var redirectURL string
	ctx.SetCookie("OAuth_ID", OAuthFlowData.ID, int(5*time.Minute/time.Second), "/", "", false, true)
	switch providor {
	case "discord":
		redirectURL = protocol + "://" + hostname + "/auth/discord/login"
	case "google":
		redirectURL = protocol + "://" + hostname + "/auth/google/login"
	default:
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported provider"})
	}
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func loginPageHandler(ctx *gin.Context) {
	code := ctx.Query("code")
	state := ctx.Query("state")
	if code == "" || state == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}
	// Return login page with code and state
	// Todo: Implement HTML template return
	ctx.HTML(http.StatusOK, "login.html", gin.H{
		"code":  code,
		"state": state,
	})
}

func authCallbackHandler(ctx *gin.Context) {
	code := ctx.Query("code")
	if code == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}
	var oauthFlow OAuthFlow
	err := DBConnection.Model(&OAuthFlow{}).Where("id = ? AND expires_at > ?", code, time.Now()).Take(&oauthFlow).Error
	if err != nil || oauthFlow.ID == "" || oauthFlow.ClientID == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}
	redirectURL := ""
	var user User
	err = DBConnection.Model(&User{}).Where("id = ?", oauthFlow.UserID).Take(&user).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	// Currently, we directly redirect to the client app with code and state
	// In the future, we may implement token exchange here

	redirectURL = oauthFlow.RedirectURI + "?code=" + oauthFlow.ID + "&state=" + oauthFlow.ClientState
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func tokenHandler(ctx *gin.Context) {
	// To be implemented: Exchange authorization code for access token

}
