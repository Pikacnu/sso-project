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

	authorizationCodeData := AuthorizationCode{
		ID:          uuid.New().String(),
		ClientID:    oauthFlow.ClientID,
		UserID:      oauthFlow.UserID,
		Code:        uuid.New().String(),
		RedirectURI: oauthFlow.RedirectURI,
		Scope:       oauthFlow.Scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	err = DBConnection.Model(&AuthorizationCode{}).Create(&authorizationCodeData).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization code"})
		return
	}

	//redirectURL := ""
	// var user User
	// err = DBConnection.Model(&User{}).Where("id = ?", oauthFlow.UserID).Take(&user).Error
	// if err != nil {
	// 	ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "User not found"})
	// 	return
	// }

	redirectURL := oauthFlow.RedirectURI + "?code=" + oauthFlow.ID + "&state=" + oauthFlow.ClientState
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func tokenHandler(ctx *gin.Context) {
	contentType := ctx.GetHeader("Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid content type"})
		return
	}
	grantType := ctx.PostForm("grant_type")
	if grantType != "authorization_code" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported grant_type"})
		return
	}
	refreshToken := ctx.PostForm("refresh_token")
	if refreshToken != "" {
		scope := ctx.PostForm("scope")
		// Check refresh token validity
		var existingRefreshToken RefreshToken
		err := DBConnection.Model(&RefreshToken{}).Where("token = ?", refreshToken).Take(&existingRefreshToken).Error
		if err != nil || existingRefreshToken.ID == "" || existingRefreshToken.ExpiresAt.Before(time.Now()) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired refresh token"})
			return
		}
		// Get Access Token associated with refresh token
		var existingAccessToken AccessToken
		err = DBConnection.Model(&AccessToken{}).Where("id = ?", existingRefreshToken.AccessTokenID).Take(&existingAccessToken).Error
		if err != nil || existingAccessToken.ID == "" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid access token associated with refresh token"})
			return
		}
		// Update access token and refresh token
		existingAccessToken.ExpiresAt = time.Now().Add(1 * time.Hour)
		if scope != "" {
			existingAccessToken.Scope = scope
		}
		existingAccessToken.Token = uuid.New().String()
		// Update tokens in database
		err = DBConnection.Model(&AccessToken{}).Where("id = ?", existingAccessToken.ID).Updates(&existingAccessToken).Error
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update access token"})
			return
		}
		existingRefreshToken.ExpiresAt = time.Now().Add(24 * time.Hour)
		existingRefreshToken.AccessTokenID = existingAccessToken.ID
		err = DBConnection.Model(&RefreshToken{}).Where("id = ?", existingRefreshToken.ID).Updates(&existingRefreshToken).Error
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"access_token":  existingAccessToken.Token,
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": existingRefreshToken.Token,
			"scope":         existingAccessToken.Scope,
		})
		return
	}
	code := ctx.PostForm("code")
	if code == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing code"})
		return
	}
	redirectURI := ctx.PostForm("redirect_uri")
	if redirectURI == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing redirect_uri"})
		return
	}
	clientID := ctx.PostForm("client_id")
	if clientID == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing client_id"})
		return
	}
	clientSecret := ctx.PostForm("client_secret")
	if clientSecret == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing client_secret"})
		return
	}

	var authorizationCode AuthorizationCode
	err := DBConnection.Model(&AuthorizationCode{}).
		Where("code = ? AND client_id = ? AND expires_at > ? AND secret = ?", code, clientID, time.Now(), clientSecret).
		Take(&authorizationCode).Error
	if err != nil || authorizationCode.ID == "" || authorizationCode.UserID == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	// Create access Token (JWT)

	accessTokenData := AccessToken{
		Token:     uuid.New().String(),
		ClientID:  authorizationCode.ClientID,
		UserID:    authorizationCode.UserID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Scope:     authorizationCode.Scope,
	}
	err = DBConnection.Model(&AccessToken{}).Create(&accessTokenData).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
		return
	}
	refreshTokenData := RefreshToken{
		Token:         uuid.New().String(),
		ClientID:      authorizationCode.ClientID,
		UserID:        authorizationCode.UserID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Scope:         authorizationCode.Scope,
		AccessTokenID: accessTokenData.ID,
	}
	err = DBConnection.Model(&RefreshToken{}).Create(&refreshTokenData).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		return
	}

	err = DBConnection.Model(&AuthorizationCode{}).Where("id = ?", authorizationCode.ID).Update("expires_at", time.Now()).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke authorization code"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenData.Token,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": refreshTokenData.Token,
		"scope":         accessTokenData.Scope,
	})

}

func introspectHandler(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}
	var accessToken AccessToken
	err := DBConnection.Model(&AccessToken{}).Where("token = ?", token).Take(&accessToken).Error
	if err != nil || accessToken.ID == "" {
		ctx.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	isActive := accessToken.ExpiresAt.After(time.Now())
	ctx.JSON(http.StatusOK, gin.H{
		"active":    isActive,
		"client_id": accessToken.ClientID,
		"username":  accessToken.UserID,
		"scope":     accessToken.Scope,
		"exp":       accessToken.ExpiresAt.Unix(),
	})
}

func revokeHandler(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}
	var accessToken AccessToken
	err := DBConnection.Model(&AccessToken{}).Where("token = ?", token).Take(&accessToken).Error
	if err != nil || accessToken.ID == "" {
		ctx.JSON(http.StatusOK, gin.H{})
		return
	}
	err = DBConnection.Model(&AccessToken{}).Where("id = ?", accessToken.ID).Update("expires_at", time.Now()).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{})
}
