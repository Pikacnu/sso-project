package auth

import (
	"net/http"
	"sso-server/src/auth"
	. "sso-server/src/db"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func authorizeHandler(ctx *gin.Context) {
	clientId := ctx.Query("client_id")
	redirectUri := ctx.Query("redirect_uri")
	scoope := ctx.Query("scope")
	state := ctx.Query("state")
	providor := ctx.Query("provider")

	// PKCE parameters
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")

	if clientId == "" || redirectUri == "" || scoope == "" || state == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	// Validate code_challenge_method if PKCE is used
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain" // Default to plain if not specified
		}
		if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid code_challenge_method. Must be 'plain' or 'S256'"})
			return
		}
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

	// Generate secure ID for OAuth flow
	flowID, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate flow ID"})
		return
	}

	OAuthFlowData := OAuthFlow{
		ClientID:            result.ID,
		RedirectURI:         redirectUri,
		Provider:            providor,
		ClientState:         state,
		Scope:               scoope,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		ID:                  flowID,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
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
	state := ctx.Query("state")

	if code == "" || state == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	var oauthFlow OAuthFlow
	err := DBConnection.Model(&OAuthFlow{}).Where("id = ? AND expires_at > ?", code, time.Now()).Take(&oauthFlow).Error
	if err != nil || oauthFlow.ID == "" || oauthFlow.ClientID == "" || state != oauthFlow.ClientState {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	// Generate secure authorization code
	authCode, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authorization code"})
		return
	}

	authorizationCodeData := AuthorizationCode{
		ClientID:            oauthFlow.ClientID,
		UserID:              oauthFlow.UserID,
		Code:                authCode,
		RedirectURI:         oauthFlow.RedirectURI,
		Scope:               oauthFlow.Scope,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CodeChallenge:       oauthFlow.CodeChallenge,
		CodeChallengeMethod: oauthFlow.CodeChallengeMethod,
	}

	err = DBConnection.Model(&AuthorizationCode{}).Create(&authorizationCodeData).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization code"})
		return
	}

	redirectURL := oauthFlow.RedirectURI + "?code=" + authCode + "&state=" + state
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func tokenHandler(ctx *gin.Context) {
	contentType := ctx.GetHeader("Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid content type"})
		return
	}
	grantType := ctx.PostForm("grant_type")

	// Handle refresh token grant
	if grantType == "refresh_token" {
		refreshToken := ctx.PostForm("refresh_token")
		if refreshToken == "" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing refresh_token"})
			return
		}

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

		// Generate new secure access token
		newAccessToken, err := auth.GenerateSecureToken()
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		// Update access token and refresh token
		existingAccessToken.ExpiresAt = time.Now().Add(1 * time.Hour)
		if scope != "" {
			existingAccessToken.Scope = scope
		}
		existingAccessToken.Token = newAccessToken

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
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": existingRefreshToken.Token,
			"scope":         existingAccessToken.Scope,
		})
		return
	}

	// Handle authorization code grant
	if grantType != "authorization_code" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported grant_type"})
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

	// PKCE: code_verifier is required if code_challenge was provided
	codeVerifier := ctx.PostForm("code_verifier")

	// Step 1: Verify client credentials
	var client OAuthClient
	err := DBConnection.Model(&OAuthClient{}).
		Where("client_id = ? AND secret = ?", clientID, clientSecret).
		Take(&client).Error
	if err != nil || client.ID == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials"})
		return
	}

	// Step 2: Retrieve authorization code
	var authorizationCode AuthorizationCode
	err = DBConnection.Model(&AuthorizationCode{}).
		Where("code = ? AND client_id = ? AND expires_at > ?", code, client.ID, time.Now()).
		Take(&authorizationCode).Error
	if err != nil || authorizationCode.ID == "" || authorizationCode.UserID == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	// Step 3: Verify redirect URI matches
	if authorizationCode.RedirectURI != redirectURI {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Redirect URI mismatch"})
		return
	}

	// Step 4: PKCE Verification
	if authorizationCode.CodeChallenge != "" {
		// If code_challenge was provided during authorize, code_verifier is required
		if codeVerifier == "" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "code_verifier required for PKCE"})
			return
		}

		// Verify the code_verifier against the code_challenge
		if !auth.VerifyCodeChallenge(codeVerifier, authorizationCode.CodeChallenge, authorizationCode.CodeChallengeMethod) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid code_verifier"})
			return
		}
	}

	// Step 5: Generate secure tokens
	accessToken, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Step 6: Create access token record
	accessTokenData := AccessToken{
		Token:     accessToken,
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

	// Step 7: Create refresh token record
	refreshTokenData := RefreshToken{
		Token:         refreshToken,
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

	// Step 8: Revoke the authorization code (one-time use)
	err = DBConnection.Model(&AuthorizationCode{}).Where("id = ?", authorizationCode.ID).Update("expires_at", time.Now()).Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke authorization code"})
		return
	}

	// Step 9: Return tokens
	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenData.Token,
		"token_type":    "Bearer",
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
