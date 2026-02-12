package auth

import (
	"context"
	"net/http"
	"slices"
	ent "sso-server/ent/generated"
	"sso-server/ent/generated/accesstoken"
	"sso-server/ent/generated/authorizationcode"
	"sso-server/ent/generated/oauthclient"
	"sso-server/ent/generated/oauthflow"
	"sso-server/ent/generated/refreshtoken"
	"sso-server/ent/generated/scope"
	"sso-server/src/auth"
	"sso-server/src/db"
	. "sso-server/src/db"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func authorizeHandler(ctx *gin.Context) {
	clientId := ctx.Query("client_id")
	redirectUri := ctx.Query("redirect_uri")
	scopeParam := ctx.Query("scope")
	state := ctx.Query("state")
	providor := ctx.Query("provider")

	// PKCE parameters
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")

	// OIDC nonce parameter for replay attack prevention
	nonce := ctx.Query("nonce")

	if clientId == "" || redirectUri == "" || scopeParam == "" || state == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Missing required parameters"})
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

	// Use Ent client to load OAuth client
	ctxBg := context.Background()
	clientUUID, err := uuid.Parse(clientId)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "Invalid client_id format"})
		return
	}
	oauthClientEnt, err := Client.OAuthClient.Query().Where(oauthclient.IDEQ(clientUUID)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "Invalid client_id"})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query client"})
		return
	}

	allowRedirectUri := strings.Split(oauthClientEnt.RedirectUris, ",")

	if !slices.Contains(allowRedirectUri, redirectUri) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid redirect_uri"})
		return
	}

	allowScopes := strings.Split(oauthClientEnt.AllowedScopes, ",")

	scopes := strings.Split(scopeParam, ",")

	isValidScope := true
	for _, s := range scopes {
		if !slices.Contains(allowScopes, s) {
			isValidScope = false
			break
		}
	}

	if !isValidScope {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "One or more requested scopes are invalid"})
		return
	}

	// Verify scopes exist using Ent
	scopeEntities, err := Client.Scope.Query().Where(scope.KeyIn(scopes...)).All(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}
	if len(scopeEntities) != len(scopes) {
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
	flowID := uuid.New()

	// Prepare pointer values for optional PKCE and OIDC fields
	var ccPtr *string
	var ccmPtr *string
	var noncePtr *string
	if codeChallenge != "" {
		ccPtr = &codeChallenge
	}
	if codeChallengeMethod != "" {
		ccmPtr = &codeChallengeMethod
	}
	if nonce != "" {
		noncePtr = &nonce
	}

	// Persist OAuthFlow using Ent
	_, err = Client.OAuthFlow.Create().
		SetClientID(oauthClientEnt.ID).
		SetRedirectURI(redirectUri).
		SetProvider(providor).
		SetClientState(state).
		SetScope(scopeParam).
		SetExpiresAt(time.Now().Add(5 * time.Minute)).
		SetID(flowID).
		SetNillableCodeChallenge(ccPtr).
		SetNillableCodeChallengeMethod(ccmPtr).
		SetNillableNonce(noncePtr).
		Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization code"})
		return
	}

	var redirectURL string
	flowIDStr := flowID.String()
	ctx.SetCookie("OAuth_ID", flowIDStr, int(5*time.Minute/time.Second), "/", "", false, true)
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

	ctxBg := context.Background()
	flowUUID, err := uuid.Parse(code)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid code format"})
		return
	}
	oauthFlowEnt, err := Client.OAuthFlow.Query().Where(oauthflow.IDEQ(flowUUID), oauthflow.ExpiresAtGT(time.Now())).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query oauth flow"})
		return
	}
	if oauthFlowEnt.ID == uuid.Nil || oauthFlowEnt.ClientID == uuid.Nil || state != oauthFlowEnt.ClientState {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	// Generate secure authorization code
	authCode, err := auth.GenerateSecureToken()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authorization code"})
		return
	}

	// Create AuthorizationCode using Ent
	builder := Client.AuthorizationCode.Create().
		SetClientID(oauthFlowEnt.ClientID).
		SetCode(authCode).
		SetRedirectURI(oauthFlowEnt.RedirectURI).
		SetScope(oauthFlowEnt.Scope).
		SetExpiresAt(time.Now().Add(10 * time.Minute)).
		SetNillableCodeChallenge(oauthFlowEnt.CodeChallenge).
		SetNillableCodeChallengeMethod(oauthFlowEnt.CodeChallengeMethod).
		SetNillableNonce(oauthFlowEnt.Nonce)

	if oauthFlowEnt.UserID != nil {
		builder.SetUserID(*oauthFlowEnt.UserID)
	}

	_, err = builder.Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization code"})
		return
	}
	redirectURL := oauthFlowEnt.RedirectURI + "?code=" + authCode + "&state=" + state
	ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func tokenHandler(ctx *gin.Context) {
	contentType := ctx.GetHeader("Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid content type"})
		return
	}
	grantType := ctx.PostForm("grant_type")
	sourceJWT := ctx.PostForm("source_token")

	sourceJWTClaims, err := auth.ValidateJWT(sourceJWT)
	if sourceJWT == "" || err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or missing source_token"})
		return
	}

	if grantType != "authorization_code" && grantType != "refresh_token" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported grant_type"})
		return
	}

	// Handle refresh token grant
	if grantType == "refresh_token" {
		refreshToken := ctx.PostForm("refresh_token")
		if refreshToken == "" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing refresh_token"})
			return
		}

		scope := ctx.PostForm("scope")
		ctxBg := context.Background()
		// Load refresh token via Ent
		rtEnt, err := Client.RefreshToken.Query().Where(refreshtoken.TokenEQ(refreshToken)).Only(ctxBg)
		if err != nil {
			if ent.IsNotFound(err) {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired refresh token"})
				return
			}
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query refresh token"})
			return
		}
		if rtEnt.ExpiresAt.Before(time.Now()) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired refresh token"})
			return
		}

		// Load associated access token
		atEnt, err := Client.AccessToken.Get(ctxBg, rtEnt.AccessTokenID)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid access token associated with refresh token"})
			return
		}

		// Generate new secure access token
		newAccessToken, err := auth.GenerateSecureToken()
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		// Update access token
		upd := Client.AccessToken.UpdateOneID(atEnt.ID).SetExpiresAt(time.Now().Add(1 * time.Hour)).SetToken(newAccessToken)
		if scope != "" {
			upd = upd.SetScope(scope)
		}
		atEnt, err = upd.Save(ctxBg)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update access token"})
			return
		}

		// Update refresh token's expiry and associated access token id
		_, err = Client.RefreshToken.UpdateOneID(rtEnt.ID).SetExpiresAt(time.Now().Add(24 * time.Hour)).SetAccessTokenID(atEnt.ID).Save(ctxBg)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
			return
		}

		modifiedClaims := sourceJWTClaims
		modifiedClaims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(atEnt.ExpiresAt)

		ctx.JSON(http.StatusOK, gin.H{
			"access_token":  atEnt.Token,
			"id_token":      modifiedClaims, // Optional: include if using OpenID Connect
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": rtEnt.Token,
			"scope":         atEnt.Scope,
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

	// Step 1: Verify client credentials via Ent
	ctxBg := context.Background()
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Invalid client_id format"})
		return
	}
	clientEnt, err := Client.OAuthClient.Query().Where(oauthclient.IDEQ(clientUUID), oauthclient.SecretEQ(clientSecret)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Invalid client credentials"})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query client"})
		return
	}

	// Step 2: Retrieve authorization code via Ent
	authCodeEnt, err := Client.AuthorizationCode.Query().Where(
		authorizationcode.CodeEQ(code),
		authorizationcode.ClientIDEQ(clientEnt.ID),
		authorizationcode.ExpiresAtGT(time.Now()),
	).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query authorization code"})
		return
	}
	if authCodeEnt.UserID == uuid.Nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
		return
	}

	// Step 3: Verify redirect URI matches
	if authCodeEnt.RedirectURI != redirectURI {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Redirect URI mismatch"})
		return
	}

	// Step 4: PKCE Verification (CodeChallenge is optional pointer)
	if authCodeEnt.CodeChallenge != nil && *authCodeEnt.CodeChallenge != "" {
		// If code_challenge was provided during authorize, code_verifier is required
		if codeVerifier == "" {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code_verifier required for PKCE"})
			return
		}

		// Determine method (default to plain)
		method := "plain"
		if authCodeEnt.CodeChallengeMethod != nil && *authCodeEnt.CodeChallengeMethod != "" {
			method = *authCodeEnt.CodeChallengeMethod
		}

		// Verify the code_verifier against the code_challenge
		if !auth.VerifyCodeChallenge(codeVerifier, *authCodeEnt.CodeChallenge, method) {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid code_verifier"})
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

	// Step 6: Create access token record via Ent
	atEnt, err := Client.AccessToken.Create().
		SetToken(accessToken).
		SetClientID(authCodeEnt.ClientID).
		SetUserID(authCodeEnt.UserID).
		SetExpiresAt(time.Now().Add(1 * time.Hour)).
		SetNillableScope(authCodeEnt.Scope).
		Save(ctxBg)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
		return
	}

	// Step 7: Create refresh token record via Ent
	rtEntCreated, err := Client.RefreshToken.Create().
		SetToken(refreshToken).
		SetClientID(authCodeEnt.ClientID).
		SetUserID(authCodeEnt.UserID).
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		SetNillableScope(authCodeEnt.Scope).
		SetAccessTokenID(atEnt.ID).
		Save(ctxBg)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		return
	}

	// Step 8: Revoke the authorization code (one-time use)
	_, err = Client.AuthorizationCode.UpdateOneID(authCodeEnt.ID).SetExpiresAt(time.Now()).Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke authorization code"})
		return
	}

	// Step 9: Get user info for ID token (if implementing OpenID Connect)
	userEnt, err := Client.User.Get(ctxBg, authCodeEnt.UserID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to query user"})
		return
	}

	// Prepare user info for ID token generation
	avatar := ""
	if userEnt.Avatar != nil {
		avatar = *userEnt.Avatar
	}
	userJWTInfoWarp := db.UserJWTPayload{
		ID:       userEnt.ID.String(),
		Username: userEnt.Username,
		Email:    userEnt.Email,
		Avatar:   avatar,
		EmailVerified: userEnt.EmailVerified,
	}

	// Get issuer for ID token
	protocol := "https"
	if ctx.Request.TLS == nil {
		protocol = "http"
	}
	issuer := protocol + "://" + ctx.Request.Host

	// Get nonce from authorization code if present
	nonceValue := ""
	if authCodeEnt.Nonce != nil {
		nonceValue = *authCodeEnt.Nonce
	}

	// Generate OIDC-compliant ID Token with RS256
	idToken, err := auth.GenerateIDToken(userJWTInfoWarp, authCodeEnt.ClientID.String(), nonceValue, time.Now(), issuer)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate ID token"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  atEnt.Token,
		"id_token":      idToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": rtEntCreated.Token,
		"scope":         atEnt.Scope,
	})

}

func introspectHandler(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}
	ctxBg := context.Background()
	atEnt, err := Client.AccessToken.Query().Where(accesstoken.TokenEQ(token)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query access token"})
		return
	}
	isActive := atEnt.ExpiresAt.After(time.Now())
	ctx.JSON(http.StatusOK, gin.H{
		"active":    isActive,
		"client_id": atEnt.ClientID.String(),
		"username":  atEnt.UserID.String(),
		"scope":     atEnt.Scope,
		"exp":       atEnt.ExpiresAt.Unix(),
	})
}

func revokeHandler(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}
	ctxBg := context.Background()
	atEnt, err := Client.AccessToken.Query().Where(accesstoken.TokenEQ(token)).Only(ctxBg)
	if err != nil {
		if ent.IsNotFound(err) {
			ctx.JSON(http.StatusOK, gin.H{})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query access token"})
		return
	}
	_, err = Client.AccessToken.UpdateOneID(atEnt.ID).SetExpiresAt(time.Now()).Save(ctxBg)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{})
}
