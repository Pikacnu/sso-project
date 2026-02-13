package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"sso-server/src/auth"
	dbpkg "sso-server/src/db"
	"sso-server/src/providors"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/oauthflow"
	"sso-server/ent/generated/session"
	"sso-server/ent/generated/socialaccount"
	"sso-server/ent/generated/user"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

// @Summary OAuth login
// @Tags auth
// @Produce json
// @Param platform path string true "OAuth provider (discord or google)"
// @Param redirect_url query string false "Redirect URL after login"
// @Success 302 {string} string "Redirect"
// @Failure 400 {object} OAuthErrorResponse
// @Router /auth/{platform}/login [get]
func loginHandler(ctx *gin.Context) {
	var uriBinding OAuthUriBinding
	if err := ctx.ShouldBindUri(&uriBinding); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	platform := uriBinding.Platform
	var OAuthConfig *oauth2.Config

	switch platform {
	case "discord":
		OAuthConfig = providors.DiscordOAuthConfig
	case "google":
		OAuthConfig = providors.GoogleOAuthConfig
	default:
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform"})
		return
	}

	redirectURL := ctx.Request.URL.Query().Get("redirect_url")

	CSRFToken := uuid.New().String()
	url := OAuthConfig.AuthCodeURL(CSRFToken)
	ctx.SetCookie("oauth_csrf_token", CSRFToken, 300, "/", "", false, true)
	ctx.SetCookie("redirect_url", redirectURL, 300, "/", "", false, true)
	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// @Summary OAuth callback
// @Tags auth
// @Produce json
// @Param platform path string true "OAuth provider (discord or google)"
// @Param code query string true "Authorization code"
// @Param state query string true "CSRF state"
// @Success 302 {string} string "Redirect"
// @Failure 400 {object} OAuthErrorResponse
// @Failure 403 {object} OAuthErrorResponse
// @Failure 500 {object} OAuthErrorResponse
// @Router /auth/{platform}/callback [get]
func callBackHandler(ctx *gin.Context) {
	var uriBinding OAuthUriBinding
	if err := ctx.ShouldBindUri(&uriBinding); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	code := ctx.Query("code")
	state := ctx.Query("state")
	platform := uriBinding.Platform
	csrfToken, err := ctx.Cookie("oauth_csrf_token")
	redirectURL, _ := ctx.Cookie("redirect_url")
	if redirectURL != "" {
		defer ctx.SetCookie("redirect_url", "", -1, "/", "", false, true)
	}

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing CSRF token"})
		return
	}
	if state != csrfToken {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF state"})
		return
	}

	ctx.SetCookie("oauth_csrf_token", "", -1, "/", "", false, true)

	var OAuthConfig *oauth2.Config
	switch platform {
	case "discord":
		OAuthConfig = providors.DiscordOAuthConfig
	case "google":
		OAuthConfig = providors.GoogleOAuthConfig
	default:
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform"})
		return
	}

	token, err := OAuthConfig.Exchange(context.Background(), code)

	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	client := OAuthConfig.Client(context.Background(), token)

	var externalID, externalEmail, externalUsername, externalAvatar string

	switch platform {
	case "discord":
		dUser, err := getDiscordUser(client)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		externalID = dUser.ID
		if dUser.Email != nil {
			externalEmail = *dUser.Email
		}
		externalUsername = dUser.Username
		if dUser.Avatar != nil {
			externalAvatar = *dUser.Avatar
		}
	case "google":
		gUser, err := getGoogleUser(client)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		externalID = gUser.ID
		externalEmail = gUser.Email
		externalUsername = gUser.Name
		externalAvatar = gUser.Avatar
	default:
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform"})
		return
	}

	ctxBg := context.Background()
	// 1. Check if this third-party account is already linked
	saEnt, err := dbpkg.Client.SocialAccount.Query().Where(socialaccount.ProviderEQ(platform), socialaccount.ProviderIDEQ(externalID)).Only(ctxBg)
	var userEnt *ent.User
	if err == nil {
		// Already linked, retrieve the user
		userEnt, err = dbpkg.Client.User.Get(ctxBg, saEnt.UserID)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to load user"})
			return
		}
	} else if ent.IsNotFound(err) {
		// 2. Not linked, check if the email already exists in the User table
		userEnt, err = dbpkg.Client.User.Query().Where(user.EmailEQ(externalEmail)).Only(ctxBg)
		if err != nil {
			if ent.IsNotFound(err) {
				// 3. Email does not exist either, create a new user
				userEntCreate, err := dbpkg.Client.User.Create().SetUsername(externalUsername).SetEmail(externalEmail).SetAvatar(externalAvatar).Save(ctxBg)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
					return
				}
				userEnt = userEntCreate
			} else {
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
				return
			}
		}
		// 4. Create SocialAccount association
		_, err = dbpkg.Client.SocialAccount.Create().SetUserID(userEnt.ID).SetProvider(platform).SetProviderID(externalID).Save(ctxBg)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create social account"})
			return
		}
	} else {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query social account"})
		return
	}

	// If there is Cookie "OAuth_ID", delete it and use it to redirect
	oauthID, err := ctx.Cookie("OAuth_ID")
	if err == nil && oauthID != "" {
		ctx.SetCookie("OAuth_ID", "", -1, "/", "", false, true)
	}

	if oauthID != "" {
		userID := userEnt.ID
		// oauthID is an OAuthFlow ID; load the flow and use its ClientID
		flowUUID, err := uuid.Parse(oauthID)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid OAuth flow ID format"})
			return
		}
		flowEnt, err := dbpkg.Client.OAuthFlow.Query().Where(oauthflow.IDEQ(flowUUID), oauthflow.ExpiresAtGT(time.Now())).Only(ctxBg)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query oauth flow"})
			return
		}

		// Update flow with user ID
		_, err = dbpkg.Client.OAuthFlow.UpdateOne(flowEnt).SetUserID(userID).Save(ctxBg)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update oauth flow"})
			return
		}

		protocol := "http"
		if ctx.Request.TLS != nil {
			protocol = "https"
		}
		redirectURL = protocol + "://" + ctx.Request.Host + "/auth/callback?code=" + oauthID + "&state=" + flowEnt.ClientState
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	// Create server-side session with secure UUID
	sessionUUID := uuid.New()
	sessionID := sessionUUID.String()

	exp := time.Now().Add(time.Hour * 24 * 7) // 7 days
	// Create session record in Ent
	if _, err := dbpkg.Client.Session.Create().SetID(sessionUUID).SetUserID(userEnt.ID).SetUserAgent(ctx.GetHeader("User-Agent")).SetIPAddress(ctx.ClientIP()).SetExpiresAt(exp).Save(ctxBg); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Create JWT with session ID using ent data mapped to JWT payload types
	avatarStr := ""
	if userEnt.Avatar != nil {
		avatarStr = *userEnt.Avatar
	}
	dbUser := dbpkg.UserJWTPayload{ID: userEnt.ID.String(), Email: userEnt.Email, Username: userEnt.Username, Avatar: avatarStr, EmailVerified: userEnt.EmailVerified}
	dbSession := dbpkg.SessionJWTPayload{ID: sessionID, UserID: userEnt.ID.String(), ExpiresAt: exp}
	tokenString, err := auth.GenerateJWT(dbUser, dbSession)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	ctx.SetCookie("session_token", tokenString, int(time.Hour*24*7/time.Second), "/", "", false, true)
	if redirectURL != "" {
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
	} else {
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
	}
}

func getDiscordUser(client *http.Client) (*providors.DiscordUser, error) {
	response, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var discordUser providors.DiscordUser
	if err := json.NewDecoder(response.Body).Decode(&discordUser); err != nil {
		return nil, err
	}
	return &discordUser, nil
}

func getGoogleUser(client *http.Client) (*ReturnedDefaultUser, error) {
	service, err := people.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	person, err := service.People.Get("people/me").PersonFields("names,emailAddresses,photos").Do()
	if err != nil {
		return nil, err
	}
	var googleUser ReturnedDefaultUser
	if len(person.Names) > 0 {
		googleUser.Name = person.Names[0].DisplayName
		googleUser.ID = person.Names[0].Metadata.Source.Id
	}
	if len(person.EmailAddresses) > 0 {
		googleUser.Email = person.EmailAddresses[0].Value
	}
	if len(person.Photos) > 0 {
		googleUser.Avatar = person.Photos[0].Url
	}
	return &googleUser, nil
}

// @Summary Logout
// @Tags auth
// @Produce json
// @Param id_token_hint query string false "ID token hint"
// @Param post_logout_redirect_uri query string false "Post logout redirect URI"
// @Param state query string false "State"
// @Success 302 {string} string "Redirect"
// @Router /auth/logout [get]
func logoutHandler(ctx *gin.Context) {
	// OIDC end_session endpoint parameters
	idTokenHint := ctx.Query("id_token_hint")
	postLogoutRedirectURI := ctx.Query("post_logout_redirect_uri")
	state := ctx.Query("state")

	// Try to get session token from cookie (for browser-based logout)
	tokenString, err := ctx.Cookie("session_token")
	if err != nil && idTokenHint == "" {
		// No token provided, redirect to home
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	// Validate token and revoke session
	if tokenString != "" {
		claims, err := auth.ValidateJWT(tokenString)
		if err == nil {
			sid := claims.Sid
			if sid != "" {
				// Parse string session ID to UUID
				sessionUUID, err := uuid.Parse(sid)
				if err == nil {
					dbpkg.Client.Session.Update().Where(session.IDEQ(sessionUUID)).SetIsRevoked(true).Save(context.Background())
				}
			}
		}
		// Clear session cookie
		ctx.SetCookie("session_token", "", -1, "/", "", false, true)
	}

	// OIDC-compliant redirect
	if postLogoutRedirectURI != "" {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			redirectURL += "?state=" + state
		}
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	// Default redirect to home
	ctx.Redirect(http.StatusTemporaryRedirect, "/")
}
