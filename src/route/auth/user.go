package auth

import (
	"net/http"

	"context"
	"encoding/json"
	"sso-server/src/auth"
	. "sso-server/src/db"
	. "sso-server/src/providors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

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
		OAuthConfig = DiscordOAuthConfig
	case "google":
		OAuthConfig = GoogleOAuthConfig
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
		OAuthConfig = DiscordOAuthConfig
	case "google":
		OAuthConfig = GoogleOAuthConfig
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

	var socialAcc SocialAccount
	var user User

	// 1. Check if this third-party account is already linked
	result := DBConnection.Where("provider = ? AND provider_id = ?", platform, externalID).Limit(1).Find(&socialAcc)
	if result.RowsAffected > 0 {
		// Already linked, retrieve the user
		DBConnection.First(&user, "id = ?", socialAcc.UserID)
	} else {
		// 2. Not linked, check if the email already exists in the User table
		result = DBConnection.Where("email = ?", externalEmail).Limit(1).Find(&user)
		if result.RowsAffected == 0 {
			// 3. Email does not exist either, create a new user
			user = User{
				Username: externalUsername,
				Email:    externalEmail,
				Avatar:   externalAvatar,
			}
			if err := DBConnection.Create(&user).Error; err != nil {
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
		}
		// 4. Create SocialAccount association
		socialAcc = SocialAccount{
			UserID:     user.ID,
			Provider:   platform,
			ProviderID: externalID,
		}
		if err := DBConnection.Create(&socialAcc).Error; err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
	}

	// If there is Cookie "OAuth_ID", delete it and use it to redirect
	oauthID, err := ctx.Cookie("OAuth_ID")
	if err == nil && oauthID != "" {
		ctx.SetCookie("OAuth_ID", "", -1, "/", "", false, true)
	}

	if oauthID != "" {
		userID := user.ID
		err := DBConnection.Model(&OAuthClient{}).Where("id = ? AND expires_at > ?", oauthID, time.Now()).UpdateColumn("userid", userID).Error
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		protocol := "http"
		if ctx.Request.TLS != nil {
			protocol = "https"
		}
		redirectURL = protocol + "://" + ctx.Request.Host + "/auth/callback?code=" + oauthID
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	// Create server-side session
	newSession := Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		UserAgent: ctx.GetHeader("User-Agent"),
		IPAddress: ctx.ClientIP(),
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7), // 7 days
	}
	// Create session record
	if err := DBConnection.Create(&newSession).Error; err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// Create JWT with session ID
	tokenString, err := auth.GenerateJWT(user, newSession)
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

func getDiscordUser(client *http.Client) (*DiscordUser, error) {
	response, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var discordUser DiscordUser
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

func logoutHandler(ctx *gin.Context) {
	tokenString, err := ctx.Cookie("session_token")
	if err != nil {
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	claims, err := auth.ValidateJWT(tokenString)
	if err != nil {
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	sid, ok := claims["sid"].(string)
	if !ok {
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	DBConnection.Model(&Session{}).Where("id = ?", sid).Update("is_revoked", true)
	ctx.SetCookie("session_token", "", -1, "/", "", false, true)
	ctx.Redirect(http.StatusTemporaryRedirect, "/")
}
