package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/google/uuid"
)

func seedAuthorizeData(t *testing.T, client *ent.Client) (string, string) {
	t.Helper()
	ctx := context.Background()
	cleanDB(t, client)

	clientUUID := uuid.New()
	clientID := clientUUID.String()
	redirectURI := "https://app.example.com/callback"

	_, err := client.OAuthClient.Create().
		SetID(clientUUID).
		SetSecret("client-secret").
		SetRedirectUris(redirectURI).
		SetAllowedScopes("openid,sso.profile").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	_, err = client.Scope.Create().
		SetClientID(clientUUID).
		SetKey("openid").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create scope openid: %v", err)
	}
	_, err = client.Scope.Create().
		SetClientID(clientUUID).
		SetKey("sso.profile").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create scope sso.profile: %v", err)
	}

	return clientID, redirectURI
}

func seedTokenFlowData(t *testing.T, client *ent.Client, code string, codeChallenge string, method string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	cleanDB(t, client)

	userID := uuid.New()
	username := "testuser-" + uuid.New().String()[:8]
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername(username).
		SetEmail(username + "@example.com").
		SetAvatar("https://example.com/avatar.png").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	clientUUID := uuid.New()
	clientID := clientUUID.String()
	clientSecret := "client-secret"
	redirectURI := "https://app.example.com/callback"

	_, err = client.OAuthClient.Create().
		SetID(clientUUID).
		SetSecret(clientSecret).
		SetRedirectUris(redirectURI).
		SetAllowedScopes("openid,sso.profile").
		SetOwnerID(userEnt.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	_, err = client.AuthorizationCode.Create().
		SetCode(code).
		SetClientID(clientUUID).
		SetUserID(userEnt.ID).
		SetRedirectURI(redirectURI).
		SetScope("sso.profile").
		SetExpiresAt(time.Now().Add(10 * time.Minute)).
		SetNillableCodeChallenge(&codeChallenge).
		SetNillableCodeChallengeMethod(&method).
		SetNillableNonce(pointerString("nonce-123")).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create authorization code: %v", err)
	}

	return clientID, clientSecret, redirectURI
}

func pointerString(value string) *string {
	return &value
}

func seedAccessTokenData(t *testing.T, client *ent.Client, token string, expiresAt time.Time) {
	t.Helper()
	ctx := context.Background()
	cleanDB(t, client)

	userID := uuid.New()
	username := "testuser-" + uuid.New().String()[:8]
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername(username).
		SetEmail(username + "@example.com").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	clientUUID := uuid.New()
	clientEnt, err := client.OAuthClient.Create().
		SetID(clientUUID).
		SetSecret("secret").
		SetRedirectUris("https://app.example.com/callback").
		SetAllowedScopes("openid,sso.profile").
		SetOwnerID(userEnt.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	_, err = client.AccessToken.Create().
		SetToken(token).
		SetClientID(clientEnt.ID).
		SetUserID(userEnt.ID).
		SetExpiresAt(expiresAt).
		SetScope("sso.profile").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create access token: %v", err)
	}
}

func TestAuthorizeHandler_CreatesFlowAndRedirect(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	clientID, redirectURI := seedAuthorizeData(t, client)
	codeVerifier, err := auth.GenerateSecureToken()
	if err != nil {
		t.Fatalf("failed to generate code verifier: %v", err)
	}
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)

	r := setupRouter()
	r.GET("/auth/authorize", authorizeHandler)

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid,sso.profile")
	q.Set("state", "state-123")
	q.Set("provider", "discord")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("nonce", "nonce-123")

	w := performRequest(r, http.MethodGet, "/auth/authorize?"+q.Encode(), "", "")
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected status 307, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "http://example.com/auth/discord/login" {
		t.Fatalf("unexpected redirect location: %s", location)
	}

	cookies := w.Result().Cookies()
	var flowID string
	for _, c := range cookies {
		if c.Name == "OAuth_ID" {
			flowID = c.Value
			break
		}
	}
	if flowID == "" {
		t.Fatalf("missing OAuth_ID cookie")
	}

	ctx := context.Background()
	flowUUID, err := uuid.Parse(flowID)
	if err != nil {
		t.Fatalf("failed to parse flowID: %v", err)
	}
	flowEnt, err := client.OAuthFlow.Get(ctx, flowUUID)
	if err != nil {
		t.Fatalf("failed to load oauth flow: %v", err)
	}
	if flowEnt.ClientID.String() != clientID {
		t.Fatalf("client_id mismatch: got %s want %s", flowEnt.ClientID, clientID)
	}
	if flowEnt.RedirectURI != redirectURI {
		t.Fatalf("redirect_uri mismatch: got %s want %s", flowEnt.RedirectURI, redirectURI)
	}
	if flowEnt.Provider != "discord" {
		t.Fatalf("provider mismatch: got %s", flowEnt.Provider)
	}
	if flowEnt.CodeChallenge == nil || *flowEnt.CodeChallenge != codeChallenge {
		t.Fatalf("code_challenge mismatch")
	}
	if flowEnt.CodeChallengeMethod == nil || *flowEnt.CodeChallengeMethod != "S256" {
		t.Fatalf("code_challenge_method mismatch")
	}
	if flowEnt.Nonce == nil || *flowEnt.Nonce != "nonce-123" {
		t.Fatalf("nonce mismatch")
	}
}

func TestTokenHandler_AuthorizationCodeSuccess(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	cleanup := setTestKeyPair(t)
	defer cleanup()

	code := "authcode-123"
	verifier := "verifier-123"
	challenge := auth.GenerateCodeChallenge(verifier)
	clientID, clientSecret, redirectURI := seedTokenFlowData(t, client, code, challenge, "S256")

	user := db.UserJWTPayload{ID: "user-123", Email: "user@example.com", Username: "testuser"}
	session := db.SessionJWTPayload{ID: "session-123", UserID: "user-123", ExpiresAt: time.Now().Add(1 * time.Hour)}
	sourceToken, err := auth.GenerateJWT(user, session)
	if err != nil {
		t.Fatalf("failed to generate source token: %v", err)
	}

	r := setupRouter()
	r.POST("/auth/token", tokenHandler)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("source_token", sourceToken)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	w := performRequest(r, http.MethodPost, "/auth/token", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if payload["access_token"] == "" {
		t.Fatalf("missing access_token")
	}
	if payload["refresh_token"] == "" {
		t.Fatalf("missing refresh_token")
	}
	if payload["id_token"] == "" {
		t.Fatalf("missing id_token")
	}
}

func TestTokenHandler_RefreshTokenSuccess(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	cleanup := setTestKeyPair(t)
	defer cleanup()

	ctx := context.Background()
	cleanDB(t, client)

	userID := uuid.New()
	username := "testuser-" + uuid.New().String()[:8]
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername(username).
		SetEmail(username + "@example.com").
		SetAvatar("https://example.com/avatar.png").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	clientUUID := uuid.New()
	clientEnt, err := client.OAuthClient.Create().
		SetID(clientUUID).
		SetSecret("secret").
		SetRedirectUris("https://app.example.com/callback").
		SetAllowedScopes("openid,sso.profile").
		SetOwnerID(userEnt.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	atEnt, err := client.AccessToken.Create().
		SetToken("access-old").
		SetClientID(clientEnt.ID).
		SetUserID(userEnt.ID).
		SetExpiresAt(time.Now().Add(1 * time.Hour)).
		SetScope("sso.profile").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create access token: %v", err)
	}

	rtEnt, err := client.RefreshToken.Create().
		SetToken("refresh-123").
		SetClientID(clientEnt.ID).
		SetUserID(userEnt.ID).
		SetAccessTokenID(atEnt.ID).
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		SetScope("sso.profile").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	sourceUser := db.UserJWTPayload{ID: "user-123", Email: "user@example.com", Username: "testuser"}
	session := db.SessionJWTPayload{ID: "session-123", UserID: "user-123", ExpiresAt: time.Now().Add(1 * time.Hour)}
	sourceToken, err := auth.GenerateJWT(sourceUser, session)
	if err != nil {
		t.Fatalf("failed to generate source token: %v", err)
	}

	r := setupRouter()
	r.POST("/auth/token", tokenHandler)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("source_token", sourceToken)
	form.Set("refresh_token", rtEnt.Token)
	form.Set("scope", "sso.profile")

	w := performRequest(r, http.MethodPost, "/auth/token", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if payload["access_token"] == "" {
		t.Fatalf("missing access_token")
	}
	if payload["refresh_token"] == "" {
		t.Fatalf("missing refresh_token")
	}
	if payload["access_token"] == "access-old" {
		t.Fatalf("access token was not rotated")
	}
	if payload["refresh_token"] != rtEnt.Token {
		t.Fatalf("refresh token mismatch")
	}
}

func TestIntrospectHandler_ActiveToken(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	seedAccessTokenData(t, client, "access-introspect", time.Now().Add(1*time.Hour))

	r := setupRouter()
	r.POST("/auth/introspect", introspectHandler)

	form := url.Values{}
	form.Set("token", "access-introspect")

	w := performRequest(r, http.MethodPost, "/auth/introspect", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if payload["active"] != true {
		t.Fatalf("expected active=true, got %v", payload["active"])
	}
}

func TestRevokeHandler_RevokesToken(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	seedAccessTokenData(t, client, "access-revoke", time.Now().Add(1*time.Hour))

	r := setupRouter()
	r.POST("/auth/revoke", revokeHandler)
	r.POST("/auth/introspect", introspectHandler)

	form := url.Values{}
	form.Set("token", "access-revoke")
	w := performRequest(r, http.MethodPost, "/auth/revoke", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	w = performRequest(r, http.MethodPost, "/auth/introspect", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if payload["active"] != false {
		t.Fatalf("expected active=false, got %v", payload["active"])
	}
}

func TestLogoutHandler_RevokesSession(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	cleanup := setTestKeyPair(t)
	defer cleanup()

	ctx := context.Background()
	cleanDB(t, client)

	userID := uuid.New()
	username := "testuser-" + uuid.New().String()[:8]
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername(username).
		SetEmail(username + "@example.com").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	sessionID := uuid.New()
	_, err = client.Session.Create().
		SetID(sessionID).
		SetUserID(userEnt.ID).
		SetExpiresAt(time.Now().Add(1 * time.Hour)).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	jwtUser := db.UserJWTPayload{ID: userEnt.ID.String(), Email: userEnt.Email, Username: userEnt.Username}
	jwtSession := db.SessionJWTPayload{ID: sessionID.String(), UserID: userEnt.ID.String(), ExpiresAt: time.Now().Add(1 * time.Hour)}
	tokenString, err := auth.GenerateJWT(jwtUser, jwtSession)
	if err != nil {
		t.Fatalf("failed to generate jwt: %v", err)
	}

	r := setupRouter()
	r.GET("/auth/logout", logoutHandler)

	req, err := http.NewRequest(http.MethodGet, "/auth/logout", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: tokenString})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected status 307, got %d", w.Code)
	}

	updatedSession, err := client.Session.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}
	if !updatedSession.IsRevoked {
		t.Fatalf("expected session to be revoked")
	}
}
