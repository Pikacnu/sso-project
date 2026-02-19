package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/src/auth"
	"sso-server/src/config"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func seedUserInfoData(t *testing.T, client *ent.Client, tokenString string, scope string, emailVerified bool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	cleanDB(t, client)

	userID := uuid.New()
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername("testuser").
		SetEmail("user@example.com").
		SetEmailVerified(emailVerified).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	clientEnt, err := client.OAuthClient.Create().
		SetSecret("secret").
		SetRedirectUris("https://app.example.com/callback").
		SetAllowedScopes("openid sso.profile").
		SetOwnerID(userEnt.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	_, err = client.AccessToken.Create().
		SetToken(tokenString).
		SetExpiresAt(time.Now().Add(1 * time.Hour)).
		SetScope(scope).
		SetClientID(clientEnt.ID).
		SetUserID(userEnt.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create access token: %v", err)
	}

	return userEnt.ID, clientEnt.ID
}

func newHS256Token(t *testing.T, userID string, email string) string {
	t.Helper()
	secret := config.NewEnvFromEnv().JWTSecret

	claims := auth.CustomClaims{
		Sub:   userID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return jwtString
}

func performUserInfoRequest(r *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestUserInfoHandler_MissingAuthorization(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", w.Code)
	}
}

func TestUserInfoHandler_InvalidToken(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, "invalid-token")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", w.Code)
	}
}

func TestUserInfoHandler_InsufficientScope(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	jwtString := newHS256Token(t, "user-123", "user@example.com")
	seedUserInfoData(t, client, jwtString, "openid", false)

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, jwtString)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
}

func TestUserInfoHandler_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	jwtString := newHS256Token(t, "user-123", "user@example.com")
	seedUserInfoData(t, client, jwtString, "sso.profile", true)

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, jwtString)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if payload["sub"] != "user-123" {
		t.Fatalf("unexpected sub: %v", payload["sub"])
	}
	if payload["email"] != "user@example.com" {
		t.Fatalf("unexpected email: %v", payload["email"])
	}
	if payload["email_verified"] != true {
		t.Fatalf("unexpected email_verified: %v", payload["email_verified"])
	}

	// exp can be a nested object depending on JSON marshal; just ensure it's present.
	if _, ok := payload["exp"]; !ok {
		t.Fatalf("missing exp in response")
	}
}

func TestUserInfoHandler_MissingScopeToken(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	jwtString := newHS256Token(t, "user-123", "user@example.com")
	seedUserInfoData(t, client, jwtString, "", false)

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, jwtString)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Insufficient scope") {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
}

func TestUserInfoHandler_ExternalScopeSuccess(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"level": 42, "vip_status": true}`))
	}))
	defer server.Close()

	if err := os.Setenv("GAME_API_KEY", "test-key"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer os.Unsetenv("GAME_API_KEY")

	jwtString := newHS256Token(t, "user-123", "user@example.com")
	_, clientID := seedUserInfoData(t, client, jwtString, "sso.profile,game_stats", true)

	ctx := context.Background()
	_, err := client.Scope.Create().
		SetClientID(clientID).
		SetKey("game_stats").
		SetIsExternal(true).
		SetExternalEndpoint(server.URL + "/user/{user_id}").
		SetExternalMethod("GET").
		SetAuthType("API_KEY").
		SetAuthSecretEnv("GAME_API_KEY").
		SetJSONSchema(`{"level":{"type":"integer"},"vip_status":{"type":"boolean"}}`).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create external scope: %v", err)
	}

	r := setupRouter()
	r.GET("/auth/userinfo", userInfoHandler)

	w := performUserInfoRequest(r, jwtString)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if _, ok := payload["_errors"]; ok {
		t.Fatalf("unexpected _errors: %v", payload["_errors"])
	}

	statsRaw, ok := payload["game_stats"].(map[string]any)
	if !ok {
		t.Fatalf("missing game_stats in response")
	}
	if statsRaw["level"] != float64(42) {
		t.Fatalf("unexpected level: %v", statsRaw["level"])
	}
	if statsRaw["vip_status"] != true {
		t.Fatalf("unexpected vip_status: %v", statsRaw["vip_status"])
	}
}
