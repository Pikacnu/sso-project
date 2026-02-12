package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ent "sso-server/ent/generated"
	enttest "sso-server/ent/generated/enttest"
	"sso-server/src/auth"
	"sso-server/src/config"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

const defaultTestDSN = "postgres://user:pass@localhost:5433/sso_test?sslmode=disable"

func openTestDB(t *testing.T) *ent.Client {
	t.Helper()
	env := config.NewEnvFromEnv()
	dsn := env.ConnectionString
	if dsn == "" || dsn == "your-connection-string" {
		dsn = env.DatabaseURL
	}
	if dsn == "" || dsn == "postgres://user:pass@localhost:5432/sso_db" {
		dsn = defaultTestDSN
	}

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("skip integration test: cannot open db: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		t.Skipf("skip integration test: db not reachable: %v", err)
	}
	_ = sqlDB.Close()

	client := enttest.Open(t, "postgres", dsn)
	return client
}

func seedUserInfoData(t *testing.T, client *ent.Client, tokenString string, scope string) {
	t.Helper()
	ctx := context.Background()

	// Clear tables to avoid conflicts.
	_, _ = client.AccessToken.Delete().Exec(ctx)
	_, _ = client.OAuthClient.Delete().Exec(ctx)
	_, _ = client.User.Delete().Exec(ctx)

	userID := uuid.New()
	userEnt, err := client.User.Create().
		SetID(userID).
		SetUsername("testuser").
		SetEmail("user@example.com").
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
	seedUserInfoData(t, client, jwtString, "openid")

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
	seedUserInfoData(t, client, jwtString, "sso.profile")

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
	seedUserInfoData(t, client, jwtString, "")

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
