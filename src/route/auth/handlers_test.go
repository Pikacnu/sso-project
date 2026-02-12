package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sso-server/src/auth"
	"sso-server/src/db"
	"sso-server/src/utils"

	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func performRequest(r *gin.Engine, method, path string, body string, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func parseError(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return payload
}

func setTestKeyPair(t *testing.T) func() {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	originalKeyPair := auth.CurrentKeyPair
	auth.CurrentKeyPair = &auth.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Modulus:    utils.EncodeToBase64URL(privateKey.PublicKey.N.Bytes()),
		Exponent:   utils.EncodeToBase64URL(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		Kid:        "test-kid",
	}
	return func() {
		auth.CurrentKeyPair = originalKeyPair
	}
}

func TestAuthorizeHandler_MissingParams(t *testing.T) {
	r := setupRouter()
	r.GET("/auth/authorize", authorizeHandler)

	w := performRequest(r, http.MethodGet, "/auth/authorize", "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	payload := parseError(t, w)
	if payload["error"] != "invalid_request" {
		t.Fatalf("unexpected error: %v", payload["error"])
	}
}

func TestAuthorizeHandler_InvalidCodeChallengeMethod(t *testing.T) {
	r := setupRouter()
	r.GET("/auth/authorize", authorizeHandler)

	q := url.Values{}
	q.Set("client_id", "client-123")
	q.Set("redirect_uri", "https://app.example.com/callback")
	q.Set("scope", "openid")
	q.Set("state", "state-123")
	q.Set("code_challenge", "challenge")
	q.Set("code_challenge_method", "S512")

	w := performRequest(r, http.MethodGet, "/auth/authorize?"+q.Encode(), "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	payload := parseError(t, w)
	if !strings.Contains(payload["error"], "code_challenge_method") {
		t.Fatalf("unexpected error: %v", payload["error"])
	}
}

func TestTokenHandler_InvalidContentType(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/token", tokenHandler)

	w := performRequest(r, http.MethodPost, "/auth/token", "", "text/plain")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	payload := parseError(t, w)
	if payload["error"] != "Invalid content type" {
		t.Fatalf("unexpected error: %v", payload["error"])
	}
}

func TestTokenHandler_MissingSourceToken(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/token", tokenHandler)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	w := performRequest(r, http.MethodPost, "/auth/token", form.Encode(), "application/x-www-form-urlencoded")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	payload := parseError(t, w)
	if payload["error"] != "Invalid or missing source_token" {
		t.Fatalf("unexpected error: %v", payload["error"])
	}
}

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/token", tokenHandler)
	cleanup := setTestKeyPair(t)
	defer cleanup()

	user := db.UserJWTPayload{ID: "user-123", Email: "user@example.com", Username: "testuser"}
	session := db.SessionJWTPayload{ID: "session-123", UserID: "user-123", ExpiresAt: time.Now().Add(1 * time.Hour)}
	jwtString, err := auth.GenerateJWT(user, session)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("source_token", jwtString)

	w := performRequest(r, http.MethodPost, "/auth/token", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
	payload := parseError(t, w)
	if payload["error"] != "Unsupported grant_type" {
		t.Fatalf("unexpected error: %v", payload["error"])
	}
}
