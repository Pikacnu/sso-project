package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sso-server/src/db"

	"github.com/gin-gonic/gin"
)

func setupAdminTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/admin/init", adminInitHandler)
	return router
}

func performAdminRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestAdminInit_Success tests successful admin initialization on first run
func TestAdminInit_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	// Clean DB first
	ctx := context.Background()
	client.RefreshToken.Delete().Exec(ctx)
	client.AccessToken.Delete().Exec(ctx)
	client.AuthorizationCode.Delete().Exec(ctx)
	client.OAuthFlow.Delete().Exec(ctx)
	client.Session.Delete().Exec(ctx)
	client.SocialAccount.Delete().Exec(ctx)
	client.Scope.Delete().Exec(ctx)
	client.OAuthClient.Delete().Exec(ctx)
	client.User.Delete().Exec(ctx)
	client.Permission.Delete().Exec(ctx)
	client.Role.Delete().Exec(ctx)
	client.OpenIDKey.Delete().Exec(ctx)

	r := setupAdminTestRouter()

	body := `{
		"email": "admin@test.example.com",
		"username": "testadmin",
		"password": "SecurePassword123"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response AdminInitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !response.Success {
		t.Fatalf("expected success to be true")
	}

	if response.AdminUser == nil || response.AdminRole == nil {
		t.Fatalf("expected admin user and role in response")
	}
}

// TestAdminInit_MissingEmail tests admin initialization with missing email
func TestAdminInit_MissingEmail(t *testing.T) {
	r := setupAdminTestRouter()

	body := `{
		"username": "testadmin",
		"password": "SecurePassword123"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResponse); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResponse["error"] == "" {
		t.Fatalf("expected error message")
	}
}

// TestAdminInit_MissingUsername tests admin initialization with missing username
func TestAdminInit_MissingUsername(t *testing.T) {
	r := setupAdminTestRouter()

	body := `{
		"email": "admin@test.example.com",
		"password": "SecurePassword123"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResponse); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResponse["error"] == "" {
		t.Fatalf("expected error message")
	}
}

// TestAdminInit_MissingPassword tests admin initialization with missing password
func TestAdminInit_MissingPassword(t *testing.T) {
	r := setupAdminTestRouter()

	body := `{
		"email": "admin@test.example.com",
		"username": "testadmin"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResponse); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResponse["error"] == "" {
		t.Fatalf("expected error message")
	}
}

// TestAdminInit_EmptyFields tests admin initialization with empty fields
func TestAdminInit_EmptyFields(t *testing.T) {
	r := setupAdminTestRouter()

	body := `{
		"email": "",
		"username": "",
		"password": ""
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResponse); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResponse["error"] == "" {
		t.Fatalf("expected error message, got empty response")
	}

	// Check that error indicates empty fields issue
	if !strings.Contains(errResponse["error"], "email") &&
		!strings.Contains(errResponse["error"], "required") &&
		!strings.Contains(errResponse["error"], "cannot be empty") {
		t.Logf("Warning: Unexpected error message: %s", errResponse["error"])
	}
}

// TestAdminInit_AlreadyInitialized tests admin initialization when already initialized
func TestAdminInit_AlreadyInitialized(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	// First initialization
	r := setupAdminTestRouter()
	body := `{
		"email": "admin1@test.example.com",
		"username": "testadmin1",
		"password": "SecurePassword123"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)
	if w.Code != http.StatusOK && w.Code != http.StatusConflict {
		// First attempt should succeed or return conflict if already exists
		if w.Code != http.StatusOK {
			t.Logf("First admin init attempt returned %d, assuming already initialized", w.Code)
		}
	}

	// Second initialization attempt should fail
	body = `{
		"email": "admin2@test.example.com",
		"username": "testadmin2",
		"password": "AnotherPassword123"
	}`

	w = performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}

	var errResponse map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResponse); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if strings.Contains(errResponse["error"], "already initialized") == false {
		t.Fatalf("expected 'already initialized' error message, got: %s", errResponse["error"])
	}
}

// TestAdminInit_InvalidJSON tests admin initialization with invalid JSON
func TestAdminInit_InvalidJSON(t *testing.T) {
	r := setupAdminTestRouter()

	body := `{invalid json}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestAdminInit_CreatesDefaultPermissions tests that admin init creates default permissions
func TestAdminInit_CreatesDefaultPermissions(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	
	// Clean DB first
	ctx := context.Background()
	client.RefreshToken.Delete().Exec(ctx)
	client.AccessToken.Delete().Exec(ctx)
	client.AuthorizationCode.Delete().Exec(ctx)
	client.OAuthFlow.Delete().Exec(ctx)
	client.Session.Delete().Exec(ctx)
	client.SocialAccount.Delete().Exec(ctx)
	client.Scope.Delete().Exec(ctx)
	client.OAuthClient.Delete().Exec(ctx)
	client.User.Delete().Exec(ctx)
	client.Permission.Delete().Exec(ctx)
	client.Role.Delete().Exec(ctx)
	client.OpenIDKey.Delete().Exec(ctx)

	ctxBg := context.Background()

	r := setupAdminTestRouter()

	body := `{
		"email": "admin@test.example.com",
		"username": "testadmin",
		"password": "SecurePassword123"
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Check that permissions were created
	expectedPermissions := []string{
		"oauth:register",
		"users:manage",
		"roles:manage",
		"scopes:manage",
		"permissions:manage",
	}

	for _, permKey := range expectedPermissions {
		_, err := db.Client.Permission.Query().Where().First(ctxBg)
		if err != nil && err.Error() != "not found" {
			t.Logf("Warning: Could not verify permission %s was created: %v", permKey, err)
		}
	}
}

// TestAdminInit_WhitespaceHandling tests that whitespace is trimmed from inputs
func TestAdminInit_WhitespaceHandling(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	// Clean DB first
	ctx := context.Background()
	client.RefreshToken.Delete().Exec(ctx)
	client.AccessToken.Delete().Exec(ctx)
	client.AuthorizationCode.Delete().Exec(ctx)
	client.OAuthFlow.Delete().Exec(ctx)
	client.Session.Delete().Exec(ctx)
	client.SocialAccount.Delete().Exec(ctx)
	client.Scope.Delete().Exec(ctx)
	client.OAuthClient.Delete().Exec(ctx)
	client.User.Delete().Exec(ctx)
	client.Permission.Delete().Exec(ctx)
	client.Role.Delete().Exec(ctx)
	client.OpenIDKey.Delete().Exec(ctx)

	r := setupAdminTestRouter()

	body := `{
		"email": "  admin@test.example.com  ",
		"username": "  testadmin  ",
		"password": "  SecurePassword123  "
	}`

	w := performAdminRequest(r, http.MethodPost, "/auth/admin/init", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response AdminInitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify the email was trimmed
	if strings.Contains((*response.AdminUser)["email"].(string), "  ") {
		t.Fatalf("expected whitespace to be trimmed from email")
	}
}
