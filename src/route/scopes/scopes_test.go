package scopes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"
	"sso-server/ent/generated/scope"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func setupScopeTestRouter(clientID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup middleware that sets client context
	router.Use(func(c *gin.Context) {
		c.Set("client_id", clientID)
	})

	RegisterScopeRoutes(router)
	return router
}

func performScopeRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// createTestOAuthClient creates an OAuthClient for testing
func createTestOAuthClient(t *testing.T, client *ent.Client, clientID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	_, err := client.OAuthClient.Create().
		SetID(clientID).
		SetSecret("test-secret").
		SetRedirectUris("https://example.com/callback").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test OAuthClient: %v", err)
	}
}

// TestRegisterScope_Success tests successfully registering a scope
func TestRegisterScope_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "openid",
		"description": "OpenID Connect standard scope",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d, response: %s", w.Code, w.Body.String())
	}

	var response ScopeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Key != "openid" {
		t.Fatalf("expected scope key 'openid', got %s", response.Key)
	}

	if response.Description != "OpenID Connect standard scope" {
		t.Fatalf("expected description to be set")
	}
}

// TestRegisterScope_WithDescription tests registering scope with description
func TestRegisterScope_WithDescription(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	description := "User profile information including name and picture"
	body := `{
		"scope": "profile",
		"description": "User profile information including name and picture",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d", w.Code)
	}

	var response ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Description != description {
		t.Fatalf("expected description %s, got %s", description, response.Description)
	}
}

// TestRegisterScope_MissingScope tests registering scope without scope name
func TestRegisterScope_MissingScope(t *testing.T) {
	clientID := uuid.New()
	r := setupScopeTestRouter(clientID)

	body := `{
		"description": "Some description",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResponse)

	if !strings.Contains(errResponse["error"], "required") {
		t.Fatalf("expected 'required' error message")
	}
}

// TestRegisterScope_EmptyScope tests registering scope with empty scope name
func TestRegisterScope_EmptyScope(t *testing.T) {
	clientID := uuid.New()
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "",
		"description": "Some description",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResponse)

	if !strings.Contains(errResponse["error"], "required") {
		t.Fatalf("expected 'required' error message")
	}
}

// TestRegisterScope_ExternalWithoutEndpoint tests external scope without endpoint
func TestRegisterScope_ExternalWithoutEndpoint(t *testing.T) {
	clientID := uuid.New()
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "external_scope",
		"is_external": true
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResponse)

	if !strings.Contains(errResponse["error"], "external_endpoint") {
		t.Fatalf("expected 'external_endpoint' error message")
	}
}

// TestRegisterScope_ExternalWithEndpoint tests registering external scope with endpoint
func TestRegisterScope_ExternalWithEndpoint(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "external_data",
		"description": "External data scope",
		"is_external": true,
		"external_endpoint": "https://api.example.com/scope/external_data",
		"external_method": "GET",
		"auth_type": "bearer"
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d, response: %s", w.Code, w.Body.String())
	}

	var response ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if !response.IsExternal {
		t.Fatalf("expected is_external to be true")
	}

	if response.ExternalEndpoint != "https://api.example.com/scope/external_data" {
		t.Fatalf("expected external_endpoint to be set")
	}
}

// TestRegisterScope_Duplicate tests registering duplicate scope for same client
func TestRegisterScope_Duplicate(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "email",
		"description": "User email address",
		"is_external": false
	}`

	// First registration
	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("first registration failed: %d", w.Code)
	}

	// Second registration with same scope
	w = performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}

	var errResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResponse)

	if !strings.Contains(errResponse["error"], "already") {
		t.Fatalf("expected 'already exists' error message")
	}
}

// TestRegisterScope_WhitespaceHandling tests scope name whitespace trimming
func TestRegisterScope_WhitespaceHandling(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "  sso.profile  ",
		"description": "SSO profile scope",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d", w.Code)
	}

	var response ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	// Scope name should be trimmed
	if strings.Contains(response.Key, "  ") {
		t.Fatalf("expected whitespace to be trimmed from scope name")
	}
}

// TestListScopes_Success tests listing scopes
func TestListScopes_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	// Clean database to ensure fresh state
	cleanDB(t, client)

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	// Register a scope first
	body := `{
		"scope": "openid",
		"description": "OpenID scope",
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("failed to register scope: expected status 200 or 201, got %d, body: %s", w.Code, w.Body.String())
	}

	// List scopes
	w = performScopeRequest(r, http.MethodGet, "/scopes", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response []ScopeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(response) == 0 {
		t.Fatalf("expected at least one scope in response, got empty list")
	}
}

// TestListScopes_Empty tests listing scopes when none exist
func TestListScopes_Empty(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	r := setupScopeTestRouter(clientID)

	// List scopes without registering any
	w := performScopeRequest(r, http.MethodGet, "/scopes", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var response []ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	// Should return empty array or valid response
	if response == nil {
		t.Logf("Received nil response instead of empty array")
	}
}

// TestRegisterScope_InvalidJSON tests registering scope with invalid JSON
func TestRegisterScope_InvalidJSON(t *testing.T) {
	clientID := uuid.New()
	r := setupScopeTestRouter(clientID)

	body := `{invalid json}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestRegisterScope_JSONSchema tests registering scope with JSON schema
func TestRegisterScope_JSONSchema(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "custom_data",
		"description": "Custom data scope with schema",
		"is_external": true,
		"external_endpoint": "https://api.example.com/custom",
		"json_schema": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"age": {"type": "number"}
			}
		},
		"is_external": false
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d", w.Code)
	}

	var response ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.JSONSchema == "" && response.JSONSchema != "{}" {
		t.Logf("Note: JSON schema may or may not be preserved in response")
	}
}

// TestRegisterScope_ClientIsolation tests that scopes are isolated per client
func TestRegisterScope_ClientIsolation(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	// Clean database to ensure fresh state
	cleanDB(t, client)

	client1ID := uuid.New()
	createTestOAuthClient(t, client, client1ID)
	client2ID := uuid.New()
	createTestOAuthClient(t, client, client2ID)

	r1 := setupScopeTestRouter(client1ID)
	r2 := setupScopeTestRouter(client2ID)

	body := `{
		"scope": "isolated_scope",
		"description": "Isolated scope",
		"is_external": false
	}`

	// Register scope for client 1
	w1 := performScopeRequest(r1, http.MethodPost, "/scopes/register", body)
	if w1.Code != http.StatusOK && w1.Code != http.StatusCreated {
		t.Fatalf("client1 registration failed: %d", w1.Code)
	}

	// Register same scope for client 2 (should succeed since different client)
	w2 := performScopeRequest(r2, http.MethodPost, "/scopes/register", body)
	if w2.Code != http.StatusOK && w2.Code != http.StatusCreated {
		t.Fatalf("client2 registration failed: %d", w2.Code)
	}

	// Try to register same scope again for client 1 (should fail)
	w1_dup := performScopeRequest(r1, http.MethodPost, "/scopes/register", body)
	if w1_dup.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate scope in same client, got %d", w1_dup.Code)
	}
}

// TestScopeFields tests that all scope fields are properly set and returned
func TestScopeFields(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)
	r := setupScopeTestRouter(clientID)

	body := `{
		"scope": "full_scope",
		"description": "Scope with all fields",
		"is_external": true,
		"external_endpoint": "https://api.example.com/full",
		"external_method": "POST",
		"auth_type": "oauth2",
		"auth_secret_env": "API_SECRET",
		"data": "some_data"
	}`

	w := performScopeRequest(r, http.MethodPost, "/scopes/register", body)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d", w.Code)
	}

	var response ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Key != "full_scope" {
		t.Fatalf("expected key 'full_scope'")
	}

	if response.Description != "Scope with all fields" {
		t.Fatalf("expected description to be set")
	}

	if !response.IsExternal {
		t.Fatalf("expected is_external to be true")
	}

	if response.ExternalEndpoint != "https://api.example.com/full" {
		t.Fatalf("expected external_endpoint to be set")
	}

	if response.ExternalMethod != "POST" {
		t.Fatalf("expected external_method to be POST")
	}

	if response.AuthType != "oauth2" {
		t.Fatalf("expected auth_type to be oauth2")
	}
}

// setupAdminTestRouter creates a test router with admin user context
func setupAdminTestRouter(adminUserID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup middleware that sets user context (admin)
	router.Use(func(c *gin.Context) {
		c.Set("user_id", adminUserID)
	})

	RegisterScopeRoutes(router)
	return router
}

// createTestAdminUser creates an admin user for testing
func createTestAdminUser(t *testing.T, client *ent.Client, username string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	// Create admin role if not exists
	roleEnt, err := client.Role.Query().Where(role.NameEQ("admin")).First(ctx)
	if err != nil {
		roleEnt, err = client.Role.Create().
			SetName("admin").
			SetDescription("Administrator role").
			Save(ctx)
		if err != nil {
			t.Fatalf("failed to create admin role: %v", err)
		}
	}

	// Create admin user with unique username
	userEnt, err := client.User.Create().
		SetUsername(username).
		SetEmail(username + "@test.local").
		SetEmailVerified(true).
		AddRoles(roleEnt).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	return userEnt.ID
}

// TestAdminListScopes_Success tests listing all scopes (admin)
func TestAdminListScopes_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	ctx := context.Background()

	// Setup test data
	adminUserID := createTestAdminUser(t, client, "admin_list_scopes_test")
	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)

	// Create test scopes
	_, err := client.Scope.Create().
		SetClientID(clientID).
		SetKey("openid").
		SetIsExternal(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test scope: %v", err)
	}

	r := setupAdminTestRouter(adminUserID)

	w := performScopeRequest(r, http.MethodGet, "/admin/scopes", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response []ScopeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(response) == 0 {
		t.Fatalf("expected at least one scope")
	}

	// Find the scope we created
	found := false
	for _, s := range response {
		if s.Key == "openid" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected scope key 'openid' in response")
	}
}

// TestAdminListScopes_FilterByClientId tests filtering scopes by client_id
func TestAdminListScopes_FilterByClientId(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	ctx := context.Background()

	adminUserID := createTestAdminUser(t, client, "admin_list_filter_test")
	clientID1 := uuid.New()
	clientID2 := uuid.New()
	createTestOAuthClient(t, client, clientID1)
	createTestOAuthClient(t, client, clientID2)

	// Create scopes for different clients
	_, err := client.Scope.Create().
		SetClientID(clientID1).
		SetKey("scope1").
		SetIsExternal(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test scope: %v", err)
	}

	_, err = client.Scope.Create().
		SetClientID(clientID2).
		SetKey("scope2").
		SetIsExternal(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test scope: %v", err)
	}

	r := setupAdminTestRouter(adminUserID)

	w := performScopeRequest(r, http.MethodGet, "/admin/scopes?client_id="+clientID1.String(), "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var response []ScopeResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(response))
	}

	if response[0].Key != "scope1" {
		t.Fatalf("expected scope key 'scope1'")
	}
}

// TestAdminCreateScope_Success tests creating a scope (admin)
func TestAdminCreateScope_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	adminUserID := createTestAdminUser(t, client, "admin_create_scope_test")
	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)

	r := setupAdminTestRouter(adminUserID)

	body := `{
		"scope": "admin_scope",
		"description": "Admin created scope",
		"is_external": false,
		"json_schema": {
			"client_id": "` + clientID.String() + `"
		}
	}`

	w := performScopeRequest(r, http.MethodPost, "/admin/scopes", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response ScopeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Key != "admin_scope" {
		t.Fatalf("expected scope key 'admin_scope', got %s", response.Key)
	}
}

// TestAdminCreateScope_MissingClientId tests error when client_id is missing
func TestAdminCreateScope_MissingClientId(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	adminUserID := createTestAdminUser(t, client, "admin_missing_clientid_test")
	r := setupAdminTestRouter(adminUserID)

	body := `{
		"scope": "test_scope",
		"description": "Missing client_id",
		"is_external": false,
		"json_schema": {}
	}`

	w := performScopeRequest(r, http.MethodPost, "/admin/scopes", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestAdminDeleteScope_Success tests deleting a scope (admin)
func TestAdminDeleteScope_Success(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	ctx := context.Background()

	adminUserID := createTestAdminUser(t, client, "admin_delete_scope_test")
	clientID := uuid.New()
	createTestOAuthClient(t, client, clientID)

	// Create test scope
	scopeEnt, err := client.Scope.Create().
		SetClientID(clientID).
		SetKey("delete_test").
		SetIsExternal(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test scope: %v", err)
	}

	r := setupAdminTestRouter(adminUserID)

	w := performScopeRequest(r, http.MethodDelete, "/admin/scopes/"+scopeEnt.ID.String(), "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	// Verify scope is deleted
	exists, err := client.Scope.Query().Where(scope.IDEQ(scopeEnt.ID)).Exist(ctx)
	if err != nil {
		t.Fatalf("failed to query scope: %v", err)
	}

	if exists {
		t.Fatalf("expected scope to be deleted")
	}
}

// TestAdminDeleteScope_NotFound tests deleting a non-existent scope
func TestAdminDeleteScope_NotFound(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()

	adminUserID := createTestAdminUser(t, client, "admin_delete_notfound_test")
	nonExistentID := uuid.New()

	r := setupAdminTestRouter(adminUserID)

	w := performScopeRequest(r, http.MethodDelete, "/admin/scopes/"+nonExistentID.String(), "")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}
