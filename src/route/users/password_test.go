package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func setupUserTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup middleware that sets admin role context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uuid.New().String())
		c.Set("roles", []string{"admin"})
	})

	RegisterUserRoutes(router)
	return router
}

func setupUserValidationRouter() *gin.Engine {
	// Light router for validation tests only - no role checking
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Only register handlers directly without middleware
	router.POST("/users", createUserHandler)
	router.PUT("/users/:id/password", changePasswordHandler)
	return router
}

// createTestAdminUser creates an admin user in the database for testing
func createTestAdminUser(t *testing.T, client *ent.Client) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	// Create admin role if it doesn't exist
	adminRole, err := client.Role.Query().Where(role.NameEQ("admin")).First(ctx)
	if err != nil {
		adminRole, err = client.Role.Create().SetName("admin").Save(ctx)
		if err != nil {
			t.Fatalf("failed to create admin role: %v", err)
		}
	}

	// Create admin user with unique username
	adminID := uuid.New()
	username := "testadmin-" + uuid.New().String()[:8]

	// Create user first, then add roles
	user, err := client.User.Create().
		SetID(adminID).
		SetUsername(username).
		SetEmail(username + "@test.example.com").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create test admin user: %v", err)
	}

	// Add role to user
	if adminRole != nil {
		_, err = client.User.UpdateOneID(adminID).AddRoles(adminRole).Save(ctx)
		if err != nil {
			t.Fatalf("failed to add admin role to user: %v", err)
		}
	}

	return user.ID
}

// setupUserTestRouterWithAdmin creates a router with an admin user context
func setupUserTestRouterWithAdmin(adminID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup middleware that sets admin role context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", adminID.String())
		c.Set("roles", []string{"admin"})
	})

	RegisterUserRoutes(router)
	return router
}

func performUserRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestCreateUserWithPassword tests creating a user with password
func TestCreateUserWithPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	// Generate unique test user
	testUserID := uuid.New().String()[:8]
	uniqueEmail := "user-" + testUserID + "@test.example.com"
	uniqueUsername := "testuser-" + testUserID
	password := "SecurePassword123"
	body := fmt.Sprintf(`{
		"email": "%s",
		"username": "%s",
		"password": "%s"
	}`, uniqueEmail, uniqueUsername, password)

	w := performUserRequest(r, http.MethodPost, "/users", body)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("expected status 201 or 200, got %d, response: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	userID, ok := response["id"].(string)
	if !ok {
		t.Fatalf("expected user id in response")
	}

	// Verify password was hashed by trying to check it
	ctx := context.Background()
	user, err := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("failed to get user from database: %v", err)
	}

	if user.Password == nil || *user.Password == "" {
		t.Fatalf("expected password to be hashed")
	}

	// Verify the password is different from the input (it should be hashed)
	if *user.Password == password {
		t.Fatalf("password should be hashed, not stored in plain text")
	}

	// Verify we can check the password
	if !auth.CheckPasswordHash(password, *user.Password) {
		t.Fatalf("password check failed, password was not properly hashed")
	}
}

// TestCreateUserWithoutPassword tests creating a user without password
func TestCreateUserWithoutPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	body := `{
		"email": "user2@test.example.com",
		"username": "testuser2"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", body)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("expected status 201 or 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	userID, ok := response["id"].(string)
	if !ok {
		t.Fatalf("expected user id in response")
	}

	// Verify user was created without password
	ctx := context.Background()
	user, err := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("failed to get user from database: %v", err)
	}

	if user.Password != nil {
		t.Fatalf("expected password to be empty when not provided")
	}
}

// TestCreateUserMissingEmail tests creating a user without email
func TestCreateUserMissingEmail(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	r := setupUserValidationRouter()

	body := `{
		"username": "testuser",
		"password": "SecurePassword123"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateUserMissingUsername tests creating a user without username
func TestCreateUserMissingUsername(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	r := setupUserValidationRouter()

	body := `{
		"email": "user@test.example.com",
		"password": "SecurePassword123"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestUpdateUserPassword tests updating a user's password
func TestUpdateUserPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()
	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	// First create a user
	createBody := `{
		"email": "user3@test.example.com",
		"username": "testuser3",
		"password": "OriginalPassword123"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", createBody)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("failed to create user: %d", w.Code)
	}

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	userID := createResponse["id"].(string)

	// Now update the password
	updateBody := `{
		"password": "NewPassword456"
	}`

	w = performUserRequest(r, http.MethodPut, "/users/"+userID, updateBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	// Verify the password was updated
	user, err := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("failed to get user from database: %v", err)
	}

	if user.Password == nil {
		t.Fatalf("expected password to be set")
	}

	// New password should work
	if !auth.CheckPasswordHash("NewPassword456", *user.Password) {
		t.Fatalf("new password check failed")
	}

	// Old password should not work
	if auth.CheckPasswordHash("OriginalPassword123", *user.Password) {
		t.Fatalf("old password should not work anymore")
	}
}

// TestChangePassword tests the password change endpoint with old password verification
func TestChangePassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()
	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	// First create a user
	createBody := `{
		"email": "user4@test.example.com",
		"username": "testuser4",
		"password": "OriginalPassword789"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", createBody)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("failed to create user: %d", w.Code)
	}

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	userID := createResponse["id"].(string)

	// Change password with correct old password
	changeBody := `{
		"old_password": "OriginalPassword789",
		"new_password": "UpdatedPassword999"
	}`

	w = performUserRequest(r, http.MethodPut, "/users/"+userID+"/password", changeBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, response: %s", w.Code, w.Body.String())
	}

	// Verify the password was changed
	user, err := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("failed to get user from database: %v", err)
	}

	if user.Password == nil {
		t.Fatalf("expected password to be set")
	}

	if !auth.CheckPasswordHash("UpdatedPassword999", *user.Password) {
		t.Fatalf("new password check failed")
	}

	if auth.CheckPasswordHash("OriginalPassword789", *user.Password) {
		t.Fatalf("old password should not work anymore")
	}
}

// TestChangePassword_WrongOldPassword tests password change with incorrect old password
func TestChangePassword_WrongOldPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()
	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	// Create a user
	createBody := `{
		"email": "user5@test.example.com",
		"username": "testuser5",
		"password": "CorrectPassword123"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", createBody)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("failed to create user: %d", w.Code)
	}

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	userID := createResponse["id"].(string)

	// Try to change password with wrong old password
	changeBody := `{
		"old_password": "WrongPassword456",
		"new_password": "NewPassword789"
	}`

	w = performUserRequest(r, http.MethodPut, "/users/"+userID+"/password", changeBody)

	// Should return 401 Unauthorized
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 401 or 400 for wrong password, got %d", w.Code)
	}

	// Verify the password was NOT changed
	user, err := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("failed to get user from database: %v", err)
	}

	if user.Password == nil {
		t.Fatalf("expected password to be set")
	}

	if !auth.CheckPasswordHash("CorrectPassword123", *user.Password) {
		t.Fatalf("password should not have changed")
	}
}

// TestChangePassword_MissingOldPassword tests password change without old password
func TestChangePassword_MissingOldPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	r := setupUserValidationRouter()

	changeBody := `{
		"new_password": "NewPassword123"
	}`

	w := performUserRequest(r, http.MethodPut, "/users/"+uuid.New().String()+"/password", changeBody)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestChangePassword_MissingNewPassword tests password change without new password
func TestChangePassword_MissingNewPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	r := setupUserValidationRouter()

	changeBody := `{
		"old_password": "OldPassword123"
	}`

	w := performUserRequest(r, http.MethodPut, "/users/"+uuid.New().String()+"/password", changeBody)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestUpdateUserWithoutPassword tests updating user without changing password
func TestUpdateUserWithoutPassword(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()
	adminID := createTestAdminUser(t, client)
	r := setupUserTestRouterWithAdmin(adminID)

	// Create a user with password
	createBody := `{
		"email": "user6@test.example.com",
		"username": "testuser6",
		"password": "InitialPassword123"
	}`

	w := performUserRequest(r, http.MethodPost, "/users", createBody)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("failed to create user: %d", w.Code)
	}

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	userID := createResponse["id"].(string)

	// Get original password hash
	originalUser, _ := db.Client.User.Get(ctx, uuid.MustParse(userID))
	originalHash := originalUser.Password

	// Update user without changing password
	updateBody := `{
		"email": "newemail@test.example.com"
	}`

	w = performUserRequest(r, http.MethodPut, "/users/"+userID, updateBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Verify password unchanged
	updatedUser, _ := db.Client.User.Get(ctx, uuid.MustParse(userID))
	if updatedUser.Password != originalHash {
		// Both could be nil or both could have same hash
		if !((originalHash == nil && updatedUser.Password == nil) ||
			(originalHash != nil && updatedUser.Password != nil && *originalHash == *updatedUser.Password)) {
			t.Fatalf("password should not have changed during email update")
		}
	}
}

// TestPasswordHashing tests password hashing with bcrypt
func TestPasswordHashing(t *testing.T) {
	password := "MySecurePassword123"

	// Hash the password
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Hash should not be the same as password
	if hash == password {
		t.Fatalf("password should be hashed")
	}

	// Check password should succeed with correct password
	if !auth.CheckPasswordHash(password, hash) {
		t.Fatalf("password check failed for correct password")
	}

	// Check password should fail with incorrect password
	if auth.CheckPasswordHash("WrongPassword", hash) {
		t.Fatalf("password check should fail for incorrect password")
	}

	// Check password should fail with empty password
	if auth.CheckPasswordHash("", hash) {
		t.Fatalf("password check should fail for empty password")
	}
}
