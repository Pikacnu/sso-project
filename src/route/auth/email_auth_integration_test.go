package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"sso-server/ent/generated/user"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/google/uuid"
)

func TestEmailRegisterHandler_CreatesUser(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	ctx := context.Background()
	cleanDB(t, client)

	r := setupRouter()
	r.POST("/auth/email/register", emailRegisterHandler)

	form := url.Values{}
	form.Set("email", "newuser@example.com")
	form.Set("password", "passw0rd!")
	form.Set("username", "newuser")
	w := performRequest(r, http.MethodPost, "/auth/email/register", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	created, err := client.User.Query().Where(user.EmailEQ("newuser@example.com")).Only(ctx)
	if err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if created.Password == nil || *created.Password == "passw0rd!" {
		t.Fatalf("password was not hashed")
	}
	if created.EmailVerified {
		t.Fatalf("email_verified should be false")
	}
	if created.EmailVerificationToken == nil || *created.EmailVerificationToken == "" {
		t.Fatalf("verification token not set")
	}
}

func TestEmailLoginHandler_UnverifiedSendsVerification(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	ctx := context.Background()
	cleanDB(t, client)

	hash, err := auth.HashPassword("passw0rd!")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	userID := uuid.New()
	_, err = client.User.Create().
		SetID(userID).
		SetUsername("verifyuser").
		SetEmail("verifyuser@example.com").
		SetPassword(hash).
		SetEmailVerified(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	r := setupRouter()
	r.POST("/auth/email/login", emailLoginHandler)

	form := url.Values{}
	form.Set("email", "verifyuser@example.com")
	form.Set("password", "passw0rd!")
	w := performRequest(r, http.MethodPost, "/auth/email/login", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}

	updated, err := client.User.Get(ctx, userID)
	if err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if updated.EmailVerificationToken == nil || *updated.EmailVerificationToken == "" {
		t.Fatalf("verification token not set")
	}
	if updated.EmailVerificationExpiresAt == nil || updated.EmailVerificationExpiresAt.Before(time.Now()) {
		t.Fatalf("verification expiry not set")
	}
}

func TestVerifyEmailHandler_ReturnToken(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	// Initialize CurrentKeyPair for JWT generation
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	originalKeyPair := auth.CurrentKeyPair
	auth.CurrentKeyPair = &auth.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Modulus:    "",
		Exponent:   "",
		Kid:        "test-kid",
	}
	defer func() {
		auth.CurrentKeyPair = originalKeyPair
	}()

	ctx := context.Background()
	cleanDB(t, client)

	token, err := auth.GenerateSecureToken()
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}

	userID := uuid.New()
	_, err = client.User.Create().
		SetID(userID).
		SetUsername("tokenuser").
		SetEmail("tokenuser@example.com").
		SetEmailVerified(false).
		SetEmailVerificationToken(token).
		SetEmailVerificationExpiresAt(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	r := setupRouter()
	r.GET("/auth/verify-email", verifyEmailHandler)

	w := performRequest(r, http.MethodGet, "/auth/verify-email?token="+token+"&return_token=true", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if payload["token"] == nil || payload["token"] == "" {
		t.Fatalf("expected token in response")
	}

	updated, err := client.User.Get(ctx, userID)
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if !updated.EmailVerified {
		t.Fatalf("email_verified not set to true")
	}
}
