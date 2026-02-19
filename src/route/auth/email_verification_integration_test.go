package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"sso-server/src/db"

	"github.com/google/uuid"
)

func TestEmailVerificationFlow(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	_db := db.Client
	db.Client = client
	defer func() { db.Client = _db }()

	ctx := context.Background()
	cleanDB(t, client)

	username := "verifyuser-" + uuid.New().String()[:8]
	userEnt, err := client.User.Create().
		SetUsername(username).
		SetEmail(username + "@example.com").
		SetEmailVerified(false).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	r := setupRouter()
	r.POST("/auth/verify-email/request", requestEmailVerificationHandler)
	r.GET("/auth/verify-email", verifyEmailHandler)

	form := url.Values{}
	form.Set("email", userEnt.Email)
	w := performRequest(r, http.MethodPost, "/auth/verify-email/request", form.Encode(), "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	updated, err := client.User.Get(ctx, userEnt.ID)
	if err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if updated.EmailVerificationToken == nil || *updated.EmailVerificationToken == "" {
		t.Fatalf("verification token not set")
	}
	if updated.EmailVerificationExpiresAt == nil || updated.EmailVerificationExpiresAt.Before(time.Now()) {
		t.Fatalf("verification expiry not set")
	}

	verifyURL := "/auth/verify-email?token=" + *updated.EmailVerificationToken
	w = performRequest(r, http.MethodGet, verifyURL, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	verifiedUser, err := client.User.Get(ctx, userEnt.ID)
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if !verifiedUser.EmailVerified {
		t.Fatalf("email_verified not set to true")
	}
	if verifiedUser.EmailVerificationToken != nil {
		t.Fatalf("verification token not cleared")
	}
	if verifiedUser.EmailVerificationExpiresAt != nil {
		t.Fatalf("verification expiry not cleared")
	}
}
