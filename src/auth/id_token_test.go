package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"sso-server/src/db"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateIDToken_RS256Claims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	originalKeyPair := CurrentKeyPair
	CurrentKeyPair = &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Modulus:    encodeToBase64URL(privateKey.PublicKey.N.Bytes()),
		Exponent:   encodeToBase64URL(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		Kid:        "test-kid",
	}
	defer func() {
		CurrentKeyPair = originalKeyPair
	}()

	user := db.UserJWTPayload{
		ID:            "user-123",
		Email:         "user@example.com",
		Username:      "testuser",
		Avatar:        "https://example.com/avatar.png",
		EmailVerified: true,
	}

	clientID := "client-abc"
	nonce := "nonce-xyz"
	authTime := time.Unix(1700000000, 0)
	issuer := "https://issuer.example.com"

	tokenString, err := GenerateIDToken(user, clientID, nonce, authTime, issuer)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	claims := &IDTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, AuthorizeKeyFunc, ParseOption, TokenExpireOption)
	if err != nil {
		t.Fatalf("failed to parse id token: %v", err)
	}
	if !token.Valid {
		t.Fatalf("id token is not valid")
	}

	if token.Header["kid"] != "test-kid" {
		t.Fatalf("unexpected kid header: %v", token.Header["kid"])
	}

	if claims.Sub != user.ID {
		t.Fatalf("sub mismatch: got %s want %s", claims.Sub, user.ID)
	}
	if claims.Aud != clientID {
		t.Fatalf("aud mismatch: got %s want %s", claims.Aud, clientID)
	}
	if claims.Nonce != nonce {
		t.Fatalf("nonce mismatch: got %s want %s", claims.Nonce, nonce)
	}
	if claims.AuthTime != authTime.Unix() {
		t.Fatalf("auth_time mismatch: got %d want %d", claims.AuthTime, authTime.Unix())
	}
	if claims.Name != user.Username {
		t.Fatalf("name mismatch: got %s want %s", claims.Name, user.Username)
	}
	if claims.Email != user.Email {
		t.Fatalf("email mismatch: got %s want %s", claims.Email, user.Email)
	}
	if !claims.EmailVerified {
		t.Fatalf("email_verified should be true")
	}
	if claims.Picture != user.Avatar {
		t.Fatalf("picture mismatch: got %s want %s", claims.Picture, user.Avatar)
	}
	if claims.PreferredUsername != user.Username {
		t.Fatalf("preferred_username mismatch: got %s want %s", claims.PreferredUsername, user.Username)
	}
	if claims.Issuer != issuer {
		t.Fatalf("iss mismatch: got %s want %s", claims.Issuer, issuer)
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatalf("missing exp/iat claims")
	}
}

func TestGenerateIDToken_NoKeyPair(t *testing.T) {
	originalKeyPair := CurrentKeyPair
	CurrentKeyPair = nil
	defer func() {
		CurrentKeyPair = originalKeyPair
	}()

	user := db.UserJWTPayload{ID: "user-123"}
	_, err := GenerateIDToken(user, "client-abc", "nonce", time.Now(), "https://issuer.example.com")
	if err == nil {
		t.Fatalf("expected error when RSA key pair is not initialized")
	}
}

func TestGenerateAndValidateJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	originalKeyPair := CurrentKeyPair
	CurrentKeyPair = &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Modulus:    encodeToBase64URL(privateKey.PublicKey.N.Bytes()),
		Exponent:   encodeToBase64URL(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		Kid:        "test-kid",
	}
	defer func() {
		CurrentKeyPair = originalKeyPair
	}()

	user := db.UserJWTPayload{
		ID:       "user-123",
		Email:    "user@example.com",
		Username: "testuser",
		Avatar:   "https://example.com/avatar.png",
	}
	session := db.SessionJWTPayload{
		ID:        "session-123",
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	tokenString, err := GenerateJWT(user, session)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	claims, err := ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if claims.Sub != user.ID {
		t.Fatalf("sub mismatch: got %s want %s", claims.Sub, user.ID)
	}
	if claims.Sid != session.ID {
		t.Fatalf("sid mismatch: got %s want %s", claims.Sid, session.ID)
	}
	if claims.Email != user.Email {
		t.Fatalf("email mismatch: got %s want %s", claims.Email, user.Email)
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	originalKeyPair := CurrentKeyPair
	CurrentKeyPair = &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Modulus:    encodeToBase64URL(privateKey.PublicKey.N.Bytes()),
		Exponent:   encodeToBase64URL(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		Kid:        "test-kid",
	}
	defer func() {
		CurrentKeyPair = originalKeyPair
	}()

	user := db.UserJWTPayload{ID: "user-123"}
	session := db.SessionJWTPayload{ID: "session-123", ExpiresAt: time.Now().Add(1 * time.Hour)}

	tokenString, err := GenerateJWT(user, session)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	// Corrupt the token to force validation failure.
	invalidToken := tokenString + "corrupt"
	if _, err := ValidateJWT(invalidToken); err == nil {
		t.Fatalf("expected validation error for invalid token")
	}
}
