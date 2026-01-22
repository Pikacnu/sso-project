package auth_test

import (
	"sso-server/src/auth"
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	token1, err := auth.GenerateSecureToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if len(token1) == 0 {
		t.Error("Generated token is empty")
	}

	// Generate another token to ensure uniqueness
	token2, err := auth.GenerateSecureToken()
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	if token1 == token2 {
		t.Error("Generated tokens are not unique")
	}

	t.Logf("Token 1: %s", token1)
	t.Logf("Token 2: %s", token2)
	t.Logf("Token length: %d", len(token1))
}

func TestGenerateCodeChallenge(t *testing.T) {
	tests := []struct {
		name         string
		codeVerifier string
		expected     string
	}{
		{
			name:         "Test Vector 1",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expected:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.GenerateCodeChallenge(tt.codeVerifier)
			if result != tt.expected {
				t.Errorf("GenerateCodeChallenge() = %v, want %v", result, tt.expected)
			}
			t.Logf("Code Verifier: %s", tt.codeVerifier)
			t.Logf("Code Challenge: %s", result)
		})
	}
}

func TestVerifyCodeChallenge(t *testing.T) {
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)

	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		expected            bool
	}{
		{
			name:                "Valid S256",
			codeVerifier:        codeVerifier,
			codeChallenge:       codeChallenge,
			codeChallengeMethod: "S256",
			expected:            true,
		},
		{
			name:                "Invalid verifier",
			codeVerifier:        "wrong_verifier",
			codeChallenge:       codeChallenge,
			codeChallengeMethod: "S256",
			expected:            false,
		},
		{
			name:                "Plain method - matching",
			codeVerifier:        "test123",
			codeChallenge:       "test123",
			codeChallengeMethod: "plain",
			expected:            true,
		},
		{
			name:                "Plain method - not matching",
			codeVerifier:        "test123",
			codeChallenge:       "test456",
			codeChallengeMethod: "plain",
			expected:            false,
		},
		{
			name:                "Empty method defaults to plain",
			codeVerifier:        "test123",
			codeChallenge:       "test123",
			codeChallengeMethod: "",
			expected:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.VerifyCodeChallenge(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if result != tt.expected {
				t.Errorf("VerifyCodeChallenge() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPKCEFlow(t *testing.T) {
	// Simulate complete PKCE flow
	t.Run("Complete PKCE Flow", func(t *testing.T) {
		// Step 1: Client generates code_verifier
		codeVerifier, err := auth.GenerateSecureToken()
		if err != nil {
			t.Fatalf("Failed to generate code verifier: %v", err)
		}
		t.Logf("Code Verifier: %s", codeVerifier)

		// Step 2: Client generates code_challenge
		codeChallenge := auth.GenerateCodeChallenge(codeVerifier)
		t.Logf("Code Challenge: %s", codeChallenge)

		// Step 3: Server stores code_challenge with authorization code
		// (this would happen in the authorize endpoint)

		// Step 4: Client sends code_verifier with token request
		// Server verifies code_verifier against stored code_challenge
		isValid := auth.VerifyCodeChallenge(codeVerifier, codeChallenge, "S256")
		if !isValid {
			t.Error("PKCE verification failed")
		}

		t.Log("✓ PKCE flow completed successfully")
	})
}

func BenchmarkGenerateSecureToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := auth.GenerateSecureToken()
		if err != nil {
			b.Fatalf("Failed to generate token: %v", err)
		}
	}
}

func BenchmarkGenerateCodeChallenge(b *testing.B) {
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.GenerateCodeChallenge(codeVerifier)
	}
}

func BenchmarkVerifyCodeChallenge(b *testing.B) {
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.VerifyCodeChallenge(codeVerifier, codeChallenge, "S256")
	}
}
