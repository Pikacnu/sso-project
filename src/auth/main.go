package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sso-server/src/config"
	"sso-server/src/db"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var cfg = config.NewEnvFromEnv()
var ParseOption = jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg(), jwt.SigningMethodRS256.Alg()})
var TokenExpireOption = jwt.WithExpirationRequired()

func AuthorizeKeyFunc(token *jwt.Token) (any, error) {
	switch token.Method.Alg() {
	case jwt.SigningMethodHS256.Alg():
		return []byte(cfg.JWTSecret), nil
	case jwt.SigningMethodRS256.Alg():
		if CurrentKeyPair != nil && CurrentKeyPair.PublicKey != nil {
			return CurrentKeyPair.PublicKey, nil
		}
		return nil, jwt.ErrTokenUnverifiable
	default:
		return nil, jwt.ErrTokenUnverifiable
	}
}

type CustomClaims struct {
	Sub    string `json:"sub"`
	Sid    string `json:"sid"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	jwt.RegisteredClaims
}

// IDTokenClaims represents OIDC-compliant ID Token claims
type IDTokenClaims struct {
	// Required OIDC claims
	Sub string `json:"sub"` // Subject (user unique ID)
	Aud string `json:"aud"` // Audience (client ID)

	// Optional OIDC claims
	Nonce    string   `json:"nonce,omitempty"`     // Nonce for replay attack prevention
	AuthTime int64    `json:"auth_time,omitempty"` // Time when authentication occurred
	Acr      string   `json:"acr,omitempty"`       // Authentication Context Class Reference
	Amr      []string `json:"amr,omitempty"`       // Authentication Methods References
	Azp      string   `json:"azp,omitempty"`       // Authorized party

	// Profile scope claims
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`

	// Email scope claims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`

	// Phone scope claims
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`

	// Session ID
	Sid string `json:"sid,omitempty"`

	jwt.RegisteredClaims
}

// GenerateJWT generates a JWT using HS256 (for internal use, backward compatibility)
func GenerateJWT(user db.UserJWTPayload, session db.SessionJWTPayload) (string, error) {
	claims := CustomClaims{
		Sub:    user.ID,
		Sid:    session.ID,
		Email:  user.Email,
		Name:   user.Username,
		Avatar: user.Avatar,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = CurrentKeyPair.Kid
	return token.SignedString([]byte(cfg.JWTSecret))
}

// GenerateIDToken generates an OIDC-compliant ID Token using RS256
func GenerateIDToken(user db.UserJWTPayload, clientID string, nonce string, authTime time.Time, issuer string) (string, error) {
	if CurrentKeyPair == nil || CurrentKeyPair.PrivateKey == nil {
		return "", errors.New("RSA key pair not initialized")
	}

	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)

	claims := IDTokenClaims{
		Sub:               user.ID,
		Aud:               clientID,
		Nonce:             nonce,
		AuthTime:          authTime.Unix(),
		Name:              user.Username,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Picture:           user.Avatar,
		PreferredUsername: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = CurrentKeyPair.Kid

	return token.SignedString(CurrentKeyPair.PrivateKey)
}

func ValidateJWT(tokenString string) (CustomClaims, error) {
	claims := CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, AuthorizeKeyFunc, jwt.WithExpirationRequired())
	if err != nil {
		return CustomClaims{}, err
	}
	if token.Valid {
		return claims, nil
	}
	return CustomClaims{}, errors.New("invalid token")
}

// GenerateSecureToken generates a cryptographically secure random token
// Returns a base64 URL-encoded string of 32 random bytes (256 bits)
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateCodeChallenge creates a SHA256 hash of the code verifier for PKCE
// code_challenge = BASE64URL(SHA256(code_verifier))
func GenerateCodeChallenge(codeVerifier string) string {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}

// VerifyCodeChallenge verifies that the code_verifier matches the code_challenge
func VerifyCodeChallenge(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod == "" || codeChallengeMethod == "plain" {
		// Plain method: code_challenge == code_verifier
		return codeVerifier == codeChallenge
	}
	if codeChallengeMethod == "S256" {
		// S256 method: code_challenge == BASE64URL(SHA256(code_verifier))
		computed := GenerateCodeChallenge(codeVerifier)
		return computed == codeChallenge
	}
	return false
}
