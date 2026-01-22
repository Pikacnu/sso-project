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
var ParseOption = jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})
var TokenExpireOption = jwt.WithExpirationRequired()

func AuthorizeKeyFunc(token *jwt.Token) (any, error) {
	switch token.Method.Alg() {
	case jwt.SigningMethodHS256.Alg():
		return []byte(cfg.JWTSecret), nil
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

func GenerateJWT(user db.User, session db.Session) (string, error) {
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
	return token.SignedString([]byte(cfg.JWTSecret))
}

func ValidateJWT(tokenString string) (CustomClaims, error) {
	token, err := jwt.Parse(tokenString, AuthorizeKeyFunc, jwt.WithExpirationRequired())
	if err != nil {
		return CustomClaims{}, err
	}
	if claims, ok := token.Claims.(CustomClaims); ok && token.Valid {
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
