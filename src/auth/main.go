package auth

import (
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
