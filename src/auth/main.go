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

func GenerateJWT(user db.User, session db.Session) (string, error) {
	claims := jwt.MapClaims{
		"sub":    user.ID,
		"sid":    session.ID,
		"email":  user.Email,
		"name":   user.Username,
		"avatar": user.Avatar,
		"iat":    time.Now().Unix(),
		"exp":    session.ExpiresAt.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

func ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, AuthorizeKeyFunc, jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
