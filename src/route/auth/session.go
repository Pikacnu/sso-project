package auth

import (
	"context"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/src/auth"
	"sso-server/src/db"

	"github.com/google/uuid"
)

type sessionTokenResult struct {
	Token     string
	ExpiresAt time.Time
}

func createSessionToken(ctx context.Context, userEnt *ent.User, userAgent string, ipAddress string) (sessionTokenResult, error) {
	sessionUUID := uuid.New()
	sessionID := sessionUUID.String()
	exp := time.Now().Add(time.Hour * 24 * 7)

	if _, err := db.Client.Session.Create().
		SetID(sessionUUID).
		SetUserID(userEnt.ID).
		SetUserAgent(userAgent).
		SetIPAddress(ipAddress).
		SetExpiresAt(exp).
		Save(ctx); err != nil {
		return sessionTokenResult{}, err
	}

	avatarStr := ""
	if userEnt.Avatar != nil {
		avatarStr = *userEnt.Avatar
	}

	jwtUser := db.UserJWTPayload{
		ID:            userEnt.ID.String(),
		Email:         userEnt.Email,
		Username:      userEnt.Username,
		Avatar:        avatarStr,
		EmailVerified: userEnt.EmailVerified,
	}
	jwtSession := db.SessionJWTPayload{
		ID:        sessionID,
		UserID:    userEnt.ID.String(),
		ExpiresAt: exp,
	}

	tokenString, err := auth.GenerateJWT(jwtUser, jwtSession)
	if err != nil {
		return sessionTokenResult{}, err
	}

	return sessionTokenResult{Token: tokenString, ExpiresAt: exp}, nil
}
