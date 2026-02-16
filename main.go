// @title SSO API
// @version 1.0
// @description SSO server API
// @BasePath /
//
//go:generate swag init -g main.go -o docs
package main

import (
	"context"
	"sso-server/ent/generated/openidkey"
	"sso-server/ent/generated/session"
	"sso-server/src/auth"
	"sso-server/src/config"
	"sso-server/src/db"
	"sso-server/src/route"
	"time"
)

func main() {
	// Load config from environment variables
	SystemEnv := config.NewEnvFromEnv()
	// init DB Connection
	db.InitDB()
	// Initialize RSA keys for OpenID Connect
	auth.InitKey()
	// start web server
	route.StartWebServer()

	// Periodically clean up expired sessions
	go createIntervalTicker(
		10*time.Minute,
		func() {
			ctxBg := context.Background()
			_, err := db.Client.Session.Delete().Where(session.ExpiresAtLT(time.Now())).Exec(ctxBg)
			if err != nil {
				print(err)
			}
		},
	)
	// Periodically deactivate expired OpenID keys based on config setting
	go createIntervalTicker(
		24*time.Hour,
		func() {
			ctxBg := context.Background()
			cutoff := time.Now().Add(-time.Duration(SystemEnv.OpenIDKeyExpireDays) * 24 * time.Hour)
			removeCutoff := time.Now().Add(-time.Duration(SystemEnv.OpenIDKeyExpireDays*2) * 24 * time.Hour)
			// Deactivate keys that are past expire duration but not too old to remove (e.g. between 30-60 days old)
			if err := db.Client.OpenIDKey.Update().Where(openidkey.And(
				openidkey.CreatedAtLT(cutoff),
				openidkey.CreatedAtGT(removeCutoff),
				openidkey.IsActiveEQ(true),
			)).SetIsActive(false).Exec(ctxBg); err != nil {
				print(err)
			}
			// Permanently delete keys that are very old (e.g. twice the expire duration)
			if _, err := db.Client.OpenIDKey.Delete().Where(openidkey.CreatedAtLT(removeCutoff)).Exec(ctxBg); err != nil {
				print(err)
			}
			auth.GenerateKeys()
		},
	)
}

func createIntervalTicker(d time.Duration, fn func()) (<-chan time.Time, *time.Ticker) {
	ticker := time.NewTicker(d)
	go func() {
		for range ticker.C {
			fn()
		}
	}()
	return ticker.C, ticker
}
