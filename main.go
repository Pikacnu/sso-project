package main

import (
	"context"

	"sso-server/src/db"
	"sso-server/src/route"
	"time"

	"sso-server/ent/generated/session"
)

func main() {
	// init DB Connection
	db.InitDB()
	// start web server
	route.StartWebServer()
	go cleanUpOldSessions()
}

func cleanUpOldSessions() {
	timer := time.NewTicker(10 * time.Minute)
	for range timer.C {
		ctxBg := context.Background()
		_, err := db.Client.Session.Delete().Where(session.ExpiresAtLT(time.Now())).Exec(ctxBg)
		if err != nil {
			// Log error but don't panic
		}
	}
}
