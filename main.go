package main

import (
	"sso-server/src/db"
	"sso-server/src/route"
	"time"
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
		db.DBConnection.Where("expires_at < ?", time.Now()).Delete(&db.Session{})
	}
}
