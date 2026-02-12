package db

import (
	"context"
	"sso-server/src/config"
	"time"

	ent "sso-server/ent/generated"

	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/lib/pq"
)

var Client *ent.Client
var cfg = config.NewEnvFromEnv()

// UserJWTPayload holds minimal user data for JWT generation
type UserJWTPayload struct {
	ID       string
	Email    string
	Username string
	Avatar   string
	EmailVerified bool
}

// SessionJWTPayload holds minimal session data for JWT generation
type SessionJWTPayload struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

func ApplyMigrations(client *ent.Client) error {
	ctx := context.Background()
	return client.Schema.Create(ctx)
}

func InitDB() {
	drv, err := entsql.Open("postgres", cfg.ConnectionString)
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}
	client := ent.NewClient(ent.Driver(drv))
	err = ApplyMigrations(client)
	if err != nil {
		panic("failed to apply migrations: " + err.Error())
	}
	Client = client
}
