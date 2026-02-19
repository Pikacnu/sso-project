package scopes

import (
	"context"
	"database/sql"
	"testing"

	ent "sso-server/ent/generated"
	enttest "sso-server/ent/generated/enttest"
	"sso-server/src/config"
	"sso-server/src/db"

	_ "github.com/lib/pq"
)

const defaultTestDSN = "postgres://user:pass@localhost:5434/sso_test?sslmode=disable"

// openTestDB opens a test database connection and initializes the global db.Client
// This is needed because the handlers use the global db.Client
func openTestDB(t *testing.T) *ent.Client {
	t.Helper()
	env := config.NewEnvFromEnv()
	dsn := env.ConnectionString
	if dsn == "" {
		dsn = defaultTestDSN
	}

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("skip integration test: cannot open db: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		t.Skipf("skip integration test: db not reachable: %v", err)
	}
	_ = sqlDB.Close()

	client := enttest.Open(t, "postgres", dsn)

	// Initialize global db.Client for handlers
	db.Client = client

	return client
}

// cleanDB clears all data from the database for test isolation
func cleanDB(t *testing.T, client *ent.Client) {
	t.Helper()
	ctx := struct{ context.Context }{context.Background()}

	client.RefreshToken.Delete().Exec(ctx)
	client.AccessToken.Delete().Exec(ctx)
	client.AuthorizationCode.Delete().Exec(ctx)
	client.OAuthFlow.Delete().Exec(ctx)
	client.Session.Delete().Exec(ctx)
	client.SocialAccount.Delete().Exec(ctx)
	client.Scope.Delete().Exec(ctx)
	client.OAuthClient.Delete().Exec(ctx)
	client.User.Delete().Exec(ctx)
	client.Permission.Delete().Exec(ctx)
	client.Role.Delete().Exec(ctx)
	client.OpenIDKey.Delete().Exec(ctx)
}
