package clients

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	ent "sso-server/ent/generated"
	enttest "sso-server/ent/generated/enttest"
	"sso-server/src/config"
	"sso-server/src/db"

	_ "github.com/lib/pq"
)

const defaultTestDSN = "postgres://user:pass@localhost:5434/sso_test?sslmode=disable"

// openTestDB opens a test database connection and initializes the global db.Client
// This mirrors other packages' test helpers so each package can run tests in isolated schemas.
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
	// Create an isolated schema for this test run to avoid cross-package collisions
	schemaName := fmt.Sprintf("test_%d", time.Now().UnixNano())
	if _, err := sqlDB.Exec(fmt.Sprintf(`CREATE SCHEMA "%s"`, schemaName)); err != nil {
		_ = sqlDB.Close()
		t.Skipf("skip integration test: failed to create schema: %v", err)
	}
	_ = sqlDB.Close()

	// Append options to set search_path to the new schema
	var schemaDSN string
	if strings.Contains(dsn, "?") {
		schemaDSN = dsn + "&options=-c%20search_path%3D" + schemaName
	} else {
		schemaDSN = dsn + "?options=-c%20search_path%3D" + schemaName
	}

	client := enttest.Open(t, "postgres", schemaDSN)

	// Initialize global db.Client for handlers
	db.Client = client

	return client
}

// cleanDB clears all data from the database for test isolation
func cleanDB(t *testing.T, client *ent.Client) {
	t.Helper()
	ctx := context.Background()

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
