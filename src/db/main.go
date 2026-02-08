package db

import (
	"context"
	"sso-server/src/config"

	"database/sql"
	ent "sso-server/ent/generated"

	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Client *ent.Client
var DBConnection *gorm.DB
var cfg = config.NewEnvFromEnv()

func ApplyMigrations(client *ent.Client) error {
	ctx := context.Background()
	return client.Schema.Create(ctx)
}

func ConnectDatabase(dsn string) (*ent.Client, *sql.DB, error) {
	drv, err := entsql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, err
	}
	sqlDB := drv.DB()
	client := ent.NewClient(ent.Driver(drv))
	return client, sqlDB, nil
}

func InitDB() {
	client, sqlDB, err := ConnectDatabase(cfg.ConnectionString)
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}
	err = ApplyMigrations(client)
	if err != nil {
		panic("failed to apply migrations: " + err.Error())
	}
	Client = client

	// Also create a GORM DB connection using the same underlying sql.DB
	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{})
	if err != nil {
		panic("failed to initialize GORM DB connection: " + err.Error())
	}
	DBConnection = gormDB
}
