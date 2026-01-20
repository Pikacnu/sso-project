package db

import (
	"sso-server/src/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DBConnection *gorm.DB
var cfg = config.NewEnvFromEnv()

func ApplyMigrations(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&SocialAccount{},
		&Client{},
		&AccessToken{},
		&RefreshToken{},
		&AuthorizationCode{},
		&Session{},
	)
}

func ConnectDatabase(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func InitDB() {
	db, err := ConnectDatabase(cfg.ConnectionString)
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}
	err = ApplyMigrations(db)
	if err != nil {
		panic("failed to apply migrations: " + err.Error())
	}
	DBConnection = db
}
