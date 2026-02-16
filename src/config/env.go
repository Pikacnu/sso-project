package config

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Env holds application configuration loaded from environment variables.
type Env struct {
	AppName                 string `json:"app_name"`
	Port                    string `json:"port"`
	Hostname                string `json:"hostname"`
	FrontendURL             string `json:"frontend_url"`
	Debug                   bool   `json:"debug"`
	DatabaseURL             string `json:"database_url"`
	GoogleClientID          string `json:"google_client_id"`
	GoogleClientSecret      string `json:"google_client_secret"`
	DiscordClientID         string `json:"discord_client_id"`
	DiscordClientSecret     string `json:"discord_client_secret"`
	JWTSecret               string `json:"jwt_secret"`
	ConnectionString        string `json:"connection_string"`
	OpenIDKeyExpireDays     int    `json:"openid_key_expire_days"`
	EmailFrom               string `json:"email_from"`
	EmailSMTPHost           string `json:"email_smtp_host"`
	EmailSMTPPort           int    `json:"email_smtp_port"`
	EmailSMTPUser           string `json:"email_smtp_user"`
	EmailSMTPPassword       string `json:"email_smtp_password"`
	RateLimitPerMinute      int    `json:"rate_limit_per_minute"`
	ExternalCacheTTLSeconds int    `json:"external_cache_ttl_seconds"`
}

var SystemEnv *Env

// NewEnvFromEnv creates an Env populated from environment variables with defaults.
func NewEnvFromEnv() *Env {
	godotenv.Load()
	if SystemEnv != nil {
		return SystemEnv
	}
	SystemEnv = &Env{
		AppName:                 getEnv("APP_NAME", "sso-server"),
		Port:                    getEnv("PORT", "8080"),
		Hostname:                getEnv("HOSTNAME", "localhost"),
		FrontendURL:             getEnv("FRONTEND_URL", "http://localhost:5173"),
		Debug:                   getEnvBool("DEBUG", "false"),
		DatabaseURL:             getEnv("DATABASE_URL", "postgres://user:pass@localhost:5432/sso_db"),
		GoogleClientID:          getEnv("GOOGLE_CLIENT_ID", "your-google-client-id"),
		GoogleClientSecret:      getEnv("GOOGLE_CLIENT_SECRET", "your-google-client-secret"),
		DiscordClientID:         getEnv("DISCORD_CLIENT_ID", "your-discord-client-id"),
		DiscordClientSecret:     getEnv("DISCORD_CLIENT_SECRET", "your-discord-client-secret"),
		JWTSecret:               getEnv("JWT_SECRET", "your-jwt-secret"),
		ConnectionString:        getEnv("CONNECTION_STRING", "your-connection-string"),
		OpenIDKeyExpireDays:     getEnvInt("OPENID_KEY_EXPIRE_DAYS", 30),
		EmailFrom:               getEnv("EMAIL_FROM", "no-reply@example.com"),
		EmailSMTPHost:           getEnv("EMAIL_SMTP_HOST", ""),
		EmailSMTPPort:           getEnvInt("EMAIL_SMTP_PORT", 587),
		EmailSMTPUser:           getEnv("EMAIL_SMTP_USER", ""),
		EmailSMTPPassword:       getEnv("EMAIL_SMTP_PASSWORD", ""),
		RateLimitPerMinute:      getEnvInt("RATE_LIMIT_PER_MINUTE", 100),
		ExternalCacheTTLSeconds: getEnvInt("EXTERNAL_CACHE_TTL_SECONDS", 300),
	}
	return SystemEnv
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	s := getEnv(key, strconv.Itoa(def))
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func getEnvBool(key, def string) bool {
	s := getEnv(key, def)
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

// Format returns a pretty-printed JSON representation of the Env.
func (e *Env) Format() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b)
}

// BindAddr returns an address string suitable for gin.Run (adds leading ':' if missing).
func (e *Env) BindAddr() string {
	if e == nil {
		return ":8080"
	}
	if e.Port == "" {
		return ":8080"
	}
	if e.Port[0] == ':' {
		return e.Port
	}
	return ":" + e.Port
}
