package middleware

import (
	"sso-server/src/config"

	"github.com/gin-gonic/gin"
)

var cfg = config.NewEnvFromEnv()

func ConfigMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("config", cfg)
		c.Next()
	}
}

func GetConfigFromContext(c *gin.Context) *config.Env {
	if cfg, exists := c.Get("config"); exists {
		if configEnv, ok := cfg.(*config.Env); ok {
			return configEnv
		}
	}
	return nil
}

type EmailConfig struct {
	From         string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
}

func GetEmailConfigFromContext(c *gin.Context) *EmailConfig {
	env := GetConfigFromContext(c)
	if env == nil {
		return nil
	}
	return &EmailConfig{
		From:         env.EmailFrom,
		SMTPHost:     env.EmailSMTPHost,
		SMTPPort:     env.EmailSMTPPort,
		SMTPUser:     env.EmailSMTPUser,
		SMTPPassword: env.EmailSMTPPassword,
	}
}
