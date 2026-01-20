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
