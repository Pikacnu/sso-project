package route

import (
	"fmt"
	"net/http"

	"sso-server/src/config"
	"sso-server/src/middleware"
	. "sso-server/src/route/api"
	. "sso-server/src/route/auth"

	"github.com/gin-gonic/gin"
)

func StartWebServer() {
	// load configuration

	routes := []func(*gin.Engine){
		RegisterAPIRoutes,
		RegisterAuthRoutes,
		RegisterRoutes,
	}

	cfg := config.NewEnvFromEnv()
	if cfg.Debug == true {
		fmt.Println("Config:\n", cfg.Format())
	}

	router := gin.Default()
	middleware.RegistryMiddleware(router)

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello, World!",
		})
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	for _, register := range routes {
		register(router)
	}

	router.Run(cfg.BindAddr())
}
