package route

import (
	"fmt"
	"net/http"

	"sso-server/docs"
	"sso-server/src/config"
	"sso-server/src/middleware"
	. "sso-server/src/route/api"
	. "sso-server/src/route/auth"
	. "sso-server/src/route/scopes"
	. "sso-server/src/route/well_known"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func StartWebServer() {
	// load configuration

	routes := []func(*gin.Engine){
		RegisterAPIRoutes,
		RegisterAuthRoutes,
		RegisterScopeRoutes,
		RegistrerWellKnownRoutes,
		RegisterRoutes,
	}

	cfg := config.NewEnvFromEnv()
	if cfg.Debug == true {
		fmt.Println("Config:\n", cfg.Format())
	}

	router := gin.Default()
	middleware.RegistryMiddleware(router)

	docs.SwaggerInfo.Title = "SSO API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/"
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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
