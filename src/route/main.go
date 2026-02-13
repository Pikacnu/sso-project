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

	// All route registration functions
	routes := []func(*gin.Engine){
		RegisterAPIRoutes,
		RegisterAuthRoutes,
		RegisterScopeRoutes,
		RegistrerWellKnownRoutes,
	}

	// load Config
	if config.SystemEnv.Debug == true {
		fmt.Println("Config:\n", config.SystemEnv.Format())
	}

	router := gin.Default()
	middleware.RegistryMiddleware(router)

	docs.SwaggerInfo.Title = "SSO API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/"
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	for _, register := range routes {
		register(router)
	}

	router.Run(config.SystemEnv.BindAddr())
}
