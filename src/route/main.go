package route

import (
	"fmt"
	"net/http"

	"sso-server/docs"
	"sso-server/src/config"
	"sso-server/src/middleware"
	. "sso-server/src/route/api"
	. "sso-server/src/route/auth"
	. "sso-server/src/route/clients"
	. "sso-server/src/route/permissions"
	. "sso-server/src/route/roles"
	. "sso-server/src/route/scopes"
	. "sso-server/src/route/users"
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
		RegisterClientRoutes,
		RegisterPermissionRoutes,
		RegisterRoleRoutes,
		RegisterScopeRoutes,
		RegisterUserRoutes,
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

	router.GET("/health", healthCheckHandler)
	router.GET("/", serviceInfoHandler)

	for _, register := range routes {
		register(router)
	}

	router.Run(config.SystemEnv.BindAddr())
}

// @Summary Health check
// @Description Check if the service is healthy
// @Tags system
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

// @Summary Service information
// @Description Get SSO service information and available endpoints
// @Tags system
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func serviceInfoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "SSO Server",
		"version": "1.0",
		"endpoints": gin.H{
			"health":     "/health",
			"login":      "/auth/login",
			"authorize":  "/auth/authorize",
			"token":      "/auth/token",
			"swagger":    "/swagger/index.html",
			"well-known": "/.well-known/openid-configuration",
		},
	})
}
