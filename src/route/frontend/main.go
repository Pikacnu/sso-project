package frontend

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RegisterFrontendRoutes 注册前端静态文件和面板路由
func RegisterFrontendRoutes(router *gin.Engine) {
	router.Static("/_astro", "./web/dist/_astro")
	router.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	router.StaticFile("/favicon.ico", "./web/dist/favicon.ico")

	router.GET("/panel/clients", func(c *gin.Context) {
		c.File("./web/dist/clients/index.html")
	})
	router.GET("/panel/users", func(c *gin.Context) {
		c.File("./web/dist/users/index.html")
	})
	router.GET("/panel/roles", func(c *gin.Context) {
		c.File("./web/dist/roles/index.html")
	})
	router.GET("/panel/permissions", func(c *gin.Context) {
		c.File("./web/dist/permissions/index.html")
	})

	router.GET("/panel", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/panel/clients")
	})
	router.GET("/panel/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/panel/clients")
	})

	router.GET("/login", func(c *gin.Context) {
		c.File("./web/dist/login/index.html")
	})

	router.GET("/", func(c *gin.Context) {
		accept := c.GetHeader("Accept")
		if strings.Contains(accept, "application/json") {
			c.JSON(http.StatusOK, gin.H{
				"service":     "SSO Server",
				"version":     "1.0.0",
				"description": "OAuth 2.0 and OpenID Connect compliant Single Sign-On server",
				"frontend": gin.H{
					"home":          "/",
					"login":         "/login",
					"panel":         "/panel",
					"documentation": "/swagger/index.html",
				},
				"oauth": gin.H{
					"authorize":  "/auth/authorize",
					"token":      "/auth/token",
					"userinfo":   "/auth/userinfo",
					"introspect": "/auth/introspect",
					"revoke":     "/auth/revoke",
				},
				"endpoints": gin.H{
					"well-known": "/.well-known/openid-configuration",
					"health":     "/health",
				},
			})
		} else {
			c.File("./web/dist/index.html")
		}
	})
}
