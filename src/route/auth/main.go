package auth

import (
	"github.com/gin-gonic/gin"
)

type ReturnedDefaultUser struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar"`
}

type OAuthUriBinding struct {
	Platform string `uri:"platform" binding:"required"`
}

func RegisterAuthRoutes(router *gin.Engine) {
	routerGroup := router.Group("/auth")
	// User Authentication Routes
	routerGroup.GET("/logout", logoutHandler)
	routerGroup.GET("/:platform/login", loginHandler)
	routerGroup.GET("/:platform/callback", callBackHandler)
	// OAuth2 Routes
	routerGroup.GET("/callback", authCallbackHandler)
	routerGroup.GET("/authorize", authorizeHandler)
	routerGroup.GET("/login", loginPageHandler)
	routerGroup.POST("/token", tokenHandler)
	routerGroup.POST("/introspect", introspectHandler)
	routerGroup.POST("/revoke", revokeHandler)
	// User Info Routes
	routerGroup.GET("/userinfo", userInfoHandler)
}
