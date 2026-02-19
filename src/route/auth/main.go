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
	// Email verification routes
	routerGroup.POST("/verify-email/request", requestEmailVerificationHandler)
	routerGroup.GET("/verify-email", verifyEmailHandler)
	// Email auth routes
	routerGroup.POST("/email/register", emailRegisterHandler)
	routerGroup.POST("/email/login", emailLoginHandler)
	// Admin initialization routes
	routerGroup.POST("/admin/init", adminInitHandler)
}
