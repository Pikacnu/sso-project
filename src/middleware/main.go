package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

var ProtectedPaths = []string{
	"/api/",
	"/user/",
	"/clients",
}

var PublicPaths = []string{
	"/login",
	"/signup",
	"/auth/",
	"/.well-known/",
	"/swagger/",
}

func IsPublicPath(path string) bool {
	for _, publicPath := range PublicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}
	return false
}

func RegistryMiddleware(router *gin.Engine) {
	middlewares := []gin.HandlerFunc{
		gin.Logger(),
		gin.Recovery(),
		//ConfigMiddleware(),
		RateLimitMiddleware(),
		SessionMiddleware(),
		ClientMiddleware(),
	}
	router.Use(middlewares...)
}
