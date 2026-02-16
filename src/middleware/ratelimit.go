package middleware

import (
	"sso-server/src/utils"

	"github.com/gin-gonic/gin"
)

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if !utils.GlobalRateLimitInstance.RequestLimiterFunc(clientIP) {
			c.AbortWithStatus(429)
			return
		}
		c.Next()
	}
}
