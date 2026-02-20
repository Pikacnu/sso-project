package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeadersMiddleware adds important security headers to responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking attacks
		c.Header("X-Frame-Options", "DENY")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Force HTTPS (if in production)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self';")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Feature Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}
