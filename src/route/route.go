package route

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers routes for this package onto the given router.
func RegisterRoutes(r *gin.Engine) {
	r.GET("/test", testHandler)
}

func testHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "test route"})
}
