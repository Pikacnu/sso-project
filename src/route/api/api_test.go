package api

import (
    "encoding/json"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "sso-server/src/middleware"
)

// Test that unauthenticated AJAX/JSON requests to /api/user return 401 JSON
func TestGetUser_Unauthenticated_Returns401JSON(t *testing.T) {
    gin.SetMode(gin.TestMode)
    router := gin.New()
    // attach only the session middleware which will return 401 for API JSON requests
    router.Use(middleware.SessionMiddleware())
    RegisterAPIRoutes(router)

    req := httptest.NewRequest("GET", "/api/user", nil)
    req.Header.Set("Accept", "application/json")

    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    if w.Code != 401 {
        t.Fatalf("expected status 401, got %d, body: %s", w.Code, w.Body.String())
    }

    var resp map[string]string
    if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
        t.Fatalf("failed to parse response JSON: %v", err)
    }

    if resp["error"] != "authentication_required" {
        t.Fatalf("expected error 'authentication_required', got: %v", resp)
    }
}
