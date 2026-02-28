package clients

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/oauthclient"
	"sso-server/ent/generated/permission"
	"sso-server/ent/generated/user"
	dbpkg "sso-server/src/db"
	"sso-server/src/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ClientCreateRequest struct {
	AppName       string `json:"app_name"`
	Domain        string `json:"domain"`
	RedirectUris  string `json:"redirect_uris"`
	AllowedScopes string `json:"allowed_scopes"`
	OwnerID       string `json:"owner_id"`
	LogoURL       string `json:"logo_url"`
}

type ClientUpdateRequest struct {
	AppName       *string `json:"app_name"`
	Domain        *string `json:"domain"`
	RedirectUris  *string `json:"redirect_uris"`
	AllowedScopes *string `json:"allowed_scopes"`
	OwnerID       *string `json:"owner_id"`
	IsActive      *bool   `json:"is_active"`
	LogoURL       *string `json:"logo_url"`
}

func RegisterClientRoutes(router *gin.Engine) {
	// Public client routes (for users / owners). Management actions are checked inside handlers.
	pub := router.Group("/clients")
	pub.GET("", listClientsHandler)
	pub.POST("", createClientHandler)
	pub.GET("/:id", getClientHandler)

	// Management routes under /clients require admin for updates/enabled/rotate
	pub.PUT("/:id", func(c *gin.Context) {
		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - management requires admin"})
	})
	pub.POST("/:id/disable", func(c *gin.Context) {
		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - management requires admin"})
	})
	pub.POST("/:id/enable", func(c *gin.Context) {
		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - management requires admin"})
	})
	pub.POST("/:id/rotate-secret", func(c *gin.Context) {
		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden - management requires admin"})
	})

	// Admin-only routes
	admin := router.Group("/admin/clients")
	admin.Use(middleware.RequireRole("admin"))
	admin.GET("", listClientsHandler)
	admin.POST("", createClientHandler)
	admin.GET("/:id", getClientHandler)
	admin.PUT("/:id", updateClientHandler)
	admin.POST("/:id/disable", disableClientHandler)
	admin.POST("/:id/enable", enableClientHandler)
	admin.POST("/:id/rotate-secret", rotateClientSecretHandler)
}

// @Summary List OAuth clients
// @Description List all OAuth clients
// @Tags clients
// @Security BearerAuth
// @Produce json
// @Success 200 {array} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients [get]
func listClientsHandler(c *gin.Context) {
	ctx := c.Request.Context()
	path := c.Request.URL.Path
	// If admin route or user is admin, list all
	if strings.Contains(path, "/admin/") {
		clients, err := dbpkg.Client.OAuthClient.Query().All(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query clients"})
			return
		}

		response := make([]gin.H, 0, len(clients))
		for _, client := range clients {
			response = append(response, clientResponse(client))
		}

		c.JSON(http.StatusOK, response)
		return
	}

	// Non-admin: return only clients owned by current user
	userIDRaw, ok := c.Get("user_id")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
		return
	}
	userIDStr, ok := userIDRaw.(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user id"})
		return
	}

	clients, err := dbpkg.Client.OAuthClient.Query().Where(oauthclient.OwnerIDEQ(userUUID)).All(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query clients"})
		return
	}

	response := make([]gin.H, 0, len(clients))
	for _, client := range clients {
		response = append(response, clientResponse(client))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get OAuth client by ID
// @Description Get details of a specific OAuth client
// @Tags clients
// @Security BearerAuth
// @Produce json
// @Param id path string true "Client ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients/{id} [get]
func getClientHandler(c *gin.Context) {
	clientUUID, ok := parseClientID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	client, err := dbpkg.Client.OAuthClient.Query().Where(oauthclient.IDEQ(clientUUID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query client"})
		}
		return
	}

	// If request path contains /admin/, admin middleware already enforced
	if strings.Contains(c.Request.URL.Path, "/admin/") {
		c.JSON(http.StatusOK, clientResponse(client))
		return
	}

	// Otherwise ensure user is owner
	userIDRaw, ok := c.Get("user_id")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
		return
	}
	userIDStr, ok := userIDRaw.(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user id"})
		return
	}

	if client.OwnerID == nil || *client.OwnerID != userUUID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
		return
	}

	c.JSON(http.StatusOK, clientResponse(client))
}

// @Summary Create OAuth client
// @Description Create a new OAuth client
// @Tags clients
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body ClientCreateRequest true "Client creation request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients [post]
func createClientHandler(c *gin.Context) {
	var req ClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	req.RedirectUris = strings.TrimSpace(req.RedirectUris)
	if req.RedirectUris == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "redirect_uris is required"})
		return
	}

	allowedScopes := strings.TrimSpace(req.AllowedScopes)
	if allowedScopes == "" {
		allowedScopes = "openid profile"
	}

	secret, err := generateClientSecret()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate secret"})
		return
	}

	// Authorization: allow if admin (admin group) OR user has oauth:register permission
	if !strings.Contains(c.Request.URL.Path, "/admin/") {
		// Non-admin route: verify user and permission
		userIDRaw, ok := c.Get("user_id")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
			return
		}
		userIDStr, ok := userIDRaw.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
			return
		}
		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user id"})
			return
		}

		// Check permission oauth:register
		hasPerm, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).
			QueryRoles().
			QueryPermissions().
			Where(permission.KeyEQ("oauth:register")).
			Exist(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}
		if !hasPerm {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}
	}

	builder := dbpkg.Client.OAuthClient.Create().
		SetSecret(secret).
		SetRedirectUris(req.RedirectUris).
		SetAllowedScopes(allowedScopes).
		SetIsActive(true)

	if value := strings.TrimSpace(req.AppName); value != "" {
		builder = builder.SetAppName(value)
	}
	if value := strings.TrimSpace(req.Domain); value != "" {
		builder = builder.SetDomain(value)
	}
	if value := strings.TrimSpace(req.LogoURL); value != "" {
		builder = builder.SetLogoURL(value)
	}
	if ownerID := strings.TrimSpace(req.OwnerID); ownerID != "" {
		ownerUUID, err := uuid.Parse(ownerID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid owner_id"})
			return
		}
		builder = builder.SetOwnerID(ownerUUID)
	} else if userID, ok := c.Get("user_id"); ok {
		if userIDStr, ok := userID.(string); ok {
			if ownerUUID, err := uuid.Parse(userIDStr); err == nil {
				builder = builder.SetOwnerID(ownerUUID)
			}
		}
	}

	client, err := builder.Save(c.Request.Context())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create client"})
		return
	}

	response := clientResponse(client)
	response["secret"] = secret
	c.JSON(http.StatusOK, response)
}

// @Summary Update OAuth client
// @Description Update an existing OAuth client
// @Tags clients
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Client ID (UUID)"
// @Param body body ClientUpdateRequest true "Client update request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients/{id} [put]
func updateClientHandler(c *gin.Context) {
	clientUUID, ok := parseClientID(c)
	if !ok {
		return
	}

	var req ClientUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	builder := dbpkg.Client.OAuthClient.UpdateOneID(clientUUID)
	if req.AppName != nil {
		builder = builder.SetAppName(strings.TrimSpace(*req.AppName))
	}
	if req.Domain != nil {
		builder = builder.SetDomain(strings.TrimSpace(*req.Domain))
	}
	if req.RedirectUris != nil {
		redirectUris := strings.TrimSpace(*req.RedirectUris)
		if redirectUris == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "redirect_uris cannot be empty"})
			return
		}
		builder = builder.SetRedirectUris(redirectUris)
	}
	if req.AllowedScopes != nil {
		allowedScopes := strings.TrimSpace(*req.AllowedScopes)
		if allowedScopes == "" {
			allowedScopes = "openid profile"
		}
		builder = builder.SetAllowedScopes(allowedScopes)
	}
	if req.OwnerID != nil {
		ownerID := strings.TrimSpace(*req.OwnerID)
		if ownerID == "" {
			builder = builder.ClearOwnerID()
		} else {
			ownerUUID, err := uuid.Parse(ownerID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid owner_id"})
				return
			}
			builder = builder.SetOwnerID(ownerUUID)
		}
	}
	if req.IsActive != nil {
		builder = builder.SetIsActive(*req.IsActive)
	}
	if req.LogoURL != nil {
		builder = builder.SetLogoURL(strings.TrimSpace(*req.LogoURL))
	}

	client, err := builder.Save(c.Request.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update client"})
		}
		return
	}

	c.JSON(http.StatusOK, clientResponse(client))
}

// @Summary Disable OAuth client
// @Description Disable an OAuth client
// @Tags clients
// @Security BearerAuth
// @Produce json
// @Param id path string true "Client ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients/{id}/disable [post]
func disableClientHandler(c *gin.Context) {
	setClientActiveStatus(c, false)
}

// @Summary Enable OAuth client
// @Description Enable an OAuth client
// @Tags clients
// @Security BearerAuth
// @Produce json
// @Param id path string true "Client ID (UUID)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients/{id}/enable [post]
func enableClientHandler(c *gin.Context) {
	setClientActiveStatus(c, true)
}

func setClientActiveStatus(c *gin.Context, isActive bool) {
	clientUUID, ok := parseClientID(c)
	if !ok {
		return
	}

	client, err := dbpkg.Client.OAuthClient.UpdateOneID(clientUUID).SetIsActive(isActive).Save(c.Request.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update client"})
		}
		return
	}

	c.JSON(http.StatusOK, clientResponse(client))
}

// @Summary Rotate client secret
// @Description Generate and set a new secret for an OAuth client
// @Tags clients
// @Security BearerAuth
// @Produce json
// @Param id path string true "Client ID (UUID)"
// @Success 200 {object} map[string]interface{} "Returns client info with new secret"
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /clients/{id}/rotate-secret [post]
func rotateClientSecretHandler(c *gin.Context) {
	clientUUID, ok := parseClientID(c)
	if !ok {
		return
	}

	secret, err := generateClientSecret()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate secret"})
		return
	}

	client, err := dbpkg.Client.OAuthClient.UpdateOneID(clientUUID).SetSecret(secret).Save(c.Request.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate secret"})
		}
		return
	}

	response := clientResponse(client)
	response["secret"] = secret
	c.JSON(http.StatusOK, response)
}

func parseClientID(c *gin.Context) (uuid.UUID, bool) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing client ID"})
		return uuid.Nil, false
	}
	clientUUID, err := uuid.Parse(id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client ID"})
		return uuid.Nil, false
	}
	return clientUUID, true
}

func clientResponse(client *ent.OAuthClient) gin.H {
	response := gin.H{
		"id":             client.ID,
		"created_at":     client.CreatedAt,
		"updated_at":     client.UpdatedAt,
		"redirect_uris":  client.RedirectUris,
		"allowed_scopes": client.AllowedScopes,
		"is_active":      client.IsActive,
	}
	if client.Domain != nil {
		response["domain"] = *client.Domain
	}
	if client.AppName != nil {
		response["app_name"] = *client.AppName
	}
	if client.OwnerID != nil {
		response["owner_id"] = *client.OwnerID
	}
	if client.LogoURL != nil {
		response["logo_url"] = *client.LogoURL
	}
	return response
}

func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
