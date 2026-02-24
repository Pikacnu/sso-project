package scopes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/role"
	"sso-server/ent/generated/scope"
	"sso-server/ent/generated/user"
	dbpkg "sso-server/src/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ScopeRegisterRequest struct {
	Scope            string         `json:"scope"`
	Description      string         `json:"description"`
	IsExternal       bool           `json:"is_external"`
	ExternalEndpoint string         `json:"external_endpoint"`
	ExternalMethod   string         `json:"external_method"`
	AuthType         string         `json:"auth_type"`
	AuthSecretEnv    string         `json:"auth_secret_env"`
	JSONSchema       map[string]any `json:"json_schema"`
	Data             string         `json:"data"`
}

type ScopeResponse struct {
	ID               string `json:"id"`
	ClientID         string `json:"client_id"`
	Key              string `json:"key"`
	Description      string `json:"description,omitempty"`
	CreatedAt        string `json:"created_at"`
	IsExternal       bool   `json:"is_external"`
	ExternalEndpoint string `json:"external_endpoint,omitempty"`
	ExternalMethod   string `json:"external_method,omitempty"`
	AuthType         string `json:"auth_type,omitempty"`
	AuthSecretEnv    string `json:"auth_secret_env,omitempty"`
	JSONSchema       string `json:"json_schema,omitempty"`
	Data             string `json:"data,omitempty"`
}

func RegisterScopeRoutes(router *gin.Engine) {
	routerGroup := router.Group("/scopes")
	routerGroup.POST("/register", registerScopeHandler)
	routerGroup.GET("", listScopesHandler)

	// Admin routes for scope management
	adminGroup := router.Group("/admin/scopes")
	adminGroup.Use(requireAdminRole())
	adminGroup.GET("", adminListScopesHandler)
	adminGroup.POST("", adminCreateScopeHandler)
	adminGroup.DELETE("/:id", adminDeleteScopeHandler)
}

// @Summary Register scope
// @Tags scopes
// @Accept json
// @Produce json
// @Param Authorization header string true "Client secret"
// @Param X-Client-ID header string true "Client UUID"
// @Param body body ScopeRegisterRequest true "Scope registration"
// @Success 200 {object} ScopeResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /scopes/register [post]
func registerScopeHandler(c *gin.Context) {
	var clientUUID uuid.UUID
	var ctxBg = context.Background()

	// Try to get client_id from context (client authentication)
	if clientID, ok := c.Get("client_id"); ok {
		if id, ok := clientID.(uuid.UUID); ok {
			clientUUID = id
		}
	}

	var req ScopeRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	req.Scope = strings.TrimSpace(req.Scope)
	if req.Scope == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Scope is required"})
		return
	}

	if req.IsExternal && strings.TrimSpace(req.ExternalEndpoint) == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "external_endpoint is required for external scopes"})
		return
	}
	// If no client context, try to obtain client_id from request (user flow)
	if clientUUID == uuid.Nil {
		// Expect client_id in JSONSchema for user flows
		if clientIDVal, ok := req.JSONSchema["client_id"].(string); ok && clientIDVal != "" {
			if id, err := uuid.Parse(clientIDVal); err == nil {
				clientUUID = id
			}
		}
		if clientUUID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing client context or client_id in request"})
			return
		}

		// If user auth, ensure user owns the client (non-admin)
		if userID, ok := c.Get("user_id"); ok {
			userUUID, ok := userID.(uuid.UUID)
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
				return
			}
			// Check ownership
			clientEnt, err := dbpkg.Client.OAuthClient.Get(ctxBg, clientUUID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
				return
			}
			if clientEnt.OwnerID == nil || *clientEnt.OwnerID != userUUID {
				// allow if admin
				hasAdmin, _ := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).QueryRoles().Where(role.NameEQ("admin")).Exist(ctxBg)
				if !hasAdmin {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User cannot register scopes for other clients"})
					return
				}
			}
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing client or user context"})
			return
		}
	}

	exists, err := dbpkg.Client.Scope.Query().Where(
		scope.ClientIDEQ(clientUUID),
		scope.KeyEQ(req.Scope),
	).Exist(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}
	if exists {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Scope already exists"})
		return
	}

	builder := dbpkg.Client.Scope.Create().
		SetClientID(clientUUID).
		SetKey(req.Scope).
		SetIsExternal(req.IsExternal)

	if value := strings.TrimSpace(req.Description); value != "" {
		builder = builder.SetDescription(value)
	}
	if value := strings.TrimSpace(req.ExternalEndpoint); value != "" {
		builder = builder.SetExternalEndpoint(value)
	}
	if value := strings.TrimSpace(req.ExternalMethod); value != "" {
		builder = builder.SetExternalMethod(value)
	}
	if value := strings.TrimSpace(req.AuthType); value != "" {
		builder = builder.SetAuthType(value)
	}
	if value := strings.TrimSpace(req.AuthSecretEnv); value != "" {
		builder = builder.SetAuthSecretEnv(value)
	}
	if len(req.JSONSchema) > 0 {
		payload, err := json.Marshal(req.JSONSchema)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid json_schema"})
			return
		}
		builder = builder.SetJSONSchema(strings.TrimSpace(string(payload)))
	}
	if value := strings.TrimSpace(req.Data); value != "" {
		builder = builder.SetData(value)
	}

	scopeEnt, err := builder.Save(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scope"})
		return
	}

	c.JSON(http.StatusOK, scopeResponse(scopeEnt))
}

// @Summary List scopes
// @Tags scopes
// @Produce json
// @Param Authorization header string true "Client secret"
// @Param X-Client-ID header string true "Client UUID"
// @Param client_id query string false "Client UUID"
// @Success 200 {array} ScopeResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /scopes [get]
func listScopesHandler(c *gin.Context) {
	var clientUUID uuid.UUID
	var ctxBg = context.Background()
	
	// Try to get client_id from context (client authentication)
	if clientID, ok := c.Get("client_id"); ok {
		if id, ok := clientID.(uuid.UUID); ok {
			clientUUID = id
		}
	}
	
	// If no client context, handle user or admin flows
	if clientUUID == uuid.Nil {
		// If client_id query provided, try to parse
		if requested := strings.TrimSpace(c.Query("client_id")); requested != "" {
			if requestedUUID, err := uuid.Parse(requested); err == nil {
				clientUUID = requestedUUID
			}
		}

		// If still no client UUID, require user context (non-client request)
		if clientUUID == uuid.Nil {
			userID, ok := c.Get("user_id")
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing client or user context"})
				return
			}
			userUUID, ok := userID.(uuid.UUID)
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
				return
			}

			// If not admin, user must provide client_id to list scopes and that client must be owned by them
			hasAdmin, err := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).QueryRoles().Where(role.NameEQ("admin")).Exist(ctxBg)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
				return
			}
			if !hasAdmin {
				// require client_id param for non-admin users
				requested := strings.TrimSpace(c.Query("client_id"))
				if requested == "" {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "client_id is required for non-admin users"})
					return
				}
				requestedUUID, err := uuid.Parse(requested)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
					return
				}
				// verify ownership
				clientEnt, err := dbpkg.Client.OAuthClient.Get(ctxBg, requestedUUID)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
					return
				}
				if clientEnt.OwnerID == nil || *clientEnt.OwnerID != userUUID {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Cannot view scopes for other clients"})
					return
				}
				clientUUID = requestedUUID
			}
		} else {
			// client_id was provided in query; if user context present and not admin, ensure ownership
			if userID, ok := c.Get("user_id"); ok {
				userUUID, ok := userID.(uuid.UUID)
				if ok {
					hasAdmin, _ := dbpkg.Client.User.Query().Where(user.IDEQ(userUUID)).QueryRoles().Where(role.NameEQ("admin")).Exist(ctxBg)
					if !hasAdmin {
						clientEnt, err := dbpkg.Client.OAuthClient.Get(ctxBg, clientUUID)
						if err != nil {
							c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
							return
						}
						if clientEnt.OwnerID == nil || *clientEnt.OwnerID != userUUID {
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Cannot view scopes for other clients"})
							return
						}
					}
				}
			} else {
				// no user context and no client auth: unauthorized
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing client or user context"})
				return
			}
		}
	}
	scopes, err := dbpkg.Client.Scope.Query().Where(scope.ClientIDEQ(clientUUID)).All(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}

	response := make([]gin.H, 0, len(scopes))
	for _, scopeEnt := range scopes {
		response = append(response, scopeResponse(scopeEnt))
	}

	c.JSON(http.StatusOK, response)
}

func scopeResponse(scopeEnt *ent.Scope) gin.H {
	response := gin.H{
		"id":          scopeEnt.ID,
		"client_id":   scopeEnt.ClientID,
		"key":         scopeEnt.Key,
		"created_at":  scopeEnt.CreatedAt,
		"is_external": scopeEnt.IsExternal,
	}

	if scopeEnt.Description != nil {
		response["description"] = *scopeEnt.Description
	}
	if scopeEnt.ExternalEndpoint != nil {
		response["external_endpoint"] = *scopeEnt.ExternalEndpoint
	}
	if scopeEnt.ExternalMethod != nil {
		response["external_method"] = *scopeEnt.ExternalMethod
	}
	if scopeEnt.AuthType != nil {
		response["auth_type"] = *scopeEnt.AuthType
	}
	if scopeEnt.AuthSecretEnv != nil {
		response["auth_secret_env"] = *scopeEnt.AuthSecretEnv
	}
	if scopeEnt.JSONSchema != nil {
		response["json_schema"] = *scopeEnt.JSONSchema
	}
	if scopeEnt.Data != nil {
		response["data"] = *scopeEnt.Data
	}

	return response
}

// requireAdminRole middleware to check if user has admin role
func requireAdminRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := c.Get("user_id")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing user context"})
			return
		}

		userUUID, ok := userID.(uuid.UUID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
			return
		}

		ctxBg := context.Background()
		hasRole, err := dbpkg.Client.User.Query().
			Where(user.IDEQ(userUUID)).
			QueryRoles().
			Where(role.NameEQ("admin")).
			Exist(ctxBg)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if !hasRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User does not have admin permission"})
			return
		}

		c.Next()
	}
}

// @Summary List all scopes (admin)
// @Tags admin/scopes
// @Produce json
// @Param client_id query string false "Filter by client ID"
// @Success 200 {array} ScopeResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /admin/scopes [get]
func adminListScopesHandler(c *gin.Context) {
	ctxBg := context.Background()

	// Build query
	query := dbpkg.Client.Scope.Query()

	// Filter by client_id if provided
	if clientIDStr := strings.TrimSpace(c.Query("client_id")); clientIDStr != "" {
		if clientUUID, err := uuid.Parse(clientIDStr); err == nil {
			query = query.Where(scope.ClientIDEQ(clientUUID))
		}
	}

	scopes, err := query.All(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}

	response := make([]gin.H, 0, len(scopes))
	for _, scopeEnt := range scopes {
		response = append(response, scopeResponse(scopeEnt))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Create scope (admin)
// @Tags admin/scopes
// @Accept json
// @Produce json
// @Param body body ScopeRegisterRequest true "Scope with client_id in json_schema"
// @Success 200 {object} ScopeResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /admin/scopes [post]
func adminCreateScopeHandler(c *gin.Context) {
	var req ScopeRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	req.Scope = strings.TrimSpace(req.Scope)
	if req.Scope == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Scope is required"})
		return
	}

	// Get client_id from json_schema field (admin panel passes it there)
	var clientUUID uuid.UUID
	if clientIDVal, ok := req.JSONSchema["client_id"].(string); ok && clientIDVal != "" {
		if id, err := uuid.Parse(clientIDVal); err == nil {
			clientUUID = id
		}
	}

	if clientUUID == uuid.Nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "client_id is required in json_schema"})
		return
	}

	if req.IsExternal && strings.TrimSpace(req.ExternalEndpoint) == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "external_endpoint is required for external scopes"})
		return
	}

	ctxBg := context.Background()
	exists, err := dbpkg.Client.Scope.Query().Where(
		scope.ClientIDEQ(clientUUID),
		scope.KeyEQ(req.Scope),
	).Exist(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}
	if exists {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Scope already exists"})
		return
	}

	builder := dbpkg.Client.Scope.Create().
		SetClientID(clientUUID).
		SetKey(req.Scope).
		SetIsExternal(req.IsExternal)

	if value := strings.TrimSpace(req.Description); value != "" {
		builder = builder.SetDescription(value)
	}
	if value := strings.TrimSpace(req.ExternalEndpoint); value != "" {
		builder = builder.SetExternalEndpoint(value)
	}
	if value := strings.TrimSpace(req.ExternalMethod); value != "" {
		builder = builder.SetExternalMethod(value)
	}
	if value := strings.TrimSpace(req.AuthType); value != "" {
		builder = builder.SetAuthType(value)
	}
	if value := strings.TrimSpace(req.AuthSecretEnv); value != "" {
		builder = builder.SetAuthSecretEnv(value)
	}
	if len(req.JSONSchema) > 1 { // > 1 because client_id is in there
		// Remove client_id before saving
		schemaCopy := make(map[string]any)
		for k, v := range req.JSONSchema {
			if k != "client_id" {
				schemaCopy[k] = v
			}
		}
		if len(schemaCopy) > 0 {
			payload, err := json.Marshal(schemaCopy)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid json_schema"})
				return
			}
			builder = builder.SetJSONSchema(strings.TrimSpace(string(payload)))
		}
	}
	if value := strings.TrimSpace(req.Data); value != "" {
		builder = builder.SetData(value)
	}

	scopeEnt, err := builder.Save(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scope"})
		return
	}

	c.JSON(http.StatusOK, scopeResponse(scopeEnt))
}

// @Summary Delete scope (admin)
// @Tags admin/scopes
// @Produce json
// @Param id path string true "Scope ID (UUID)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /admin/scopes/{id} [delete]
func adminDeleteScopeHandler(c *gin.Context) {
	idStr := c.Param("id")
	scopeUUID, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid scope ID format"})
		return
	}

	ctxBg := context.Background()
	
	// Check if scope exists
	scopeEnt, err := dbpkg.Client.Scope.Get(ctxBg, scopeUUID)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Scope not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scope"})
		}
		return
	}

	// Delete the scope
	err = dbpkg.Client.Scope.DeleteOne(scopeEnt).Exec(ctxBg)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scope"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scope deleted successfully"})
}
