package scopes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/scope"
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
	clientID, ok := c.Get("client_id")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing client context"})
		return
	}
	clientUUID, ok := clientID.(uuid.UUID)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client context"})
		return
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
	clientID, ok := c.Get("client_id")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing client context"})
		return
	}
	clientUUID, ok := clientID.(uuid.UUID)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid client context"})
		return
	}

	if requested := strings.TrimSpace(c.Query("client_id")); requested != "" {
		if requestedUUID, err := uuid.Parse(requested); err != nil || requestedUUID != clientUUID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client_id does not match"})
			return
		}
	}

	ctxBg := context.Background()
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
