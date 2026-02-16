package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/accesstoken"
	"sso-server/ent/generated/scope"
	"sso-server/src/auth"
	dbpkg "sso-server/src/db"
	"sso-server/src/external"

	"github.com/gin-gonic/gin"
)

// @Summary User info
// @Tags auth
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} UserInfoResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/userinfo [get]
func userInfoHandler(c *gin.Context) {
	rawToken := c.Request.Header.Get("Authorization")
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || !strings.HasPrefix(rawToken, "Bearer ") {
		c.AbortWithStatusJSON(401, gin.H{"error": "Missing Authorization header"})
		return
	}
	tokenString := strings.TrimPrefix(rawToken, "Bearer ")

	claims, err := auth.ValidateJWT(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		return
	}

	ctx := c.Request.Context()
	atEnt, err := dbpkg.Client.AccessToken.Query().Where(accesstoken.TokenEQ(tokenString)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		} else {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		}
		return
	}

	scopeStr := ""
	if atEnt.Scope != nil {
		scopeStr = *atEnt.Scope
	}
	scopes := parseScopeList(scopeStr)
	if !slices.Contains(scopes, "sso.profile") {
		c.AbortWithStatusJSON(403, gin.H{"error": "Insufficient scope"})
		return
	}

	userEnt, err := dbpkg.Client.User.Get(ctx, atEnt.UserID)
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Failed to load user"})
		return
	}

	response := gin.H{
		"sub":            claims.Sub,
		"email":          userEnt.Email,
		"email_verified": userEnt.EmailVerified,
		"exp":            claims.ExpiresAt,
	}

	externalScopes, err := dbpkg.Client.Scope.Query().Where(
		scope.ClientIDEQ(atEnt.ClientID),
		scope.KeyIn(scopes...),
		scope.IsExternalEQ(true),
	).All(ctx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to query scopes"})
		return
	}

	if len(externalScopes) > 0 {
		type externalResult struct {
			key          string
			claims       map[string]any
			schemaErrors []external.SchemaError
			err          error
		}

		results := make(chan externalResult, len(externalScopes))
		httpClient := &http.Client{Timeout: 5 * time.Second}

		for _, scopeEnt := range externalScopes {
			scopeEnt := scopeEnt
			go func() {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				claims, schemaErrors, err := external.CachedFetchExternalClaims(ctx, httpClient, scopeEnt, atEnt.UserID.String())
				results <- externalResult{
					key:          scopeEnt.Key,
					claims:       claims,
					schemaErrors: schemaErrors,
					err:          err,
				}
			}()
		}

		var errorsList []gin.H
		for i := 0; i < len(externalScopes); i++ {
			result := <-results
			if result.err != nil {
				errorsList = append(errorsList, gin.H{
					"scope":   result.key,
					"error":   "external_fetch",
					"message": result.err.Error(),
				})
				continue
			}
			if len(result.claims) > 0 {
				response[result.key] = result.claims
			}
			if len(result.schemaErrors) > 0 {
				errorsList = append(errorsList, gin.H{
					"scope":   result.key,
					"error":   "schema_validation",
					"message": "Some fields were removed due to schema mismatch",
					"details": result.schemaErrors,
				})
			}
		}
		if len(errorsList) > 0 {
			response["_errors"] = errorsList
		}
	}

	c.JSON(200, response)
}

type ExternalError struct {
	Scope   string                 `json:"scope"`
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Details []external.SchemaError `json:"details,omitempty"`
}

type UserInfoResponse struct {
	Sub           string          `json:"sub"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	Exp           any             `json:"exp"`
	Errors        []ExternalError `json:"_errors,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func parseScopeList(scopeStr string) []string {
	if strings.TrimSpace(scopeStr) == "" {
		return nil
	}

	parts := strings.Split(scopeStr, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		scopes = append(scopes, trimmed)
	}
	return scopes
}
