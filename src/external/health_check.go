package external

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/scope"
	dbpkg "sso-server/src/db"
)

// HealthCheckResult represents the result of a single endpoint check
type HealthCheckResult struct {
	ScopeKey       string
	Endpoint       string
	IsHealthy      bool
	AuthConfigured bool
	Message        string
}

// ValidateExternalEndpoint checks if a single external endpoint is properly configured
func ValidateExternalEndpoint(ctx context.Context, scopeEnt *ent.Scope) *HealthCheckResult {
	result := &HealthCheckResult{
		ScopeKey: scopeEnt.Key,
		Endpoint: derefString(scopeEnt.ExternalEndpoint),
	}

	// 1. Check if endpoint is set
	if strings.TrimSpace(result.Endpoint) == "" {
		result.IsHealthy = false
		result.Message = "endpoint is not configured"
		return result
	}

	// 2. Check if auth secret is configured
	authType := strings.ToUpper(strings.TrimSpace(derefString(scopeEnt.AuthType)))
	switch authType {
	case "":
		result.AuthConfigured = false
	case "API_KEY", "BEARER_TOKEN":
		secretEnv := strings.TrimSpace(derefString(scopeEnt.AuthSecretEnv))
		if secretEnv == "" {
			result.IsHealthy = false
			result.Message = fmt.Sprintf("auth type '%s' is set but auth_secret_env is not configured", authType)
			result.AuthConfigured = false
			return result
		}

		_, ok := os.LookupEnv(secretEnv)
		if !ok {
			result.IsHealthy = false
			result.Message = fmt.Sprintf("auth secret env var '%s' is not set", secretEnv)
			result.AuthConfigured = false
			return result
		}
		result.AuthConfigured = true

	default:
		result.IsHealthy = false
		result.Message = fmt.Sprintf("unsupported auth type: %s", authType)
		return result
	}

	// 3. Validate JSON schema if present
	jsonSchema := strings.TrimSpace(derefString(scopeEnt.JSONSchema))
	if jsonSchema != "" {
		var schemaObj map[string]any
		if err := json.Unmarshal([]byte(jsonSchema), &schemaObj); err != nil {
			result.IsHealthy = false
			result.Message = fmt.Sprintf("invalid JSON schema: %v", err)
			return result
		}
	}

	// 4. Try to reach the endpoint with a test request (without {user_id} substitution)
	testURL := strings.ReplaceAll(result.Endpoint, "{user_id}", "test-user")

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, testURL, nil)
	if err != nil {
		// If HEAD fails, try GET
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			result.IsHealthy = false
			result.Message = fmt.Sprintf("failed to create request: %v", err)
			return result
		}
	}

	req.Header.Set("Accept", "application/json")

	// Add auth headers for test request
	if authType != "" {
		secretEnv := derefString(scopeEnt.AuthSecretEnv)
		secret, _ := os.LookupEnv(secretEnv)

		switch authType {
		case "API_KEY":
			req.Header.Set("X-API-Key", secret)
		case "BEARER_TOKEN":
			req.Header.Set("Authorization", "Bearer "+secret)
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.IsHealthy = false
		result.Message = fmt.Sprintf("endpoint unreachable: %v", err)
		return result
	}
	defer resp.Body.Close()

	// Accept any non-5xx response as healthy (since we're using a test user_id)
	// 4xx errors are expected because test-user doesn't exist
	if resp.StatusCode >= http.StatusInternalServerError {
		result.IsHealthy = false
		result.Message = fmt.Sprintf("endpoint returned status %d", resp.StatusCode)
		return result
	}

	result.IsHealthy = true
	result.Message = fmt.Sprintf("endpoint is reachable (status: %d)", resp.StatusCode)
	return result
}

// HealthCheckExternalProviders validates all external provider endpoints on startup
func HealthCheckExternalProviders(ctx context.Context) {
	scopes, err := dbpkg.Client.Scope.Query().Where(scope.IsExternalEQ(true)).All(ctx)
	if err != nil {
		log.Printf("[WARN] Failed to query external scopes for health check: %v", err)
		return
	}

	if len(scopes) == 0 {
		log.Println("[INFO] No external scopes configured")
		return
	}

	log.Printf("[INFO] Validating %d external provider endpoint(s)...", len(scopes))

	hasWarnings := false
	for _, scopeEnt := range scopes {
		result := ValidateExternalEndpoint(ctx, scopeEnt)

		if result.IsHealthy {
			log.Printf("[INFO] ✓ Scope '%s': %s", result.ScopeKey, result.Message)
		} else {
			hasWarnings = true
			log.Printf("[WARN] ✗ Scope '%s': %s", result.ScopeKey, result.Message)
		}
	}

	if hasWarnings {
		log.Println("[WARN] Some external provider endpoints are misconfigured. Features may not work as expected.")
	} else {
		log.Println("[INFO] All external provider endpoints are properly configured")
	}
}
