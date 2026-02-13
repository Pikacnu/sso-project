package external

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	ent "sso-server/ent/generated"
)

const (
	authTypeAPIKey      = "API_KEY"
	authTypeBearerToken = "BEARER_TOKEN"
)

func FetchExternalClaims(ctx context.Context, httpClient *http.Client, scopeEnt *ent.Scope, userID string) (map[string]any, []SchemaError, error) {
	if scopeEnt == nil {
		return nil, nil, errors.New("scope is nil")
	}
	if !scopeEnt.IsExternal {
		return nil, nil, errors.New("scope is not external")
	}

	endpoint := strings.TrimSpace(derefString(scopeEnt.ExternalEndpoint))
	if endpoint == "" {
		return nil, nil, errors.New("external endpoint is empty")
	}
	url := strings.ReplaceAll(endpoint, "{user_id}", userID)

	method := strings.ToUpper(strings.TrimSpace(derefString(scopeEnt.ExternalMethod)))
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")

	authType := strings.ToUpper(strings.TrimSpace(derefString(scopeEnt.AuthType)))
	switch authType {
	case "":
		// No auth configured.
	case authTypeAPIKey:
		secret, err := getSecretFromEnv(scopeEnt.AuthSecretEnv)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("X-API-Key", secret)
	case authTypeBearerToken:
		secret, err := getSecretFromEnv(scopeEnt.AuthSecretEnv)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
	default:
		return nil, nil, fmt.Errorf("unsupported auth type: %s", authType)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, fmt.Errorf("external endpoint returned status %d", resp.StatusCode)
	}

	var payload map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, nil, err
	}

	filtered, schemaErrors, err := ValidateAndFilterClaims(derefString(scopeEnt.JSONSchema), payload)
	if err != nil {
		return nil, nil, err
	}

	return filtered, schemaErrors, nil
}

func getSecretFromEnv(envNamePtr *string) (string, error) {
	name := strings.TrimSpace(derefString(envNamePtr))
	if name == "" {
		return "", errors.New("auth secret env is empty")
	}
	secret, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("auth secret env not set: %s", name)
	}
	return secret, nil
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
