package external

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	ent "sso-server/ent/generated"
	"sso-server/src/config"
)

type CacheEntry struct {
	Claims       map[string]any
	SchemaErrors []SchemaError
	ExpiresAt    time.Time
}

type ExternalClaimsCache struct {
	mu    sync.RWMutex
	cache map[string]*CacheEntry
	ttl   time.Duration
}

func NewExternalClaimsCache(
	ttlSeconds int,
) *ExternalClaimsCache {
	var ttl time.Duration
	if ttlStr, ok := os.LookupEnv("EXTERNAL_CACHE_TTL"); ok {
		var ttlSeconds int
		_, err := fmt.Sscanf(ttlStr, "%d", &ttlSeconds)
		if err == nil && ttlSeconds > 0 {
			ttl = time.Duration(ttlSeconds) * time.Second
		}
	}

	return &ExternalClaimsCache{
		cache: make(map[string]*CacheEntry),
		ttl:   ttl,
	}
}

func (c *ExternalClaimsCache) getCacheKey(userID, scopeKey string) string {
	return fmt.Sprintf("%s:%s", userID, scopeKey)
}

func (c *ExternalClaimsCache) Get(userID, scopeKey string) (map[string]any, []SchemaError, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.getCacheKey(userID, scopeKey)
	entry, exists := c.cache[key]
	if !exists {
		return nil, nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, nil, false
	}

	return entry.Claims, entry.SchemaErrors, true
}

func (c *ExternalClaimsCache) Set(userID, scopeKey string, claims map[string]any, schemaErrors []SchemaError) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.getCacheKey(userID, scopeKey)
	c.cache[key] = &CacheEntry{
		Claims:       claims,
		SchemaErrors: schemaErrors,
		ExpiresAt:    time.Now().Add(c.ttl),
	}
}

func (c *ExternalClaimsCache) InvalidateUser(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := fmt.Sprintf("%s:", userID)
	for key := range c.cache {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			delete(c.cache, key)
		}
	}
}

func (c *ExternalClaimsCache) InvalidateScope(scopeKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	suffix := fmt.Sprintf(":%s", scopeKey)
	for key := range c.cache {
		// Simple string suffix matching
		if len(key) > len(suffix) && key[len(key)-len(suffix):] == suffix {
			delete(c.cache, key)
		}
	}
}

func (c *ExternalClaimsCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CacheEntry)
}

var claimsCache = NewExternalClaimsCache(
	config.SystemEnv.ExternalCacheTTLSeconds,
)

// CachedFetchExternalClaims fetches external claims with in-memory caching
// Returns cached claims if available and not expired, otherwise fetches from external endpoint
func CachedFetchExternalClaims(ctx context.Context, httpClient *http.Client, scopeEnt *ent.Scope, userID string) (map[string]any, []SchemaError, error) {
	// Try to get from cache first
	claims, schemaErrors, found := claimsCache.Get(userID, scopeEnt.Key)
	if found {
		return claims, schemaErrors, nil
	}

	// Cache miss, fetch from external endpoint
	claims, schemaErrors, err := FetchExternalClaims(ctx, httpClient, scopeEnt, userID)
	if err != nil {
		return nil, nil, err
	}

	// Store in cache
	claimsCache.Set(userID, scopeEnt.Key, claims, schemaErrors)

	return claims, schemaErrors, nil
}

// InvalidateUserCache removes cached claims for a user
func InvalidateUserCache(userID string) {
	claimsCache.InvalidateUser(userID)
}

// InvalidateScopeCache removes cached claims for a scope
func InvalidateScopeCache(scopeKey string) {
	claimsCache.InvalidateScope(scopeKey)
}

// ClearCache removes all cached claims (useful for testing)
func ClearCache() {
	claimsCache.Clear()
}
