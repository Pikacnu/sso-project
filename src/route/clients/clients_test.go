package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/permission"
	"sso-server/ent/generated/role"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func setupClientTestRouterWithUser(userID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.Use(func(c *gin.Context) {
		c.Set("user_id", userID.String())
		c.Set("roles", []string{"user"})
	})

	RegisterClientRoutes(router)
	return router
}

func performClientRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// createTestUserWithPermission creates a user and assigns the oauth:register permission via a role
func createTestUserWithPermission(t *testing.T, client *ent.Client) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	// Ensure role exists
	var rEnt *ent.Role
	rEnt, err := client.Role.Query().Where(role.NameEQ("user")).First(ctx)
	if err != nil {
		rEnt, err = client.Role.Create().SetName("user").Save(ctx)
		if err != nil {
			t.Fatalf("failed to create role: %v", err)
		}
	}

	// Ensure permission exists
	var pEnt *ent.Permission
	pEnt, err = client.Permission.Query().Where(permission.KeyEQ("oauth:register")).First(ctx)
	if err != nil {
		pEnt, err = client.Permission.Create().SetKey("oauth:register").SetDescription("Register OAuth clients").Save(ctx)
		if err != nil {
			t.Fatalf("failed to create permission: %v", err)
		}
	}

	// Link permission to role
	if err := client.Role.UpdateOneID(rEnt.ID).AddPermissions(pEnt).Exec(ctx); err != nil {
		t.Fatalf("failed to add permission to role: %v", err)
	}

	// Create user
	userID := uuid.New()
	u, err := client.User.Create().SetID(userID).SetUsername("testuser-").SetEmail(userID.String() + "@test.example.com").Save(ctx)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Assign role to user
	if _, err := client.User.UpdateOneID(u.ID).AddRoles(rEnt).Save(ctx); err != nil {
		t.Fatalf("failed to add role to user: %v", err)
	}

	return u.ID
}

func TestCreateClient_AsUserWithPermission_Succeeds(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	userID := createTestUserWithPermission(t, client)
	r := setupClientTestRouterWithUser(userID)

	body := `{"app_name":"My App","redirect_uris":"https://example.com/callback","allowed_scopes":"openid","logo_url":"https://example.com/logo.png"}`

	w := performClientRequest(r, http.MethodPost, "/clients", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["owner_id"] == nil {
		t.Fatalf("expected owner_id to be set")
	}
	if resp["secret"] == nil {
		t.Fatalf("expected secret to be returned")
	}
}

func TestListClients_OnlyOwnClients(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()

	userA := createTestUserWithPermission(t, client)
	userB := uuid.New()
	// Create userB without permission
	_, err := client.User.Create().SetID(userB).SetUsername("other").SetEmail(userB.String() + "@test.example.com").Save(ctx)
	if err != nil {
		t.Fatalf("failed to create userB: %v", err)
	}

	// Create two clients owned by different users
	clientAID := uuid.New()
	if _, err := client.OAuthClient.Create().SetID(clientAID).SetOwnerID(userA).SetSecret("s").SetRedirectUris("https://a").Save(ctx); err != nil {
		t.Fatalf("failed to create clientA: %v", err)
	}
	clientBID := uuid.New()
	if _, err := client.OAuthClient.Create().SetID(clientBID).SetOwnerID(userB).SetSecret("s").SetRedirectUris("https://b").Save(ctx); err != nil {
		t.Fatalf("failed to create clientB: %v", err)
	}

	r := setupClientTestRouterWithUser(userA)

	w := performClientRequest(r, http.MethodGet, "/clients", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for list, got %d, body: %s", w.Code, w.Body.String())
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("expected 1 client for userA, got %d", len(list))
	}
	if list[0]["owner_id"] == nil {
		t.Fatalf("expected owner_id present")
	}
}

func TestManagementEndpoints_ForbiddenForNonAdmin(t *testing.T) {
	client := openTestDB(t)
	defer client.Close()
	defer cleanDB(t, client)

	ctx := context.Background()
	userID := createTestUserWithPermission(t, client)

	// create an oauth client
	cid := uuid.New()
	if _, err := client.OAuthClient.Create().SetID(cid).SetOwnerID(userID).SetSecret("s").SetRedirectUris("https://x").Save(ctx); err != nil {
		t.Fatalf("failed to create oauth client: %v", err)
	}

	r := setupClientTestRouterWithUser(userID)
	// Attempt disable on public route (should return 403 per handler)
	w := performClientRequest(r, http.MethodPost, "/clients/"+cid.String()+"/disable", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disable, got %d, body: %s", w.Code, w.Body.String())
	}
}
