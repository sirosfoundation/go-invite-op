package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-invite-op/internal/storage/memory"
)

func setupTestRouter() (*gin.Engine, *Handlers) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	logger, _ := zap.NewDevelopment()
	handlers := NewHandlers(store, logger)

	router := gin.New()
	// Simulate tenant context from JWT middleware
	group := router.Group("/api/v1", func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	handlers.RegisterRoutes(group)
	return router, handlers
}

func TestCreateInvite(t *testing.T) {
	router, _ := setupTestRouter()

	body := `{"email": "user@example.com", "max_uses": 3, "ttl_seconds": 3600}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusCreated, resp.Code)

	var result InviteResponse
	err := json.Unmarshal(resp.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", result.Email)
	assert.Equal(t, 3, result.MaxUses)
	assert.NotEmpty(t, result.Code)
	assert.NotEmpty(t, result.ID)
	assert.Equal(t, "test-tenant", result.TenantID)
	assert.NotEmpty(t, result.ExpiresAt)
}

func TestCreateInviteWithCode(t *testing.T) {
	router, _ := setupTestRouter()

	body := `{"email": "@example.com", "code": "my-custom-code"}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusCreated, resp.Code)

	var result InviteResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Equal(t, "my-custom-code", result.Code)
}

func TestCreateInviteMissingEmail(t *testing.T) {
	router, _ := setupTestRouter()

	body := `{"max_uses": 3}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestListInvites(t *testing.T) {
	router, _ := setupTestRouter()

	// Create two invites
	for _, email := range []string{"a@b.com", "c@d.com"} {
		body := `{"email": "` + email + `"}`
		req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		require.Equal(t, http.StatusCreated, resp.Code)
	}

	req, _ := http.NewRequest("GET", "/api/v1/invites", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var result []*InviteResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Len(t, result, 2)
}

func TestGetInvite(t *testing.T) {
	router, _ := setupTestRouter()

	// Create
	body := `{"email": "user@example.com"}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created InviteResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))

	// Get
	req, _ = http.NewRequest("GET", "/api/v1/invites/"+created.ID, nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	var got InviteResponse
	json.Unmarshal(resp.Body.Bytes(), &got)
	assert.Equal(t, created.ID, got.ID)
}

func TestGetInviteNotFound(t *testing.T) {
	router, _ := setupTestRouter()

	req, _ := http.NewRequest("GET", "/api/v1/invites/nonexistent", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestUpdateInvite(t *testing.T) {
	router, _ := setupTestRouter()

	// Create
	body := `{"email": "user@example.com", "max_uses": 3}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created InviteResponse
	json.Unmarshal(resp.Body.Bytes(), &created)

	// Update
	newMaxUses := 10
	updateBody := `{"max_uses": 10}`
	req, _ = http.NewRequest("PUT", "/api/v1/invites/"+created.ID, bytes.NewBufferString(updateBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	var updated InviteResponse
	json.Unmarshal(resp.Body.Bytes(), &updated)
	assert.Equal(t, newMaxUses, updated.MaxUses)
}

func TestDeleteInvite(t *testing.T) {
	router, _ := setupTestRouter()

	// Create
	body := `{"email": "user@example.com"}`
	req, _ := http.NewRequest("POST", "/api/v1/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created InviteResponse
	json.Unmarshal(resp.Body.Bytes(), &created)

	// Delete
	req, _ = http.NewRequest("DELETE", "/api/v1/invites/"+created.ID, nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNoContent, resp.Code)

	// Verify gone
	req, _ = http.NewRequest("GET", "/api/v1/invites/"+created.ID, nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestDeleteInviteNotFound(t *testing.T) {
	router, _ := setupTestRouter()

	req, _ := http.NewRequest("DELETE", "/api/v1/invites/nonexistent", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNotFound, resp.Code)
}
