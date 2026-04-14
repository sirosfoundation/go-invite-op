package op

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-invite-op/internal/config"
	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/email"
	"github.com/sirosfoundation/go-invite-op/internal/storage/memory"
)

func testConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			BaseURL: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret: "test-secret-key-for-testing-only",
			Issuer: "go-invite-op-test",
		},
		OP: config.OPConfig{
			SessionTimeout:     600,
			CleanupIntervalSec: 3600,
		},
	}
}

func setupProvider(t *testing.T) (*Provider, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider := NewProvider(store, cfg, emailer, logger)

	router := gin.New()
	provider.RegisterRoutes(router)
	return provider, router
}

func TestDiscovery(t *testing.T) {
	_, router := setupProvider(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test-tenant/.well-known/openid-configuration", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080/test-tenant", body["issuer"])
	assert.Equal(t, "http://localhost:8080/test-tenant/authorize", body["authorization_endpoint"])
	assert.Equal(t, "http://localhost:8080/test-tenant/token", body["token_endpoint"])
	assert.Equal(t, "http://localhost:8080/test-tenant/register", body["registration_endpoint"])
}

func TestRegisterClient(t *testing.T) {
	_, router := setupProvider(t)

	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "TestApp"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["client_id"])
	assert.NotEmpty(t, resp["client_secret"])
	assert.Equal(t, "TestApp", resp["client_name"])
}

func TestRegisterClientMissingRedirectURIs(t *testing.T) {
	_, router := setupProvider(t)

	body := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthorizeGetMissingResponseType(t *testing.T) {
	_, router := setupProvider(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test-tenant/authorize?client_id=xxx", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthorizeGetInvalidClient(t *testing.T) {
	_, router := setupProvider(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test-tenant/authorize?response_type=code&client_id=nonexistent&redirect_uri=http://localhost/cb", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFullAuthFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider := NewProvider(store, cfg, emailer, logger)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Step 1: Register a client
	regBody := `{"redirect_uris": ["http://localhost:3000/callback"]}`
	regReq, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)
	require.Equal(t, http.StatusCreated, regW.Code)

	var regResp map[string]interface{}
	require.NoError(t, json.Unmarshal(regW.Body.Bytes(), &regResp))
	clientID := regResp["client_id"].(string)
	clientSecret := regResp["client_secret"].(string)

	// Step 2: Create an invite
	ctx := regReq.Context()
	invite := &domain.Invite{
		ID:        "invite-1",
		TenantID:  "test-tenant",
		Email:     "user@example.com",
		Code:      "TESTCODE123",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	// Step 3: Start authorization
	authURL := "/test-tenant/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/callback") +
		"&state=teststate&nonce=testnonce"
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code)
	assert.Contains(t, authW.Body.String(), "session_id")

	// Extract session_id from form
	bodyStr := authW.Body.String()
	sessionStart := strings.Index(bodyStr, `value="`) + len(`value="`)
	sessionEnd := strings.Index(bodyStr[sessionStart:], `"`)
	sessionID := bodyStr[sessionStart : sessionStart+sessionEnd]

	// Step 4: Submit email
	emailForm := url.Values{
		"session_id": {sessionID},
		"email":      {"user@example.com"},
	}
	emailW := httptest.NewRecorder()
	emailReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(emailForm.Encode()))
	emailReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(emailW, emailReq)
	require.Equal(t, http.StatusOK, emailW.Code)
	assert.Contains(t, emailW.Body.String(), "invite code")

	// Step 5: Submit code
	codeForm := url.Values{
		"session_id": {sessionID},
		"code":       {"TESTCODE123"},
	}
	codeW := httptest.NewRecorder()
	codeReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(codeW, codeReq)
	require.Equal(t, http.StatusFound, codeW.Code)

	// Extract auth code from redirect
	location := codeW.Header().Get("Location")
	require.NotEmpty(t, location)
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	authCode := redirectURL.Query().Get("code")
	assert.NotEmpty(t, authCode)
	assert.Equal(t, "teststate", redirectURL.Query().Get("state"))

	// Step 6: Token exchange
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"http://localhost:3000/callback"},
	}
	tokenW := httptest.NewRecorder()
	tokenReq, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(tokenW, tokenReq)
	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &tokenResp))
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.NotEmpty(t, tokenResp["id_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])
}

func TestTokenInvalidGrantType(t *testing.T) {
	_, router := setupProvider(t)

	form := url.Values{"grant_type": {"implicit"}}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenInvalidClient(t *testing.T) {
	_, router := setupProvider(t)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid"},
		"client_id":     {"nonexistent"},
		"client_secret": {"wrong"},
	}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
