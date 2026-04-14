package op

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
	provider, err := NewProvider(store, cfg, emailer, logger)
	require.NoError(t, err)

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
	assert.Equal(t, "http://localhost:8080/test-tenant/.well-known/jwks.json", body["jwks_uri"])

	// Should advertise PKCE and public client support
	authMethods := body["token_endpoint_auth_methods_supported"].([]interface{})
	assert.Contains(t, authMethods, "client_secret_post")
	assert.Contains(t, authMethods, "none")
	challengeMethods := body["code_challenge_methods_supported"].([]interface{})
	assert.Contains(t, challengeMethods, "S256")
}

func TestJWKS(t *testing.T) {
	_, router := setupProvider(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test-tenant/.well-known/jwks.json", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	keys, ok := body["keys"].([]interface{})
	require.True(t, ok)
	require.Len(t, keys, 1)

	jwk := keys[0].(map[string]interface{})
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "RS256", jwk["alg"])
	assert.NotEmpty(t, jwk["kid"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
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
	assert.Equal(t, "client_secret_post", resp["token_endpoint_auth_method"])
}

func TestRegisterPublicClient(t *testing.T) {
	_, router := setupProvider(t)

	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "SPA", "token_endpoint_auth_method": "none"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["client_id"])
	assert.Nil(t, resp["client_secret"]) // public client has no secret
	assert.Equal(t, "SPA", resp["client_name"])
	assert.Equal(t, "none", resp["token_endpoint_auth_method"])
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
	provider, err := NewProvider(store, cfg, emailer, logger)
	require.NoError(t, err)

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

	// Verify the ID token is a valid RS256 JWT with kid header
	idTokenStr := tokenResp["id_token"].(string)
	parsed, err := jwt.Parse(idTokenStr, func(tok *jwt.Token) (interface{}, error) {
		assert.Equal(t, jwt.SigningMethodRS256, tok.Method)
		assert.NotEmpty(t, tok.Header["kid"])
		return provider.signingKey.Public(), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "user@example.com", claims["email"])
	assert.Equal(t, "testnonce", claims["nonce"])
}

func TestFullAuthFlowPKCE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider, err := NewProvider(store, cfg, emailer, logger)
	require.NoError(t, err)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Step 1: Register a public client (token_endpoint_auth_method=none)
	regBody := `{"redirect_uris": ["http://localhost:3000/callback"], "token_endpoint_auth_method": "none"}`
	regReq, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)
	require.Equal(t, http.StatusCreated, regW.Code)

	var regResp map[string]interface{}
	require.NoError(t, json.Unmarshal(regW.Body.Bytes(), &regResp))
	clientID := regResp["client_id"].(string)
	assert.Nil(t, regResp["client_secret"]) // public client

	// Step 2: Create an invite
	ctx := regReq.Context()
	invite := &domain.Invite{
		ID:        "invite-pkce",
		TenantID:  "test-tenant",
		Email:     "pkce@example.com",
		Code:      "PKCECODE",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	// Step 3: Generate PKCE code_verifier and code_challenge
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Step 4: Start authorization with PKCE
	authURL := "/test-tenant/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/callback") +
		"&state=pkcestate&nonce=pkcenonce" +
		"&code_challenge=" + codeChallenge +
		"&code_challenge_method=S256"
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code)

	// Extract session_id
	bodyStr := authW.Body.String()
	sessionStart := strings.Index(bodyStr, `value="`) + len(`value="`)
	sessionEnd := strings.Index(bodyStr[sessionStart:], `"`)
	sessionID := bodyStr[sessionStart : sessionStart+sessionEnd]

	// Step 5: Submit email
	emailForm := url.Values{"session_id": {sessionID}, "email": {"pkce@example.com"}}
	emailW := httptest.NewRecorder()
	emailReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(emailForm.Encode()))
	emailReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(emailW, emailReq)
	require.Equal(t, http.StatusOK, emailW.Code)

	// Step 6: Submit code
	codeForm := url.Values{"session_id": {sessionID}, "code": {"PKCECODE"}}
	codeW := httptest.NewRecorder()
	codeReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(codeW, codeReq)
	require.Equal(t, http.StatusFound, codeW.Code)

	location := codeW.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	authCode := redirectURL.Query().Get("code")
	assert.NotEmpty(t, authCode)
	assert.Equal(t, "pkcestate", redirectURL.Query().Get("state"))

	// Step 7: Token exchange with code_verifier (no client_secret)
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {"http://localhost:3000/callback"},
	}
	tokenW := httptest.NewRecorder()
	tokenReq, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(tokenW, tokenReq)
	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &tokenResp))
	assert.NotEmpty(t, tokenResp["id_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])

	// Verify the token is signed with RS256 and has kid
	idTokenStr := tokenResp["id_token"].(string)
	parsed, err := jwt.Parse(idTokenStr, func(tok *jwt.Token) (interface{}, error) {
		assert.Equal(t, jwt.SigningMethodRS256, tok.Method)
		assert.NotEmpty(t, tok.Header["kid"])
		return provider.signingKey.Public(), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "pkce@example.com", claims["email"])
	assert.Equal(t, "pkcenonce", claims["nonce"])
}

func TestPKCERequiredForPublicClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider, err := NewProvider(store, cfg, emailer, logger)
	require.NoError(t, err)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Register public client
	regBody := `{"redirect_uris": ["http://localhost:3000/cb"], "token_endpoint_auth_method": "none"}`
	regReq, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)
	require.Equal(t, http.StatusCreated, regW.Code)

	var regResp map[string]interface{}
	require.NoError(t, json.Unmarshal(regW.Body.Bytes(), &regResp))
	clientID := regResp["client_id"].(string)

	// Authorize without code_challenge → should fail
	authURL := "/test-tenant/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/cb")
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	assert.Equal(t, http.StatusBadRequest, authW.Code)

	var errResp map[string]interface{}
	require.NoError(t, json.Unmarshal(authW.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestPKCEWrongVerifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider, err := NewProvider(store, cfg, emailer, logger)
	require.NoError(t, err)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Register public client
	regBody := `{"redirect_uris": ["http://localhost:3000/callback"], "token_endpoint_auth_method": "none"}`
	regReq, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)
	require.Equal(t, http.StatusCreated, regW.Code)

	var regResp map[string]interface{}
	require.NoError(t, json.Unmarshal(regW.Body.Bytes(), &regResp))
	clientID := regResp["client_id"].(string)

	// Create invite
	invite := &domain.Invite{
		ID: "inv-wrong", TenantID: "test-tenant", Email: "wrong@example.com",
		Code: "WRONGCODE", MaxUses: 5, ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(regReq.Context(), invite))

	// Generate PKCE
	codeVerifier := "correct-verifier-value-for-testing"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Authorize with PKCE
	authURL := "/test-tenant/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/callback") +
		"&code_challenge=" + codeChallenge + "&code_challenge_method=S256"
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code)

	bodyStr := authW.Body.String()
	sessionStart := strings.Index(bodyStr, `value="`) + len(`value="`)
	sessionEnd := strings.Index(bodyStr[sessionStart:], `"`)
	sessionID := bodyStr[sessionStart : sessionStart+sessionEnd]

	// Submit email + code
	emailForm := url.Values{"session_id": {sessionID}, "email": {"wrong@example.com"}}
	emailW := httptest.NewRecorder()
	emailReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(emailForm.Encode()))
	emailReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(emailW, emailReq)

	codeForm := url.Values{"session_id": {sessionID}, "code": {"WRONGCODE"}}
	codeW := httptest.NewRecorder()
	codeReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(codeW, codeReq)
	require.Equal(t, http.StatusFound, codeW.Code)

	location := codeW.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	authCode := redirectURL.Query().Get("code")

	// Token exchange with WRONG verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"code_verifier": {"wrong-verifier-value"},
		"redirect_uri":  {"http://localhost:3000/callback"},
	}
	tokenW := httptest.NewRecorder()
	tokenReq, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(tokenW, tokenReq)
	assert.Equal(t, http.StatusBadRequest, tokenW.Code)

	var errResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestJWKSKeyParams(t *testing.T) {
	provider, router := setupProvider(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test-tenant/.well-known/jwks.json", nil)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Keys, 1)

	jwk := body.Keys[0]
	assert.Equal(t, provider.keyID, jwk["kid"])

	// Verify the RSA modulus can be decoded back to the actual public key
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	require.NoError(t, err)
	n := new(big.Int).SetBytes(nBytes)
	assert.True(t, n.BitLen() >= 2048)
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

func TestPublicClientTokenFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfig()
	emailer := email.NewLogSender(logger)
	provider := NewProvider(store, cfg, emailer, logger)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Seed a public client (no client_secret)
	ctx := t.Context()
	client := &domain.OIDCClient{
		ClientID:                "public-client",
		ClientName:              "Public Client",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		TokenEndpointAuthMethod: "none",
	}
	require.NoError(t, store.Clients().Upsert(ctx, client))

	// Create an invite
	invite := &domain.Invite{
		ID:        "invite-pub-1",
		TenantID:  "test-tenant",
		Email:     "user@example.com",
		Code:      "PUBCODE123",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	// Start authorization
	authURL := "/test-tenant/authorize?response_type=code&client_id=public-client" +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/cb") +
		"&state=s&nonce=n"
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code)

	bodyStr := authW.Body.String()
	sessionStart := strings.Index(bodyStr, `value="`) + len(`value="`)
	sessionEnd := strings.Index(bodyStr[sessionStart:], `"`)
	sessionID := bodyStr[sessionStart : sessionStart+sessionEnd]

	// Submit email
	emailForm := url.Values{"session_id": {sessionID}, "email": {"user@example.com"}}
	emailW := httptest.NewRecorder()
	emailReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(emailForm.Encode()))
	emailReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(emailW, emailReq)
	require.Equal(t, http.StatusOK, emailW.Code)

	// Submit code
	codeForm := url.Values{"session_id": {sessionID}, "code": {"PUBCODE123"}}
	codeW := httptest.NewRecorder()
	codeReq, _ := http.NewRequest("POST", "/test-tenant/authorize", strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(codeW, codeReq)
	require.Equal(t, http.StatusFound, codeW.Code)

	location := codeW.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	authCode := redirectURL.Query().Get("code")
	require.NotEmpty(t, authCode)

	// Token exchange — no client_secret for a public client
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {"public-client"},
		"redirect_uri": {"https://app.example.com/cb"},
	}
	tokenW := httptest.NewRecorder()
	tokenReq, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(tokenW, tokenReq)
	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &tokenResp))
	assert.NotEmpty(t, tokenResp["id_token"])
}

func TestConfidentialClientWrongSecretRejected(t *testing.T) {
	_, router := setupProvider(t)

	// Register a confidential client (has a secret)
	regBody := `{"redirect_uris": ["http://localhost/cb"]}`
	regReq, _ := http.NewRequest("POST", "/test-tenant/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)
	require.Equal(t, http.StatusCreated, regW.Code)

	var regResp map[string]interface{}
	require.NoError(t, json.Unmarshal(regW.Body.Bytes(), &regResp))
	clientID := regResp["client_id"].(string)

	// Attempt token exchange with wrong secret — must be rejected
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"somecode"},
		"client_id":     {clientID},
		"client_secret": {"wrong-secret"},
	}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test-tenant/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func testConfigWithStaticClients(staticClients []config.StaticClientConfig) *config.Config {
	cfg := testConfig()
	cfg.OP.StaticClients = staticClients
	return cfg
}

func TestTemplatedClientAuthFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	store := memory.NewStore()
	cfg := testConfigWithStaticClients([]config.StaticClientConfig{
		{
			ClientID:                "client-${tenant}-wallet",
			ClientName:              "Wallet (${tenant})",
			RedirectURIs:            []string{"https://id.siros.org/id/${tenant}/oidc/cb"},
			TokenEndpointAuthMethod: "none",
		},
	})
	emailer := email.NewLogSender(logger)
	provider := NewProvider(store, cfg, emailer, logger)

	router := gin.New()
	provider.RegisterRoutes(router)

	// Templated client is NOT seeded in the store — it's resolved at request time.
	ctx := t.Context()

	// Create an invite for the tenant "acme"
	invite := &domain.Invite{
		ID:        "invite-tmpl-1",
		TenantID:  "acme",
		Email:     "user@acme.com",
		Code:      "TMPLCODE1",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	// The expanded client_id for tenant "acme"
	expandedClientID := "client-acme-wallet"
	redirectURI := "https://id.siros.org/id/acme/oidc/cb"

	// Start authorization
	authURL := "/acme/authorize?response_type=code&client_id=" + expandedClientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=s&nonce=n"
	authW := httptest.NewRecorder()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	router.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code)

	bodyStr := authW.Body.String()
	sessionStart := strings.Index(bodyStr, `value="`) + len(`value="`)
	sessionEnd := strings.Index(bodyStr[sessionStart:], `"`)
	sessionID := bodyStr[sessionStart : sessionStart+sessionEnd]

	// Submit email
	emailForm := url.Values{"session_id": {sessionID}, "email": {"user@acme.com"}}
	emailW := httptest.NewRecorder()
	emailReq, _ := http.NewRequest("POST", "/acme/authorize", strings.NewReader(emailForm.Encode()))
	emailReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(emailW, emailReq)
	require.Equal(t, http.StatusOK, emailW.Code)

	// Submit code
	codeForm := url.Values{"session_id": {sessionID}, "code": {"TMPLCODE1"}}
	codeW := httptest.NewRecorder()
	codeReq, _ := http.NewRequest("POST", "/acme/authorize", strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(codeW, codeReq)
	require.Equal(t, http.StatusFound, codeW.Code)

	location := codeW.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	require.NoError(t, err)
	authCode := parsedURL.Query().Get("code")
	require.NotEmpty(t, authCode)

	// Token exchange — public client, no secret required
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {expandedClientID},
		"redirect_uri": {redirectURI},
	}
	tokenW := httptest.NewRecorder()
	tokenReq, _ := http.NewRequest("POST", "/acme/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(tokenW, tokenReq)
	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &tokenResp))
	assert.NotEmpty(t, tokenResp["id_token"])
}

func TestTemplatedClientDifferentTenants(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	cfg := testConfigWithStaticClients([]config.StaticClientConfig{
		{
			ClientID:                "client-${tenant}-wallet",
			RedirectURIs:            []string{"https://id.siros.org/id/${tenant}/oidc/cb"},
			TokenEndpointAuthMethod: "none",
		},
	})
	provider := NewProvider(store, cfg, email.NewLogSender(zap.NewNop()), zap.NewNop())

	router := gin.New()
	provider.RegisterRoutes(router)

	// client-acme-wallet → valid for tenant "acme"
	acmeURL := "/acme/authorize?response_type=code&client_id=client-acme-wallet" +
		"&redirect_uri=" + url.QueryEscape("https://id.siros.org/id/acme/oidc/cb")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", acmeURL, nil))
	assert.Equal(t, http.StatusOK, w.Code)

	// client-beta-wallet → valid for tenant "beta"
	betaURL := "/beta/authorize?response_type=code&client_id=client-beta-wallet" +
		"&redirect_uri=" + url.QueryEscape("https://id.siros.org/id/beta/oidc/cb")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", betaURL, nil))
	assert.Equal(t, http.StatusOK, w.Code)

	// client-acme-wallet does NOT match the template for tenant "beta"
	// (template expands to client-beta-wallet for tenant "beta")
	crossURL := "/beta/authorize?response_type=code&client_id=client-acme-wallet" +
		"&redirect_uri=" + url.QueryEscape("https://id.siros.org/id/acme/oidc/cb")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", crossURL, nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}