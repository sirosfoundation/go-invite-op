package op

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-invite-op/internal/config"
	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/email"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
)

// Provider implements the OpenID Provider endpoints.
type Provider struct {
	store      storage.Store
	cfg        *config.Config
	emailer    email.Sender
	logger     *zap.Logger
	signingKey crypto.Signer
	keyID      string
	signingAlg string
}

// NewProvider creates a new OP provider. It loads or generates the signing key.
func NewProvider(store storage.Store, cfg *config.Config, emailer email.Sender, logger *zap.Logger) (*Provider, error) {
	p := &Provider{
		store:   store,
		cfg:     cfg,
		emailer: emailer,
		logger:  logger.Named("op"),
	}

	if err := p.loadOrGenerateKey(); err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	return p, nil
}

// loadOrGenerateKey loads an RSA/EC key from jwt.key_file, or generates an
// ephemeral RSA-2048 key if none is configured.
func (p *Provider) loadOrGenerateKey() error {
	if p.cfg.JWT.KeyFile != "" {
		data, err := os.ReadFile(p.cfg.JWT.KeyFile)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found in key file")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 for RSA keys
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr != nil {
				// Try EC private key
				ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
				if ecErr != nil {
					return fmt.Errorf("parsing private key: tried PKCS8, PKCS1, and EC formats: %w", errors.Join(err, rsaErr, ecErr))
				}
				key = ecKey
			} else {
				key = rsaKey
			}
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("key does not implement crypto.Signer")
		}
		p.signingKey = signer
	} else {
		// Generate ephemeral RSA key
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generating ephemeral RSA key: %w", err)
		}
		p.signingKey = key
		p.logger.Warn("No jwt.key_file configured; using ephemeral RSA key (tokens will not survive restarts)")
	}

	// Determine algorithm from key type
	switch k := p.signingKey.(type) {
	case *rsa.PrivateKey:
		p.signingAlg = "RS256"
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P384():
			p.signingAlg = "ES384"
		case elliptic.P521():
			p.signingAlg = "ES512"
		default:
			p.signingAlg = "ES256"
		}
	default:
		return fmt.Errorf("unsupported key type %T", p.signingKey)
	}

	// Compute key ID from public key thumbprint (SHA-256, first 8 bytes hex)
	pubBytes, err := x509.MarshalPKIXPublicKey(p.signingKey.Public())
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}
	thumbprint := sha256.Sum256(pubBytes)
	p.keyID = hex.EncodeToString(thumbprint[:8])

	return nil
}

// RegisterRoutes registers OP routes on the router.
func (p *Provider) RegisterRoutes(router *gin.Engine) {
	router.GET("/:tenant/.well-known/openid-configuration", p.Discovery)
	router.GET("/:tenant/.well-known/jwks.json", p.JWKS)
	router.POST("/:tenant/register", p.RegisterClient)
	router.GET("/:tenant/authorize", p.AuthorizeGet)
	router.POST("/:tenant/authorize", p.AuthorizePost)
	router.POST("/:tenant/token", p.Token)
}

// Discovery returns the OpenID Provider configuration.
func (p *Provider) Discovery(c *gin.Context) {
	tenant := c.Param("tenant")
	baseURL := strings.TrimRight(p.cfg.Server.BaseURL, "/")
	issuer := fmt.Sprintf("%s/%s", baseURL, tenant)

	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"registration_endpoint":                 issuer + "/register",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{p.signingAlg},
		"scopes_supported":                      []string{"openid", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// JWKS returns the JSON Web Key Set containing the provider's public signing key.
func (p *Provider) JWKS(c *gin.Context) {
	jwk, err := p.publicKeyJWK()
	if err != nil {
		p.logger.Error("Failed to build JWK", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": []interface{}{jwk}})
}

// publicKeyJWK returns the public key as a JWK map.
func (p *Provider) publicKeyJWK() (map[string]interface{}, error) {
	switch pub := p.signingKey.Public().(type) {
	case *rsa.PublicKey:
		return map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"alg": p.signingAlg,
			"kid": p.keyID,
			"n":   base64URLEncodeBigInt(pub.N),
			"e":   base64URLEncodeBigInt(big.NewInt(int64(pub.E))),
		}, nil
	case *ecdsa.PublicKey:
		var crv string
		var coordLen int
		switch pub.Curve {
		case elliptic.P256():
			crv = "P-256"
			coordLen = 32
		case elliptic.P384():
			crv = "P-384"
			coordLen = 48
		case elliptic.P521():
			crv = "P-521"
			coordLen = 66
		default:
			return nil, fmt.Errorf("unsupported EC curve")
		}
		// Use Bytes() to get the uncompressed point (0x04 || X || Y)
		uncompressed, err := pub.Bytes()
		if err != nil {
			return nil, fmt.Errorf("encoding EC public key: %w", err)
		}
		if len(uncompressed) != 1+2*coordLen {
			return nil, fmt.Errorf("unexpected EC public key length")
		}
		xBytes := uncompressed[1 : 1+coordLen]
		yBytes := uncompressed[1+coordLen:]
		return map[string]interface{}{
			"kty": "EC",
			"use": "sig",
			"alg": p.signingAlg,
			"kid": p.keyID,
			"crv": crv,
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}
}

func base64URLEncodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// RegisterClientRequest is the dynamic client registration request.
type RegisterClientRequest struct {
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// RegisterClient handles dynamic client registration.
func (p *Provider) RegisterClient(c *gin.Context) {
	var req RegisterClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uris required"})
		return
	}

	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post"
	}
	if authMethod != "client_secret_post" && authMethod != "none" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported token_endpoint_auth_method"})
		return
	}

	clientID := uuid.New().String()
	var clientSecret string

	if authMethod != "none" {
		var err error
		clientSecret, err = generateRandom(32)
		if err != nil {
			p.logger.Error("Failed to generate client secret", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	client := &domain.OIDCClient{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RedirectURIs:            req.RedirectURIs,
		ClientName:              req.ClientName,
		TokenEndpointAuthMethod: authMethod,
	}

	if err := p.store.Clients().Create(c.Request.Context(), client); err != nil {
		p.logger.Error("Failed to register client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp := gin.H{
		"client_id":                  client.ClientID,
		"redirect_uris":              client.RedirectURIs,
		"client_name":                client.ClientName,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
	}

	c.JSON(http.StatusCreated, resp)
}

// AuthorizeGet shows the email input form.
func (p *Provider) AuthorizeGet(c *gin.Context) {
	tenant := c.Param("tenant")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	nonce := c.Query("nonce")
	responseType := c.Query("response_type")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	client, err := p.resolveClient(c.Request.Context(), tenant, clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !isValidRedirectURI(client, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	// Public clients MUST use PKCE
	if client.IsPublic() && codeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code_challenge required for public clients"})
		return
	}

	// Only S256 is supported when PKCE is used
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "only S256 code_challenge_method is supported"})
			return
		}
	}

	sessionID := uuid.New().String()
	session := &domain.PendingAuth{
		ID:                  sessionID,
		TenantID:            domain.TenantID(tenant),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Stage:               "email",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	if err := p.store.Sessions().Create(c.Request.Context(), session); err != nil {
		p.logger.Error("Failed to create auth session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	p.renderEmailForm(c, sessionID, "")
}

// AuthorizePost handles the email or code form submission.
func (p *Provider) AuthorizePost(c *gin.Context) {
	sessionID := c.PostForm("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing session"})
		return
	}

	session, err := p.store.Sessions().GetByID(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session"})
		return
	}

	switch session.Stage {
	case "email":
		p.handleEmailSubmit(c, session)
	case "code":
		p.handleCodeSubmit(c, session)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session state"})
	}
}

func (p *Provider) handleEmailSubmit(c *gin.Context, session *domain.PendingAuth) {
	emailAddr := strings.TrimSpace(c.PostForm("email"))
	if emailAddr == "" {
		p.renderEmailForm(c, session.ID, "Email address is required")
		return
	}

	invite, err := p.store.Invites().FindBestMatch(c.Request.Context(), session.TenantID, emailAddr)
	if err != nil {
		p.renderEmailForm(c, session.ID, "No valid invite found for this email address")
		return
	}

	if err := p.emailer.SendCode(emailAddr, invite.Code); err != nil {
		p.logger.Error("Failed to send invite code", zap.Error(err))
		p.renderEmailForm(c, session.ID, "Failed to send verification code. Please try again.")
		return
	}

	session.Email = emailAddr
	session.InviteID = invite.ID
	session.Code = invite.Code
	session.Stage = "code"
	if err := p.store.Sessions().Update(c.Request.Context(), session); err != nil {
		p.logger.Error("Failed to update session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	p.renderCodeForm(c, session.ID, emailAddr, "")
}

func (p *Provider) handleCodeSubmit(c *gin.Context, session *domain.PendingAuth) {
	code := strings.TrimSpace(c.PostForm("code"))
	if code == "" {
		p.renderCodeForm(c, session.ID, session.Email, "Invite code is required")
		return
	}

	if code != session.Code {
		p.renderCodeForm(c, session.ID, session.Email, "Invalid invite code")
		return
	}

	// Increment use count
	invite, err := p.store.Invites().GetByID(c.Request.Context(), session.TenantID, session.InviteID)
	if err == nil {
		invite.UseCount++
		_ = p.store.Invites().Update(c.Request.Context(), invite)
	}

	// Generate authorization code
	authCode, err := generateRandom(32)
	if err != nil {
		p.logger.Error("Failed to generate auth code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	session.Stage = "done"
	session.Code = authCode
	if err := p.store.Sessions().Update(c.Request.Context(), session); err != nil {
		p.logger.Error("Failed to update session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	redirectURL, _ := url.Parse(session.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", authCode)
	if session.State != "" {
		q.Set("state", session.State)
	}
	redirectURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// Token handles the token exchange (authorization_code grant).
func (p *Provider) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	codeVerifier := c.PostForm("code_verifier")
	redirectURI := c.PostForm("redirect_uri")
	tenant := c.Param("tenant")

	client, err := p.resolveClient(c.Request.Context(), tenant, clientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	// Authenticate the client based on its auth method
	if client.IsPublic() {
		// Public clients authenticate via PKCE (verified below)
		if codeVerifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code_verifier required for public clients"})
			return
		}
	} else {
		// Confidential clients authenticate via client_secret (constant-time)
		if client.ClientSecret == "" || clientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	session, err := p.store.Sessions().FindByCode(c.Request.Context(), domain.TenantID(tenant), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if session.ClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if redirectURI != "" && redirectURI != session.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify PKCE code_verifier if a code_challenge was stored
	if session.CodeChallenge != "" {
		if codeVerifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code_verifier required"})
			return
		}
		if !verifyCodeChallenge(session.CodeChallenge, session.CodeChallengeMethod, codeVerifier) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code_verifier mismatch"})
			return
		}
	}

	baseURL := strings.TrimRight(p.cfg.Server.BaseURL, "/")
	issuer := fmt.Sprintf("%s/%s", baseURL, tenant)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   session.Email,
		"aud":   clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": session.Email,
	}
	if session.Nonce != "" {
		claims["nonce"] = session.Nonce
	}

	signingMethod := p.jwtSigningMethod()
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = p.keyID

	idToken, err := token.SignedString(p.signingKey)
	if err != nil {
		p.logger.Error("Failed to sign ID token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	_ = p.store.Sessions().Delete(c.Request.Context(), session.ID)

	c.JSON(http.StatusOK, gin.H{
		"access_token": idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func isValidRedirectURI(client *domain.OIDCClient, uri string) bool {
	for _, allowed := range client.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// verifyCodeChallenge validates a PKCE code_verifier against the stored code_challenge.
// Only S256 is supported per RFC 7636. Uses constant-time comparison to avoid
// timing side channels.
func verifyCodeChallenge(challenge, method, verifier string) bool {
	if method != "S256" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// jwtSigningMethod returns the jwt.SigningMethod for the provider's key type.
func (p *Provider) jwtSigningMethod() jwt.SigningMethod {
	switch p.signingAlg {
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodRS256
	}
}

// MarshalJWKS returns the JWKS as JSON bytes (for testing convenience).
func (p *Provider) MarshalJWKS() ([]byte, error) {
	jwk, err := p.publicKeyJWK()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{"keys": []interface{}{jwk}})
}

// resolveClient returns the OIDC client for the given tenant and clientID.
// It first checks the store; if not found, it falls back to expanding any
// static client template entries in the configuration whose client_id matches
// after substituting ${tenant} with the provided tenant string.
func (p *Provider) resolveClient(ctx context.Context, tenant, clientID string) (*domain.OIDCClient, error) {
	client, err := p.store.Clients().GetByID(ctx, clientID)
	if err == nil {
		return client, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("looking up client: %w", err)
	}
	if sc, ok := p.cfg.OP.ResolveClientForTenant(tenant, clientID); ok {
		return &domain.OIDCClient{
			ClientID:                sc.ClientID,
			ClientName:              sc.ClientName,
			RedirectURIs:            sc.RedirectURIs,
			TokenEndpointAuthMethod: sc.TokenEndpointAuthMethod,
		}, nil
	}
	return nil, fmt.Errorf("client not found: %s", clientID)
}

func generateRandom(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

var emailFormTmpl = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html><head><title>Sign In</title></head><body>
<h2>Enter your email address</h2>
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<label>Email: <input type="email" name="email" required></label><br><br>
<button type="submit">Continue</button>
</form>
</body></html>`))

var codeFormTmpl = template.Must(template.New("code").Parse(`<!DOCTYPE html>
<html><head><title>Verify Code</title></head><body>
<h2>Enter your invite code</h2>
<p>A code has been sent to {{.Email}}</p>
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<label>Code: <input type="text" name="code" required></label><br><br>
<button type="submit">Verify</button>
</form>
</body></html>`))

func (p *Provider) renderEmailForm(c *gin.Context, sessionID, errMsg string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := emailFormTmpl.Execute(c.Writer, map[string]string{
		"SessionID": sessionID,
		"Error":     errMsg,
	}); err != nil {
		p.logger.Error("Failed to render email form", zap.Error(err))
	}
}

func (p *Provider) renderCodeForm(c *gin.Context, sessionID, emailAddr, errMsg string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := codeFormTmpl.Execute(c.Writer, map[string]string{
		"SessionID": sessionID,
		"Email":     emailAddr,
		"Error":     errMsg,
	}); err != nil {
		p.logger.Error("Failed to render code form", zap.Error(err))
	}
}
