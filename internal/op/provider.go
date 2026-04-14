package op

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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
	store   storage.Store
	cfg     *config.Config
	emailer email.Sender
	logger  *zap.Logger
}

// NewProvider creates a new OP provider.
func NewProvider(store storage.Store, cfg *config.Config, emailer email.Sender, logger *zap.Logger) *Provider {
	return &Provider{
		store:   store,
		cfg:     cfg,
		emailer: emailer,
		logger:  logger.Named("op"),
	}
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
		"id_token_signing_alg_values_supported": []string{"HS256"},
		"scopes_supported":                      []string{"openid", "email"},
	})
}

// JWKS returns the JSON Web Key Set. Currently empty since HS256 uses a shared
// secret. Present for OIDC Discovery compliance and forward-compatibility with
// asymmetric signing algorithms.
func (p *Provider) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"keys": []interface{}{}})
}

// RegisterClientRequest is the dynamic client registration request.
type RegisterClientRequest struct {
	RedirectURIs []string `json:"redirect_uris" binding:"required"`
	ClientName   string   `json:"client_name,omitempty"`
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

	clientID := uuid.New().String()
	clientSecret, err := generateRandom(32)
	if err != nil {
		p.logger.Error("Failed to generate client secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	client := &domain.OIDCClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		ClientName:   req.ClientName,
	}

	if err := p.store.Clients().Create(c.Request.Context(), client); err != nil {
		p.logger.Error("Failed to register client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"redirect_uris": client.RedirectURIs,
		"client_name":   client.ClientName,
	})
}

// AuthorizeGet shows the email input form.
func (p *Provider) AuthorizeGet(c *gin.Context) {
	tenant := c.Param("tenant")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	nonce := c.Query("nonce")
	responseType := c.Query("response_type")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	client, err := p.store.Clients().GetByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !isValidRedirectURI(client, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	sessionID := uuid.New().String()
	session := &domain.PendingAuth{
		ID:          sessionID,
		TenantID:    domain.TenantID(tenant),
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Nonce:       nonce,
		Stage:       "email",
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
	redirectURI := c.PostForm("redirect_uri")
	tenant := c.Param("tenant")

	client, err := p.store.Clients().GetByID(c.Request.Context(), clientID)
	if err != nil || client.ClientSecret != clientSecret {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	idToken, err := token.SignedString([]byte(p.cfg.JWT.Secret))
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
