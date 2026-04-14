package domain

import (
	"time"
)

// TenantID represents a tenant identifier.
type TenantID string

// Invite represents an invite entry for a tenant.
// It matches either a specific email address (e.g. "foo@example.com")
// or an email domain (e.g. "@example.com").
type Invite struct {
	ID        string    `json:"id" bson:"_id"`
	TenantID  TenantID  `json:"tenant_id" bson:"tenant_id"`
	Email     string    `json:"email" bson:"email"`
	Code      string    `json:"code" bson:"code"`
	MaxUses   int       `json:"max_uses" bson:"max_uses"`
	UseCount  int       `json:"use_count" bson:"use_count"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// IsExpired returns true if the invite has passed its expiry time.
func (i *Invite) IsExpired() bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(i.ExpiresAt)
}

// IsConsumed returns true if the invite has no remaining uses.
func (i *Invite) IsConsumed() bool {
	if i.MaxUses == 0 {
		return false
	}
	return i.UseCount >= i.MaxUses
}

// IsValid returns true if the invite is neither expired nor consumed.
func (i *Invite) IsValid() bool {
	return !i.IsExpired() && !i.IsConsumed()
}

// IsDomain returns true if this invite matches a domain (starts with @).
func (i *Invite) IsDomain() bool {
	return len(i.Email) > 0 && i.Email[0] == '@'
}

// OIDCClient represents a dynamically registered OIDC client.
type OIDCClient struct {
	ClientID                string    `json:"client_id" bson:"_id"`
	ClientSecret            string    `json:"client_secret,omitempty" bson:"client_secret"`
	RedirectURIs            []string  `json:"redirect_uris" bson:"redirect_uris"`
	ClientName              string    `json:"client_name,omitempty" bson:"client_name"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" bson:"token_endpoint_auth_method"`
	CreatedAt               time.Time `json:"created_at" bson:"created_at"`
}

// IsPublic returns true if the client uses no client authentication at the token endpoint.
func (c *OIDCClient) IsPublic() bool {
	return c.TokenEndpointAuthMethod == "none"
}

// PendingAuth represents an in-progress OIDC authentication session.
type PendingAuth struct {
	ID                  string    `json:"id" bson:"_id"`
	TenantID            TenantID  `json:"tenant_id" bson:"tenant_id"`
	ClientID            string    `json:"client_id" bson:"client_id"`
	RedirectURI         string    `json:"redirect_uri" bson:"redirect_uri"`
	State               string    `json:"state" bson:"state"`
	Nonce               string    `json:"nonce" bson:"nonce"`
	Email               string    `json:"email" bson:"email"`
	Code                string    `json:"code" bson:"code"`
	InviteID            string    `json:"invite_id" bson:"invite_id"`
	Stage               string    `json:"stage" bson:"stage"`
	CodeChallenge       string    `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`
	CreatedAt           time.Time `json:"created_at" bson:"created_at"`
}
