package storage

import (
	"context"
	"errors"
	"time"

	"github.com/sirosfoundation/go-invite-op/internal/domain"
)

// Common errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

// Store aggregates all storage interfaces.
type Store interface {
	Invites() InviteStore
	Clients() ClientStore
	Sessions() SessionStore
	Ping(ctx context.Context) error
	Close() error
}

// InviteStore defines the interface for invite storage operations.
type InviteStore interface {
	Create(ctx context.Context, invite *domain.Invite) error
	GetByID(ctx context.Context, tenantID domain.TenantID, id string) (*domain.Invite, error)
	GetByEmail(ctx context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error)
	GetByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error)
	List(ctx context.Context, tenantID domain.TenantID) ([]*domain.Invite, error)
	Update(ctx context.Context, invite *domain.Invite) error
	Delete(ctx context.Context, tenantID domain.TenantID, id string) error
	DeleteExpiredAndConsumed(ctx context.Context) (int64, error)
	FindBestMatch(ctx context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error)
}

// ClientStore defines the interface for OIDC client storage.
type ClientStore interface {
	Create(ctx context.Context, client *domain.OIDCClient) error
	GetByID(ctx context.Context, clientID string) (*domain.OIDCClient, error)
	Upsert(ctx context.Context, client *domain.OIDCClient) error
}

// SessionStore defines the interface for pending auth session storage.
type SessionStore interface {
	Create(ctx context.Context, session *domain.PendingAuth) error
	GetByID(ctx context.Context, id string) (*domain.PendingAuth, error)
	FindByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.PendingAuth, error)
	Update(ctx context.Context, session *domain.PendingAuth) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, maxAge time.Duration) (int64, error)
}
