package memory

import (
"context"
"testing"
"time"

"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"

"github.com/sirosfoundation/go-invite-op/internal/domain"
"github.com/sirosfoundation/go-invite-op/internal/storage"
)

func TestInviteStore_CRUD(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

invite := &domain.Invite{
ID:       "inv-1",
TenantID: tenantID,
Email:    "user@example.com",
Code:     "abc123",
MaxUses:  5,
}

// Create
err := store.Invites().Create(ctx, invite)
require.NoError(t, err)

// Create duplicate
err = store.Invites().Create(ctx, invite)
assert.ErrorIs(t, err, storage.ErrAlreadyExists)

// GetByID
got, err := store.Invites().GetByID(ctx, tenantID, "inv-1")
require.NoError(t, err)
assert.Equal(t, "user@example.com", got.Email)
assert.Equal(t, "abc123", got.Code)

// GetByID wrong tenant
_, err = store.Invites().GetByID(ctx, "other-tenant", "inv-1")
assert.ErrorIs(t, err, storage.ErrNotFound)

// GetByEmail
got, err = store.Invites().GetByEmail(ctx, tenantID, "USER@EXAMPLE.COM")
require.NoError(t, err)
assert.Equal(t, "inv-1", got.ID)

// GetByCode
got, err = store.Invites().GetByCode(ctx, tenantID, "abc123")
require.NoError(t, err)
assert.Equal(t, "inv-1", got.ID)

// List
list, err := store.Invites().List(ctx, tenantID)
require.NoError(t, err)
assert.Len(t, list, 1)

// Update
invite.MaxUses = 10
err = store.Invites().Update(ctx, invite)
require.NoError(t, err)

got, _ = store.Invites().GetByID(ctx, tenantID, "inv-1")
assert.Equal(t, 10, got.MaxUses)

// Delete
err = store.Invites().Delete(ctx, tenantID, "inv-1")
require.NoError(t, err)

_, err = store.Invites().GetByID(ctx, tenantID, "inv-1")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestInviteStore_FindBestMatch(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

// Domain invite
domainInvite := &domain.Invite{
ID:       "inv-domain",
TenantID: tenantID,
Email:    "@example.com",
Code:     "domain-code",
}
require.NoError(t, store.Invites().Create(ctx, domainInvite))

// Exact email invite
emailInvite := &domain.Invite{
ID:       "inv-email",
TenantID: tenantID,
Email:    "specific@example.com",
Code:     "email-code",
}
require.NoError(t, store.Invites().Create(ctx, emailInvite))

// Exact match preferred
got, err := store.Invites().FindBestMatch(ctx, tenantID, "specific@example.com")
require.NoError(t, err)
assert.Equal(t, "inv-email", got.ID)

// Domain fallback
got, err = store.Invites().FindBestMatch(ctx, tenantID, "other@example.com")
require.NoError(t, err)
assert.Equal(t, "inv-domain", got.ID)

// No match
_, err = store.Invites().FindBestMatch(ctx, tenantID, "user@other.com")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestInviteStore_FindBestMatch_Expired(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

expired := &domain.Invite{
ID:        "inv-expired",
TenantID:  tenantID,
Email:     "user@example.com",
Code:      "expired-code",
ExpiresAt: time.Now().Add(-1 * time.Hour),
}
require.NoError(t, store.Invites().Create(ctx, expired))

_, err := store.Invites().FindBestMatch(ctx, tenantID, "user@example.com")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestInviteStore_FindBestMatch_Consumed(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

consumed := &domain.Invite{
ID:       "inv-consumed",
TenantID: tenantID,
Email:    "user@example.com",
Code:     "consumed-code",
MaxUses:  1,
UseCount: 1,
}
require.NoError(t, store.Invites().Create(ctx, consumed))

_, err := store.Invites().FindBestMatch(ctx, tenantID, "user@example.com")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestInviteStore_DeleteExpiredAndConsumed(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

valid := &domain.Invite{
ID: "inv-valid", TenantID: tenantID, Email: "a@b.com", Code: "c1",
}
expired := &domain.Invite{
ID: "inv-expired", TenantID: tenantID, Email: "b@b.com", Code: "c2",
ExpiresAt: time.Now().Add(-1 * time.Hour),
}
consumed := &domain.Invite{
ID: "inv-consumed", TenantID: tenantID, Email: "c@b.com", Code: "c3",
MaxUses: 1, UseCount: 1,
}

require.NoError(t, store.Invites().Create(ctx, valid))
require.NoError(t, store.Invites().Create(ctx, expired))
require.NoError(t, store.Invites().Create(ctx, consumed))

count, err := store.Invites().DeleteExpiredAndConsumed(ctx)
require.NoError(t, err)
assert.Equal(t, int64(2), count)

list, _ := store.Invites().List(ctx, tenantID)
assert.Len(t, list, 1)
assert.Equal(t, "inv-valid", list[0].ID)
}

func TestClientStore(t *testing.T) {
store := NewStore()
ctx := context.Background()

client := &domain.OIDCClient{
ClientID:     "client-1",
ClientSecret: "secret",
RedirectURIs: []string{"http://localhost/callback"},
ClientName:   "Test Client",
}

err := store.Clients().Create(ctx, client)
require.NoError(t, err)

got, err := store.Clients().GetByID(ctx, "client-1")
require.NoError(t, err)
assert.Equal(t, "Test Client", got.ClientName)
assert.Equal(t, []string{"http://localhost/callback"}, got.RedirectURIs)

_, err = store.Clients().GetByID(ctx, "nonexistent")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestSessionStore(t *testing.T) {
store := NewStore()
ctx := context.Background()
tenantID := domain.TenantID("test-tenant")

session := &domain.PendingAuth{
ID:          "sess-1",
TenantID:    tenantID,
ClientID:    "client-1",
RedirectURI: "http://localhost/callback",
State:       "state123",
Stage:       "email",
}

err := store.Sessions().Create(ctx, session)
require.NoError(t, err)

got, err := store.Sessions().GetByID(ctx, "sess-1")
require.NoError(t, err)
assert.Equal(t, "email", got.Stage)

// Update to done with a code
session.Stage = "done"
session.Code = "auth-code-123"
err = store.Sessions().Update(ctx, session)
require.NoError(t, err)

// FindByCode
found, err := store.Sessions().FindByCode(ctx, tenantID, "auth-code-123")
require.NoError(t, err)
assert.Equal(t, "sess-1", found.ID)

// FindByCode wrong tenant
_, err = store.Sessions().FindByCode(ctx, "other-tenant", "auth-code-123")
assert.ErrorIs(t, err, storage.ErrNotFound)

// Delete
err = store.Sessions().Delete(ctx, "sess-1")
require.NoError(t, err)

_, err = store.Sessions().GetByID(ctx, "sess-1")
assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestStorePingClose(t *testing.T) {
store := NewStore()
assert.NoError(t, store.Ping(context.Background()))
assert.NoError(t, store.Close())
}
