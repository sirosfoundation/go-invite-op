package mongodb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
)

func getTestStore(t *testing.T) *Store {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping MongoDB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := NewStore(ctx, &Config{
		URI:      uri,
		Database: "invite_op_test_" + time.Now().Format("20060102150405"),
		Timeout:  5,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = store.database.Drop(context.Background())
		_ = store.Close()
	})
	return store
}

func TestMongoDBPing(t *testing.T) {
	store := getTestStore(t)
	assert.NoError(t, store.Ping(context.Background()))
}

func TestMongoDBInviteCRUD(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	invite := &domain.Invite{
		ID:        "inv-1",
		TenantID:  "tenant-1",
		Email:     "user@example.com",
		Code:      "ABC123",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	require.NoError(t, store.Invites().Create(ctx, invite))

	got, err := store.Invites().GetByID(ctx, "tenant-1", "inv-1")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", got.Email)

	got2, err := store.Invites().GetByEmail(ctx, "tenant-1", "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, "inv-1", got2.ID)

	got3, err := store.Invites().GetByCode(ctx, "tenant-1", "ABC123")
	require.NoError(t, err)
	assert.Equal(t, "inv-1", got3.ID)

	invites, err := store.Invites().List(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, invites, 1)

	invite.MaxUses = 10
	require.NoError(t, store.Invites().Update(ctx, invite))

	updated, _ := store.Invites().GetByID(ctx, "tenant-1", "inv-1")
	assert.Equal(t, 10, updated.MaxUses)

	require.NoError(t, store.Invites().Delete(ctx, "tenant-1", "inv-1"))

	_, err = store.Invites().GetByID(ctx, "tenant-1", "inv-1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestMongoDBFindBestMatch(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	emailInvite := &domain.Invite{
		ID:        "inv-email",
		TenantID:  "tenant-1",
		Email:     "user@example.com",
		Code:      "EMAIL",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	domainInvite := &domain.Invite{
		ID:        "inv-domain",
		TenantID:  "tenant-1",
		Email:     "*@example.com",
		Code:      "DOMAIN",
		MaxUses:   100,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, emailInvite))
	require.NoError(t, store.Invites().Create(ctx, domainInvite))

	// Exact email match takes priority
	found, err := store.Invites().FindBestMatch(ctx, "tenant-1", "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, "inv-email", found.ID)

	// Domain match for unknown user
	found2, err := store.Invites().FindBestMatch(ctx, "tenant-1", "other@example.com")
	require.NoError(t, err)
	assert.Equal(t, "inv-domain", found2.ID)

	// No match
	_, err = store.Invites().FindBestMatch(ctx, "tenant-1", "user@other.org")
	assert.Error(t, err)
}

func TestMongoDBDeleteExpiredAndConsumed(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	expired := &domain.Invite{
		ID:        "inv-exp",
		TenantID:  "tenant-1",
		Email:     "expired@example.com",
		Code:      "EXP",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	consumed := &domain.Invite{
		ID:        "inv-con",
		TenantID:  "tenant-1",
		Email:     "consumed@example.com",
		Code:      "CON",
		MaxUses:   1,
		UseCount:  1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	valid := &domain.Invite{
		ID:        "inv-valid",
		TenantID:  "tenant-1",
		Email:     "valid@example.com",
		Code:      "VALID",
		MaxUses:   5,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	require.NoError(t, store.Invites().Create(ctx, expired))
	require.NoError(t, store.Invites().Create(ctx, consumed))
	require.NoError(t, store.Invites().Create(ctx, valid))

	count, err := store.Invites().DeleteExpiredAndConsumed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Valid invite should remain
	_, err = store.Invites().GetByID(ctx, "tenant-1", "inv-valid")
	assert.NoError(t, err)
}

func TestMongoDBClientStore(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	client := &domain.OIDCClient{
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		RedirectURIs: []string{"http://localhost/cb"},
		ClientName:   "TestApp",
	}

	require.NoError(t, store.Clients().Create(ctx, client))

	got, err := store.Clients().GetByID(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "TestApp", got.ClientName)
}

func TestMongoDBSessionStore(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	session := &domain.PendingAuth{
		ID:          "sess-1",
		TenantID:    "tenant-1",
		ClientID:    "client-1",
		RedirectURI: "http://localhost/cb",
		Stage:       "email",
		CreatedAt:   time.Now(),
	}

	require.NoError(t, store.Sessions().Create(ctx, session))

	got, err := store.Sessions().GetByID(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, "email", got.Stage)

	session.Stage = "done"
	session.Code = "authcode123"
	require.NoError(t, store.Sessions().Update(ctx, session))

	found, err := store.Sessions().FindByCode(ctx, "tenant-1", "authcode123")
	require.NoError(t, err)
	assert.Equal(t, "sess-1", found.ID)

	require.NoError(t, store.Sessions().Delete(ctx, "sess-1"))
	_, err = store.Sessions().GetByID(ctx, "sess-1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestMongoDBSessionDeleteExpired(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	old := &domain.PendingAuth{
		ID:        "sess-old",
		TenantID:  "tenant-1",
		ClientID:  "client-1",
		Stage:     "email",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	recent := &domain.PendingAuth{
		ID:        "sess-recent",
		TenantID:  "tenant-1",
		ClientID:  "client-1",
		Stage:     "email",
		CreatedAt: time.Now(),
	}

	require.NoError(t, store.Sessions().Create(ctx, old))
	require.NoError(t, store.Sessions().Create(ctx, recent))

	count, err := store.Sessions().DeleteExpired(ctx, 1*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Recent session should remain
	_, err = store.Sessions().GetByID(ctx, "sess-recent")
	assert.NoError(t, err)
}
