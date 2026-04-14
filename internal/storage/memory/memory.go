package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
)

// Store implements an in-memory storage backend.
type Store struct {
	invites  *InviteStore
	clients  *ClientStore
	sessions *SessionStore
}

// NewStore creates a new in-memory store.
func NewStore() *Store {
	return &Store{
		invites:  &InviteStore{data: make(map[string]*domain.Invite)},
		clients:  &ClientStore{data: make(map[string]*domain.OIDCClient)},
		sessions: &SessionStore{data: make(map[string]*domain.PendingAuth)},
	}
}

func (s *Store) Invites() storage.InviteStore   { return s.invites }
func (s *Store) Clients() storage.ClientStore   { return s.clients }
func (s *Store) Sessions() storage.SessionStore { return s.sessions }
func (s *Store) Ping(_ context.Context) error   { return nil }
func (s *Store) Close() error                   { return nil }

// InviteStore implements in-memory invite storage.
type InviteStore struct {
	mu   sync.RWMutex
	data map[string]*domain.Invite
}

func (s *InviteStore) Create(_ context.Context, invite *domain.Invite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[invite.ID]; exists {
		return storage.ErrAlreadyExists
	}
	now := time.Now()
	invite.CreatedAt = now
	invite.UpdatedAt = now
	s.data[invite.ID] = invite
	return nil
}

func (s *InviteStore) GetByID(_ context.Context, tenantID domain.TenantID, id string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, exists := s.data[id]
	if !exists || inv.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	return inv, nil
}

func (s *InviteStore) GetByEmail(_ context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.data {
		if inv.TenantID == tenantID && strings.EqualFold(inv.Email, email) {
			return inv, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *InviteStore) GetByCode(_ context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.data {
		if inv.TenantID == tenantID && inv.Code == code {
			return inv, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *InviteStore) List(_ context.Context, tenantID domain.TenantID) ([]*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*domain.Invite
	for _, inv := range s.data {
		if inv.TenantID == tenantID {
			result = append(result, inv)
		}
	}
	return result, nil
}

func (s *InviteStore) Update(_ context.Context, invite *domain.Invite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[invite.ID]; !exists {
		return storage.ErrNotFound
	}
	invite.UpdatedAt = time.Now()
	s.data[invite.ID] = invite
	return nil
}

func (s *InviteStore) Delete(_ context.Context, tenantID domain.TenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, exists := s.data[id]
	if !exists || inv.TenantID != tenantID {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	return nil
}

func (s *InviteStore) DeleteExpiredAndConsumed(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for id, inv := range s.data {
		if inv.IsExpired() || inv.IsConsumed() {
			delete(s.data, id)
			count++
		}
	}
	return count, nil
}

func (s *InviteStore) FindBestMatch(_ context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	email = strings.ToLower(email)
	var domainMatch *domain.Invite
	parts := strings.SplitN(email, "@", 2)
	var emailDomain string
	if len(parts) == 2 {
		emailDomain = "@" + parts[1]
	}
	for _, inv := range s.data {
		if inv.TenantID != tenantID || !inv.IsValid() {
			continue
		}
		if strings.EqualFold(inv.Email, email) {
			return inv, nil
		}
		if emailDomain != "" && strings.EqualFold(inv.Email, emailDomain) {
			domainMatch = inv
		}
	}
	if domainMatch != nil {
		return domainMatch, nil
	}
	return nil, storage.ErrNotFound
}

// ClientStore implements in-memory OIDC client storage.
type ClientStore struct {
	mu   sync.RWMutex
	data map[string]*domain.OIDCClient
}

func (s *ClientStore) Create(_ context.Context, client *domain.OIDCClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[client.ClientID]; exists {
		return storage.ErrAlreadyExists
	}
	client.CreatedAt = time.Now()
	s.data[client.ClientID] = client
	return nil
}

func (s *ClientStore) Upsert(_ context.Context, client *domain.OIDCClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.data[client.ClientID]; exists {
		client.CreatedAt = existing.CreatedAt
	} else {
		client.CreatedAt = time.Now()
	}
	s.data[client.ClientID] = client
	return nil
}

func (s *ClientStore) GetByID(_ context.Context, clientID string) (*domain.OIDCClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.data[clientID]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

// SessionStore implements in-memory pending auth session storage.
type SessionStore struct {
	mu   sync.RWMutex
	data map[string]*domain.PendingAuth
}

func (s *SessionStore) Create(_ context.Context, session *domain.PendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[session.ID]; exists {
		return storage.ErrAlreadyExists
	}
	session.CreatedAt = time.Now()
	s.data[session.ID] = session
	return nil
}

func (s *SessionStore) GetByID(_ context.Context, id string) (*domain.PendingAuth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return session, nil
}

func (s *SessionStore) FindByCode(_ context.Context, tenantID domain.TenantID, code string) (*domain.PendingAuth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.data {
		if session.TenantID == tenantID && session.Code == code && session.Stage == "done" {
			return session, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *SessionStore) Update(_ context.Context, session *domain.PendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[session.ID]; !exists {
		return storage.ErrNotFound
	}
	s.data[session.ID] = session
	return nil
}

func (s *SessionStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[id]; !exists {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	return nil
}

func (s *SessionStore) DeleteExpired(_ context.Context, maxAge time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	var count int64
	for id, sess := range s.data {
		if sess.CreatedAt.Before(cutoff) {
			delete(s.data, id)
			count++
		}
	}
	return count, nil
}
