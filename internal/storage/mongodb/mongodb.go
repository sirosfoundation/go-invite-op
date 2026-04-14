package mongodb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
)

// Config holds MongoDB connection configuration.
type Config struct {
	URI        string
	Database   string
	Timeout    int // seconds
	TLSEnabled bool
	CAPath     string
	CertPath   string
	KeyPath    string
}

// Store implements MongoDB storage.
type Store struct {
	client   *mongo.Client
	database *mongo.Database
	invites  *InviteStore
	clients  *ClientStore
	sessions *SessionStore
}

// NewStore creates a new MongoDB store.
func NewStore(ctx context.Context, cfg *Config) (*Store, error) {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(timeout)

	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAPath != "" {
			caCert, err := os.ReadFile(cfg.CAPath)
			if err != nil {
				return nil, fmt.Errorf("reading MongoDB CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("parsing MongoDB CA certificate")
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.CertPath != "" && cfg.KeyPath != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("loading MongoDB client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		clientOptions.SetTLSConfig(tlsCfg)
	}

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("connecting to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("pinging MongoDB: %w", err)
	}

	database := client.Database(cfg.Database)

	s := &Store{
		client:   client,
		database: database,
		invites:  &InviteStore{collection: database.Collection("invites")},
		clients:  &ClientStore{collection: database.Collection("oidc_clients")},
		sessions: &SessionStore{collection: database.Collection("auth_sessions")},
	}

	if err := s.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("creating indexes: %w", err)
	}

	return s, nil
}

func (s *Store) createIndexes(ctx context.Context) error {
	// Invites: unique (tenant_id, email), unique (tenant_id, code), TTL on expires_at
	_, err := s.invites.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "email", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "code", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetSparse(true),
		},
	})
	if err != nil {
		return fmt.Errorf("creating invite indexes: %w", err)
	}

	// Clients: unique client_id (already _id)
	// No additional indexes needed.

	// Sessions: TTL on created_at (10 minute session lifetime)
	_, err = s.sessions.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(600),
	})
	if err != nil {
		return fmt.Errorf("creating session indexes: %w", err)
	}

	return nil
}

func (s *Store) Invites() storage.InviteStore   { return s.invites }
func (s *Store) Clients() storage.ClientStore   { return s.clients }
func (s *Store) Sessions() storage.SessionStore { return s.sessions }

func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.client.Disconnect(ctx)
}

func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx, nil)
}

// InviteStore implements MongoDB invite storage.
type InviteStore struct {
	collection *mongo.Collection
}

func (s *InviteStore) Create(ctx context.Context, invite *domain.Invite) error {
	now := time.Now()
	invite.CreatedAt = now
	invite.UpdatedAt = now
	_, err := s.collection.InsertOne(ctx, invite)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("creating invite: %w", err)
	}
	return nil
}

func (s *InviteStore) GetByID(ctx context.Context, tenantID domain.TenantID, id string) (*domain.Invite, error) {
	var invite domain.Invite
	err := s.collection.FindOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)}).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("getting invite: %w", err)
	}
	return &invite, nil
}

func (s *InviteStore) GetByEmail(ctx context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error) {
	var invite domain.Invite
	filter := bson.M{"tenant_id": string(tenantID), "email": bson.M{"$regex": "^" + escapeRegex(email) + "$", "$options": "i"}}
	err := s.collection.FindOne(ctx, filter).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("getting invite by email: %w", err)
	}
	return &invite, nil
}

func (s *InviteStore) GetByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error) {
	var invite domain.Invite
	err := s.collection.FindOne(ctx, bson.M{"tenant_id": string(tenantID), "code": code}).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("getting invite by code: %w", err)
	}
	return &invite, nil
}

func (s *InviteStore) List(ctx context.Context, tenantID domain.TenantID) ([]*domain.Invite, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID)},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	defer cursor.Close(ctx)

	var invites []*domain.Invite
	if err := cursor.All(ctx, &invites); err != nil {
		return nil, fmt.Errorf("decoding invites: %w", err)
	}
	if invites == nil {
		invites = []*domain.Invite{}
	}
	return invites, nil
}

func (s *InviteStore) Update(ctx context.Context, invite *domain.Invite) error {
	invite.UpdatedAt = time.Now()
	result, err := s.collection.ReplaceOne(ctx,
		bson.M{"_id": invite.ID, "tenant_id": string(invite.TenantID)},
		invite)
	if err != nil {
		return fmt.Errorf("updating invite: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *InviteStore) Delete(ctx context.Context, tenantID domain.TenantID, id string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)})
	if err != nil {
		return fmt.Errorf("deleting invite: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *InviteStore) DeleteExpiredAndConsumed(ctx context.Context) (int64, error) {
	now := time.Now()
	// Delete expired (non-zero expires_at that has passed) OR consumed (use_count >= max_uses where max_uses > 0)
	filter := bson.M{
		"$or": []bson.M{
			{"expires_at": bson.M{"$ne": time.Time{}, "$lt": now}},
			{"max_uses": bson.M{"$gt": 0}, "$expr": bson.M{"$gte": []string{"$use_count", "$max_uses"}}},
		},
	}
	result, err := s.collection.DeleteMany(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("deleting expired/consumed invites: %w", err)
	}
	return result.DeletedCount, nil
}

func (s *InviteStore) FindBestMatch(ctx context.Context, tenantID domain.TenantID, email string) (*domain.Invite, error) {
	now := time.Now()
	tid := string(tenantID)

	// Valid invite filter: not expired and not consumed
	validFilter := bson.M{
		"tenant_id": tid,
		"$or": []bson.M{
			{"expires_at": time.Time{}},        // never expires
			{"expires_at": bson.M{"$gt": now}}, // not yet expired
		},
		"$and": []bson.M{
			{"$or": []bson.M{
				{"max_uses": 0}, // infinite
				{"$expr": bson.M{"$lt": []string{"$use_count", "$max_uses"}}},
			}},
		},
	}

	// Try exact email match first
	exactFilter := bson.M{}
	for k, v := range validFilter {
		exactFilter[k] = v
	}
	exactFilter["email"] = bson.M{"$regex": "^" + escapeRegex(email) + "$", "$options": "i"}

	var invite domain.Invite
	err := s.collection.FindOne(ctx, exactFilter).Decode(&invite)
	if err == nil {
		return &invite, nil
	}
	if err != mongo.ErrNoDocuments {
		return nil, fmt.Errorf("finding invite by email: %w", err)
	}

	// Try domain match
	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx < 0 {
		return nil, storage.ErrNotFound
	}
	emailDomain := email[atIdx:] // "@example.com"

	domainFilter := bson.M{}
	for k, v := range validFilter {
		domainFilter[k] = v
	}
	domainFilter["email"] = bson.M{"$regex": "^" + escapeRegex(emailDomain) + "$", "$options": "i"}

	err = s.collection.FindOne(ctx, domainFilter).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("finding invite by domain: %w", err)
	}
	return &invite, nil
}

// ClientStore implements MongoDB OIDC client storage.
type ClientStore struct {
	collection *mongo.Collection
}

func (s *ClientStore) Create(ctx context.Context, client *domain.OIDCClient) error {
	client.CreatedAt = time.Now()
	_, err := s.collection.InsertOne(ctx, client)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("creating OIDC client: %w", err)
	}
	return nil
}

func (s *ClientStore) GetByID(ctx context.Context, clientID string) (*domain.OIDCClient, error) {
	var client domain.OIDCClient
	err := s.collection.FindOne(ctx, bson.M{"_id": clientID}).Decode(&client)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("getting OIDC client: %w", err)
	}
	return &client, nil
}

// SessionStore implements MongoDB pending auth session storage.
type SessionStore struct {
	collection *mongo.Collection
}

func (s *SessionStore) Create(ctx context.Context, session *domain.PendingAuth) error {
	session.CreatedAt = time.Now()
	_, err := s.collection.InsertOne(ctx, session)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("creating auth session: %w", err)
	}
	return nil
}

func (s *SessionStore) GetByID(ctx context.Context, id string) (*domain.PendingAuth, error) {
	var session domain.PendingAuth
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("getting auth session: %w", err)
	}
	return &session, nil
}

func (s *SessionStore) FindByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.PendingAuth, error) {
	var session domain.PendingAuth
	err := s.collection.FindOne(ctx, bson.M{
		"tenant_id": string(tenantID),
		"code":      code,
		"stage":     "done",
	}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("finding session by code: %w", err)
	}
	return &session, nil
}

func (s *SessionStore) Update(ctx context.Context, session *domain.PendingAuth) error {
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": session.ID}, session)
	if err != nil {
		return fmt.Errorf("updating auth session: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("deleting auth session: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *SessionStore) DeleteExpired(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge)
	result, err := s.collection.DeleteMany(ctx, bson.M{
		"created_at": bson.M{"$lt": cutoff},
	})
	if err != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", err)
	}
	return result.DeletedCount, nil
}

// escapeRegex escapes special regex characters for use in MongoDB $regex queries.
func escapeRegex(s string) string {
	special := []byte(`\.+*?^${}()|[]`)
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		for _, sp := range special {
			if c == sp {
				result = append(result, '\\')
				break
			}
		}
		result = append(result, c)
	}
	return string(result)
}
