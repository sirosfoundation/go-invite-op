package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/config.yaml")
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 8081, cfg.Server.AdminPort)
	assert.Equal(t, "memory", cfg.Storage.Type)
	assert.Equal(t, "invite_op", cfg.Storage.MongoDB.Database)
	assert.Equal(t, 10, cfg.Storage.MongoDB.Timeout)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "go-invite-op", cfg.JWT.Issuer)
	assert.Equal(t, 587, cfg.SMTP.Port)
	assert.Equal(t, 600, cfg.OP.SessionTimeout)
	assert.Equal(t, 3600, cfg.OP.CleanupIntervalSec)
	assert.Equal(t, 10, cfg.OP.RateLimit.MaxAttempts)
	assert.Equal(t, 60, cfg.OP.RateLimit.WindowSeconds)
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(yamlFile, []byte(`
server:
  port: 9090
  base_url: "https://example.com"
storage:
  type: "mongodb"
  mongodb:
    uri: "mongodb://dbhost:27017"
    database: "test_db"
jwt:
  secret: "my-secret"
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(yamlFile)
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "https://example.com", cfg.Server.BaseURL)
	assert.Equal(t, "mongodb", cfg.Storage.Type)
	assert.Equal(t, "mongodb://dbhost:27017", cfg.Storage.MongoDB.URI)
	assert.Equal(t, "test_db", cfg.Storage.MongoDB.Database)
	assert.Equal(t, "my-secret", cfg.JWT.Secret)
}

func TestLoadStaticClients(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(yamlFile, []byte(`
op:
  static_clients:
    - client_id: "siros-tenant-foobar"
      client_name: "Foobar Inc."
      redirect_uris:
        - https://id.siros.org/id/foobar/oidc/cb
      token_endpoint_auth_method: "none"
    - client_id: "confidential-client"
      redirect_uris:
        - https://app.example.com/callback
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(yamlFile)
	require.NoError(t, err)

	require.Len(t, cfg.OP.StaticClients, 2)

	assert.Equal(t, "siros-tenant-foobar", cfg.OP.StaticClients[0].ClientID)
	assert.Equal(t, "Foobar Inc.", cfg.OP.StaticClients[0].ClientName)
	assert.Equal(t, []string{"https://id.siros.org/id/foobar/oidc/cb"}, cfg.OP.StaticClients[0].RedirectURIs)
	assert.Equal(t, "none", cfg.OP.StaticClients[0].TokenEndpointAuthMethod)

	assert.Equal(t, "confidential-client", cfg.OP.StaticClients[1].ClientID)
	assert.Equal(t, []string{"https://app.example.com/callback"}, cfg.OP.StaticClients[1].RedirectURIs)
	assert.Equal(t, "", cfg.OP.StaticClients[1].TokenEndpointAuthMethod)
}

func TestValidateStaticClientMissingClientID(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080, AdminPort: 8081},
		Storage: StorageConfig{Type: "memory"},
		OP: OPConfig{
			StaticClients: []StaticClientConfig{
				{RedirectURIs: []string{"https://example.com/cb"}},
			},
		},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateStaticClientMissingRedirectURIs(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080, AdminPort: 8081},
		Storage: StorageConfig{Type: "memory"},
		OP: OPConfig{
			StaticClients: []StaticClientConfig{
				{ClientID: "my-client"},
			},
		},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateInvalidStorageType(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080, AdminPort: 8081},
		Storage: StorageConfig{Type: "redis"},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateMongoDBMissingURI(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080, AdminPort: 8081},
		Storage: StorageConfig{Type: "mongodb"},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateTLSMissingCert(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:      8080,
			AdminPort: 8081,
			TLS:       TLSConfig{Enabled: true, KeyFile: "/key.pem"},
		},
		Storage: StorageConfig{Type: "memory"},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateTLSMissingKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:      8080,
			AdminPort: 8081,
			TLS:       TLSConfig{Enabled: true, CertFile: "/cert.pem"},
		},
		Storage: StorageConfig{Type: "memory"},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidatePortRange(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 0, AdminPort: 8081},
		Storage: StorageConfig{Type: "memory"},
	}
	assert.Error(t, cfg.Validate())

	cfg.Server.Port = 70000
	assert.Error(t, cfg.Validate())
}

func TestValidateCORSWildcardWithCredentials(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:      8080,
			AdminPort: 8081,
			CORS: CORSConfig{
				AllowedOrigins:   []string{"*"},
				AllowCredentials: true,
			},
		},
		Storage: StorageConfig{Type: "memory"},
	}
	assert.Error(t, cfg.Validate())
}

func TestValidateMongoDBMTLSIncomplete(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080, AdminPort: 8081},
		Storage: StorageConfig{Type: "mongodb", MongoDB: MongoDBConfig{URI: "mongodb://localhost", CertPath: "/cert.pem"}},
	}
	assert.Error(t, cfg.Validate())
}

func TestLoadSecretFromFile(t *testing.T) {
	dir := t.TempDir()

	secretFile := filepath.Join(dir, "jwt-secret")
	err := os.WriteFile(secretFile, []byte("file-based-secret\n"), 0600)
	require.NoError(t, err)

	yamlFile := filepath.Join(dir, "config.yaml")
	err = os.WriteFile(yamlFile, []byte(`
jwt:
  secret_path: "`+secretFile+`"
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(yamlFile)
	require.NoError(t, err)
	assert.Equal(t, "file-based-secret", cfg.JWT.Secret)
}

func TestMongoDBPasswordFromFile(t *testing.T) {
	dir := t.TempDir()

	pwFile := filepath.Join(dir, "mongo-pw")
	err := os.WriteFile(pwFile, []byte("s3cret\n"), 0600)
	require.NoError(t, err)

	yamlFile := filepath.Join(dir, "config.yaml")
	err = os.WriteFile(yamlFile, []byte(`
storage:
  type: "mongodb"
  mongodb:
    uri: "mongodb://user:${MONGODB_PASSWORD}@dbhost:27017"
    password_path: "`+pwFile+`"
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(yamlFile)
	require.NoError(t, err)
	assert.Equal(t, "mongodb://user:s3cret@dbhost:27017", cfg.Storage.MongoDB.URI)
}

func TestEffectiveAdminTLS(t *testing.T) {
	shared := &TLSConfig{Enabled: true, CertFile: "shared.crt", KeyFile: "shared.key"}
	admin := &TLSConfig{Enabled: true, CertFile: "admin.crt", KeyFile: "admin.key"}

	// Admin TLS overrides shared
	result := EffectiveAdminTLS(shared, admin)
	assert.Equal(t, "admin.crt", result.CertFile)

	// Nil admin falls back to shared
	result = EffectiveAdminTLS(shared, nil)
	assert.Equal(t, "shared.crt", result.CertFile)

	// Disabled admin falls back to shared
	disabledAdmin := &TLSConfig{Enabled: false}
	result = EffectiveAdminTLS(shared, disabledAdmin)
	assert.Equal(t, "shared.crt", result.CertFile)
}

func TestTLSMinVersion(t *testing.T) {
	cfg := &TLSConfig{MinVersion: "1.3"}
	assert.Equal(t, uint16(0x0304), cfg.TLSMinVersion()) // tls.VersionTLS13

	cfg.MinVersion = "TLS1.3"
	assert.Equal(t, uint16(0x0304), cfg.TLSMinVersion())

	cfg.MinVersion = "1.2"
	assert.Equal(t, uint16(0x0303), cfg.TLSMinVersion()) // tls.VersionTLS12

	cfg.MinVersion = ""
	assert.Equal(t, uint16(0x0303), cfg.TLSMinVersion()) // defaults to 1.2
}
