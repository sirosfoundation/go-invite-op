package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server" envconfig:"SERVER"`
	Storage StorageConfig `yaml:"storage" envconfig:"STORAGE"`
	Logging LoggingConfig `yaml:"logging" envconfig:"LOGGING"`
	JWT     JWTConfig     `yaml:"jwt" envconfig:"JWT"`
	SMTP    SMTPConfig    `yaml:"smtp" envconfig:"SMTP"`
	OP      OPConfig      `yaml:"op" envconfig:"OP"`
}

// ServerConfig contains HTTP server configuration.
type ServerConfig struct {
	Host           string     `yaml:"host" envconfig:"HOST"`
	Port           int        `yaml:"port" envconfig:"PORT"`
	AdminPort      int        `yaml:"admin_port" envconfig:"ADMIN_PORT"`
	AdminToken     string     `yaml:"admin_token" envconfig:"ADMIN_TOKEN"`
	AdminTokenPath string     `yaml:"admin_token_path" envconfig:"ADMIN_TOKEN_PATH"`
	BaseURL        string     `yaml:"base_url" envconfig:"BASE_URL"`
	CORS           CORSConfig `yaml:"cors" envconfig:"CORS"`
	TLS            TLSConfig  `yaml:"tls" envconfig:"TLS"`
	AdminTLS       *TLSConfig `yaml:"admin_tls,omitempty" envconfig:"ADMIN_TLS"`
}

// TLSConfig contains TLS configuration.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled" envconfig:"ENABLED"`
	CertFile   string `yaml:"cert_file" envconfig:"CERT_FILE"`
	KeyFile    string `yaml:"key_file" envconfig:"KEY_FILE"`
	MinVersion string `yaml:"min_version" envconfig:"MIN_VERSION"`
}

// TLSMinVersion returns the minimum TLS version.
func (t *TLSConfig) TLSMinVersion() uint16 {
	switch strings.ToUpper(t.MinVersion) {
	case "1.3", "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// ListenAndServe starts the server with TLS if enabled.
func (t *TLSConfig) ListenAndServe(srv *http.Server) error {
	if t != nil && t.Enabled {
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{}
		}
		srv.TLSConfig.MinVersion = t.TLSMinVersion()
		return srv.ListenAndServeTLS(t.CertFile, t.KeyFile)
	}
	return srv.ListenAndServe()
}

// EffectiveAdminTLS returns the TLS config to use for the admin server.
func EffectiveAdminTLS(shared *TLSConfig, admin *TLSConfig) *TLSConfig {
	if admin != nil && admin.Enabled {
		return admin
	}
	return shared
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins" envconfig:"ALLOWED_ORIGINS"`
	AllowedMethods   []string `yaml:"allowed_methods" envconfig:"ALLOWED_METHODS"`
	AllowedHeaders   []string `yaml:"allowed_headers" envconfig:"ALLOWED_HEADERS"`
	AllowCredentials bool     `yaml:"allow_credentials" envconfig:"ALLOW_CREDENTIALS"`
	MaxAge           int      `yaml:"max_age" envconfig:"MAX_AGE"`
}

// SetDefaults sets default CORS values.
func (c *CORSConfig) SetDefaults() {
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{"*"}
	}
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{"Authorization", "Content-Type", "X-Tenant-ID"}
	}
	if c.MaxAge == 0 {
		c.MaxAge = 43200
	}
}

// StorageConfig contains data store configuration.
type StorageConfig struct {
	Type    string        `yaml:"type" envconfig:"TYPE"`
	MongoDB MongoDBConfig `yaml:"mongodb" envconfig:"MONGODB"`
}

// MongoDBConfig contains MongoDB-specific configuration.
type MongoDBConfig struct {
	URI          string `yaml:"uri" envconfig:"URI"`
	Database     string `yaml:"database" envconfig:"DATABASE"`
	Timeout      int    `yaml:"timeout" envconfig:"TIMEOUT"`
	PasswordPath string `yaml:"password_path" envconfig:"PASSWORD_PATH"`
	TLSEnabled   bool   `yaml:"tls_enabled" envconfig:"TLS_ENABLED"`
	CAPath       string `yaml:"ca_path" envconfig:"CA_PATH"`
	CertPath     string `yaml:"cert_path" envconfig:"CERT_PATH"`
	KeyPath      string `yaml:"key_path" envconfig:"KEY_PATH"`
}

// LoggingConfig contains logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level" envconfig:"LEVEL"`
	Format string `yaml:"format" envconfig:"FORMAT"`
}

// JWTConfig contains JWT configuration.
type JWTConfig struct {
	Secret     string `yaml:"secret" envconfig:"SECRET"`
	SecretPath string `yaml:"secret_path" envconfig:"SECRET_PATH"`
	Issuer     string `yaml:"issuer" envconfig:"ISSUER"`
}

// SMTPConfig contains email delivery configuration.
type SMTPConfig struct {
	Host         string `yaml:"host" envconfig:"HOST"`
	Port         int    `yaml:"port" envconfig:"PORT"`
	Username     string `yaml:"username" envconfig:"USERNAME"`
	Password     string `yaml:"password" envconfig:"PASSWORD"`
	PasswordPath string `yaml:"password_path" envconfig:"PASSWORD_PATH"`
	From         string `yaml:"from" envconfig:"FROM"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	Enabled        bool `yaml:"enabled" envconfig:"ENABLED"`
	MaxAttempts    int  `yaml:"max_attempts" envconfig:"MAX_ATTEMPTS"`
	WindowSeconds  int  `yaml:"window_seconds" envconfig:"WINDOW_SECONDS"`
	LockoutSeconds int  `yaml:"lockout_seconds" envconfig:"LOCKOUT_SECONDS"`
}

// SetDefaults fills in zero-value fields with reasonable defaults.
func (r *RateLimitConfig) SetDefaults() {
	if r.MaxAttempts == 0 {
		r.MaxAttempts = 10
	}
	if r.WindowSeconds == 0 {
		r.WindowSeconds = 60
	}
	if r.LockoutSeconds == 0 {
		r.LockoutSeconds = 300
	}
}

// OPConfig contains OpenID Provider configuration.
type OPConfig struct {
	Issuer             string          `yaml:"issuer" envconfig:"ISSUER"`
	SessionTimeout     int             `yaml:"session_timeout" envconfig:"SESSION_TIMEOUT"`
	CleanupIntervalSec int             `yaml:"cleanup_interval" envconfig:"CLEANUP_INTERVAL"`
	RateLimit          RateLimitConfig `yaml:"rate_limit" envconfig:"RATE_LIMIT"`
}

// Load reads configuration from a YAML file and applies env var overrides.
func Load(configFile string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	if err := envconfig.Process("INVITE", cfg); err != nil {
		return nil, fmt.Errorf("processing env config: %w", err)
	}

	cfg.setDefaults()

	if cfg.Server.AdminTokenPath != "" {
		token, err := readSecret(cfg.Server.AdminTokenPath)
		if err != nil {
			return nil, fmt.Errorf("reading admin token: %w", err)
		}
		cfg.Server.AdminToken = token
	}

	if cfg.JWT.SecretPath != "" {
		secret, err := readSecret(cfg.JWT.SecretPath)
		if err != nil {
			return nil, fmt.Errorf("reading JWT secret: %w", err)
		}
		cfg.JWT.Secret = secret
	}

	if cfg.Storage.MongoDB.PasswordPath != "" {
		password, err := readSecret(cfg.Storage.MongoDB.PasswordPath)
		if err != nil {
			return nil, fmt.Errorf("reading MongoDB password: %w", err)
		}
		cfg.Storage.MongoDB.URI = strings.ReplaceAll(cfg.Storage.MongoDB.URI, "${MONGODB_PASSWORD}", password)
	}

	if cfg.SMTP.PasswordPath != "" {
		password, err := readSecret(cfg.SMTP.PasswordPath)
		if err != nil {
			return nil, fmt.Errorf("reading SMTP password: %w", err)
		}
		cfg.SMTP.Password = password
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func (c *Config) setDefaults() {
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.AdminPort == 0 {
		c.Server.AdminPort = 8081
	}
	if c.Storage.Type == "" {
		c.Storage.Type = "memory"
	}
	if c.Storage.MongoDB.Database == "" {
		c.Storage.MongoDB.Database = "invite_op"
	}
	if c.Storage.MongoDB.Timeout == 0 {
		c.Storage.MongoDB.Timeout = 10
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.JWT.Issuer == "" {
		c.JWT.Issuer = "go-invite-op"
	}
	if c.SMTP.Port == 0 {
		c.SMTP.Port = 587
	}
	if c.OP.SessionTimeout == 0 {
		c.OP.SessionTimeout = 600
	}
	if c.OP.CleanupIntervalSec == 0 {
		c.OP.CleanupIntervalSec = 3600
	}
	c.Server.CORS.SetDefaults()
	c.OP.RateLimit.SetDefaults()
}

// Validate checks configuration for errors.
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Server.AdminPort < 1 || c.Server.AdminPort > 65535 {
		return fmt.Errorf("invalid admin port: %d", c.Server.AdminPort)
	}
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("server.tls.cert_file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.key_file is required when TLS is enabled")
		}
	}
	if c.Server.AdminTLS != nil && c.Server.AdminTLS.Enabled {
		if c.Server.AdminTLS.CertFile == "" {
			return fmt.Errorf("server.admin_tls.cert_file is required when admin TLS is enabled")
		}
		if c.Server.AdminTLS.KeyFile == "" {
			return fmt.Errorf("server.admin_tls.key_file is required when admin TLS is enabled")
		}
	}
	switch c.Storage.Type {
	case "memory", "mongodb":
		// ok
	default:
		return fmt.Errorf("invalid storage type: %s (must be memory or mongodb)", c.Storage.Type)
	}
	if c.Storage.Type == "mongodb" && c.Storage.MongoDB.URI == "" {
		return fmt.Errorf("mongodb uri is required when using mongodb storage")
	}
	if c.Storage.MongoDB.CertPath != "" && c.Storage.MongoDB.KeyPath == "" {
		return fmt.Errorf("mongodb.key_path is required when mongodb.cert_path is set")
	}
	if c.Storage.MongoDB.KeyPath != "" && c.Storage.MongoDB.CertPath == "" {
		return fmt.Errorf("mongodb.cert_path is required when mongodb.key_path is set")
	}
	if c.Server.CORS.AllowCredentials {
		for _, origin := range c.Server.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("CORS: allow_credentials cannot be true when allowed_origins contains '*'")
			}
		}
	}
	return nil
}

// LogProductionWarnings emits warnings for insecure configuration.
func (c *Config) LogProductionWarnings(logger *zap.Logger) {
	if c.JWT.Secret == "" || c.JWT.Secret == "change-me-in-production" {
		logger.Warn("JWT secret is not set or uses the default value")
	}
	if c.Server.AdminToken == "" {
		logger.Warn("Admin token is not set; a random token will be generated")
	}
	if !c.Server.TLS.Enabled {
		logger.Warn("TLS is not enabled; traffic is unencrypted")
	}
	for _, origin := range c.Server.CORS.AllowedOrigins {
		if origin == "*" {
			logger.Warn("CORS allows all origins (wildcard)")
			break
		}
	}
}

func readSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
