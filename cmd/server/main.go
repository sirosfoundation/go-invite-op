package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sirosfoundation/go-invite-op/internal/api"
	"github.com/sirosfoundation/go-invite-op/internal/config"
	"github.com/sirosfoundation/go-invite-op/internal/email"
	"github.com/sirosfoundation/go-invite-op/internal/health"
	"github.com/sirosfoundation/go-invite-op/internal/op"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
	"github.com/sirosfoundation/go-invite-op/internal/storage/memory"
	"github.com/sirosfoundation/go-invite-op/internal/storage/mongodb"
	"github.com/sirosfoundation/go-invite-op/pkg/middleware"
)

var (
	configFile = flag.String("config", "configs/config.yaml", "Path to configuration file")
	version    = "dev"
	buildTime  = "unknown"
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger, err := newLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	cfg.LogProductionWarnings(logger)

	logger.Info("Starting go-invite-op",
		zap.String("version", version),
		zap.String("build_time", buildTime),
		zap.String("storage_type", cfg.Storage.Type),
	)

	// Storage
	var store storage.Store
	switch cfg.Storage.Type {
	case "mongodb":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		mongoCfg := &mongodb.Config{
			URI:        cfg.Storage.MongoDB.URI,
			Database:   cfg.Storage.MongoDB.Database,
			Timeout:    cfg.Storage.MongoDB.Timeout,
			TLSEnabled: cfg.Storage.MongoDB.TLSEnabled,
			CAPath:     cfg.Storage.MongoDB.CAPath,
			CertPath:   cfg.Storage.MongoDB.CertPath,
			KeyPath:    cfg.Storage.MongoDB.KeyPath,
		}
		store, err = mongodb.NewStore(ctx, mongoCfg)
		if err != nil {
			logger.Fatal("Failed to connect to MongoDB", zap.Error(err))
		}
		logger.Info("Connected to MongoDB", zap.String("database", cfg.Storage.MongoDB.Database))
	default:
		store = memory.NewStore()
		logger.Info("Using in-memory storage")
	}

	// Static clients are resolved at request time by the provider via
	// ResolveClientForTenant, which handles both tenant scoping and ${tenant}
	// template expansion. No store seeding is needed.
	if len(cfg.OP.StaticClients) > 0 {
		logger.Info("Loaded static OIDC client configurations",
			zap.Int("count", len(cfg.OP.StaticClients)))
	}

	// Readiness manager
	readiness := health.NewReadinessManager(
		health.WithCacheTTL(2*time.Second),
		health.WithCheckTimeout(2*time.Second),
	)
	readiness.AddChecker(health.NewDatabaseChecker("storage", store))
	readiness.StartBackgroundProbe(5 * time.Second)

	// Email sender
	var emailer email.Sender
	if cfg.SMTP.Host != "" {
		emailer = email.NewSMTPSender(cfg.SMTP, logger)
	} else {
		logger.Warn("No SMTP config; using log sender for invite codes")
		emailer = email.NewLogSender(logger)
	}

	// Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Rate limiter for OP endpoints
	var opRateLimiter *middleware.RateLimiter
	if cfg.OP.RateLimit.Enabled {
		opRateLimiter = middleware.NewRateLimiter(middleware.RateLimitConfig{
			Enabled:        cfg.OP.RateLimit.Enabled,
			MaxAttempts:    cfg.OP.RateLimit.MaxAttempts,
			WindowSeconds:  cfg.OP.RateLimit.WindowSeconds,
			LockoutSeconds: cfg.OP.RateLimit.LockoutSeconds,
		}, logger)
	}

	// Hostname for X-Served-By
	hostname, _ := os.Hostname()

	// Main router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.ServedByMiddleware(hostname))
	router.Use(middleware.PrometheusMiddleware("/health", "/status", "/readyz"))
	router.Use(middleware.Logger(logger, "/status", "/health", "/readyz"))
	router.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.Server.CORS.AllowedOrigins,
		AllowMethods:     cfg.Server.CORS.AllowedMethods,
		AllowHeaders:     cfg.Server.CORS.AllowedHeaders,
		AllowCredentials: cfg.Server.CORS.AllowCredentials,
		MaxAge:           time.Duration(cfg.Server.CORS.MaxAge) * time.Second,
	}))

	// Health/status/readiness endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "go-invite-op",
			"version": version,
		})
	})

	router.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "go-invite-op",
			"version": version,
		})
	})

	router.GET("/readyz", func(c *gin.Context) {
		status := readiness.CheckReady(c.Request.Context())
		if !status.Ready {
			logger.Warn("Readiness check failed", zap.Any("checks", status.Checks))
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		c.JSON(http.StatusOK, status)
	})

	// OP routes (public, per-tenant)
	opProvider, err := op.NewProvider(store, cfg, emailer, logger)
	if err != nil {
		logger.Fatal("Failed to create OP provider", zap.Error(err))
	}
	if opRateLimiter != nil {
		router.Use(func(c *gin.Context) {
			if !opRateLimiter.Allow(c.ClientIP()) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
				c.Abort()
				return
			}
			c.Next()
		})
	}
	opProvider.RegisterRoutes(router)

	// API routes (JWT-protected)
	apiGroup := router.Group("/api/v1")
	if cfg.JWT.Secret != "" {
		apiGroup.Use(middleware.JWTAuthMiddleware(cfg.JWT.Secret, logger))
	} else {
		logger.Warn("No JWT secret configured; API routes are unprotected")
	}

	handlers := api.NewHandlers(store, logger)
	handlers.RegisterRoutes(apiGroup)

	// Main HTTP server
	httpAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("HTTP server listening", zap.String("address", httpAddr), zap.Bool("tls", cfg.Server.TLS.Enabled))
		if srvErr := cfg.Server.TLS.ListenAndServe(httpServer); srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			logger.Fatal("HTTP server error", zap.Error(srvErr))
		}
	}()

	// Admin server
	adminToken := cfg.Server.AdminToken
	if adminToken == "" {
		adminToken, err = middleware.GenerateAdminToken()
		if err != nil {
			logger.Fatal("Failed to generate admin token", zap.Error(err))
		}
		logger.Info("Generated admin API token", zap.String("token", adminToken))
		logger.Warn("Auto-generated admin token; set INVITE_SERVER_ADMIN_TOKEN for production")
	}

	adminRouter := gin.New()
	adminRouter.Use(gin.Recovery())

	// Prometheus metrics endpoint (unauthenticated; relies on network isolation
	// of the admin port, same pattern as go-wallet-backend).
	adminRouter.GET("/metrics", gin.WrapH(promhttp.Handler()))

	adminRouter.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "go-invite-op-admin",
			"version": version,
		})
	})

	adminRouter.GET("/admin/readyz", func(c *gin.Context) {
		status := readiness.CheckReady(c.Request.Context())
		if !status.Ready {
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		c.JSON(http.StatusOK, status)
	})

	adminGroup := adminRouter.Group("/admin")
	adminGroup.Use(middleware.AdminAuthMiddleware(adminToken, logger))
	handlers.RegisterRoutes(adminGroup)

	adminAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.AdminPort)
	adminServer := &http.Server{
		Addr:         adminAddr,
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	adminTLS := config.EffectiveAdminTLS(&cfg.Server.TLS, cfg.Server.AdminTLS)
	go func() {
		logger.Info("Admin server listening", zap.String("address", adminAddr), zap.Bool("tls", adminTLS.Enabled))
		if adminErr := adminTLS.ListenAndServe(adminServer); adminErr != nil && !errors.Is(adminErr, http.ErrServerClosed) {
			logger.Fatal("Admin server error", zap.Error(adminErr))
		}
	}()

	// Periodic cleanup of expired/consumed invites and stale sessions
	cleanupTicker := time.NewTicker(time.Duration(cfg.OP.CleanupIntervalSec) * time.Second)
	go func() {
		for range cleanupTicker.C {
			count, err := store.Invites().DeleteExpiredAndConsumed(context.Background())
			if err != nil {
				logger.Error("Failed to cleanup invites", zap.Error(err))
			} else if count > 0 {
				logger.Info("Cleaned up invites", zap.Int64("count", count))
			}
			sessionMaxAge := time.Duration(cfg.OP.SessionTimeout) * time.Second
			sCount, sErr := store.Sessions().DeleteExpired(context.Background(), sessionMaxAge)
			if sErr != nil {
				logger.Error("Failed to cleanup sessions", zap.Error(sErr))
			} else if sCount > 0 {
				logger.Info("Cleaned up expired sessions", zap.Int64("count", sCount))
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down...")
	cleanupTicker.Stop()
	readiness.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}
	if err := adminServer.Shutdown(ctx); err != nil {
		logger.Error("Admin server shutdown error", zap.Error(err))
	}
	if err := store.Close(); err != nil {
		logger.Error("Store close error", zap.Error(err))
	}

	logger.Info("Server stopped")
}

func newLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	level := zap.NewAtomicLevel()
	switch cfg.Level {
	case "debug":
		level.SetLevel(zap.DebugLevel)
	case "warn":
		level.SetLevel(zap.WarnLevel)
	case "error":
		level.SetLevel(zap.ErrorLevel)
	default:
		level.SetLevel(zap.InfoLevel)
	}

	encoding := "json"
	if cfg.Format == "text" {
		encoding = "console"
	}

	zapCfg := zap.Config{
		Level:            level,
		Encoding:         encoding,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewProductionEncoderConfig(),
	}
	zapCfg.EncoderConfig.TimeKey = "ts"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return zapCfg.Build()
}
