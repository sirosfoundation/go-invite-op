package middleware

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// RateLimitConfig configures rate limiting behavior.
type RateLimitConfig struct {
	Enabled        bool `yaml:"enabled" envconfig:"ENABLED"`
	MaxAttempts    int  `yaml:"max_attempts" envconfig:"MAX_ATTEMPTS"`
	WindowSeconds  int  `yaml:"window_seconds" envconfig:"WINDOW_SECONDS"`
	LockoutSeconds int  `yaml:"lockout_seconds" envconfig:"LOCKOUT_SECONDS"`
}

// SetDefaults fills in zero-value fields with reasonable defaults.
func (c *RateLimitConfig) SetDefaults() {
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 10
	}
	if c.WindowSeconds == 0 {
		c.WindowSeconds = 60
	}
	if c.LockoutSeconds == 0 {
		c.LockoutSeconds = 300
	}
}

// RateLimiter manages per-identifier sliding-window rate limiting with lockout.
type RateLimiter struct {
	config RateLimitConfig
	logger *zap.Logger

	mu       sync.RWMutex
	limiters map[string]*identLimiter

	cleanupInterval time.Duration
	lastCleanup     time.Time
}

type identLimiter struct {
	limiter    *rate.Limiter
	lastSeen   time.Time
	lockedOut  bool
	lockoutEnd time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cfg RateLimitConfig, logger *zap.Logger) *RateLimiter {
	cfg.SetDefaults()
	return &RateLimiter{
		config:          cfg,
		logger:          logger.Named("ratelimit"),
		limiters:        make(map[string]*identLimiter),
		cleanupInterval: 10 * time.Minute,
		lastCleanup:     time.Now(),
	}
}

func (r *RateLimiter) getLimiter(identifier string) *identLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Since(r.lastCleanup) > r.cleanupInterval {
		r.cleanup()
	}

	lim, exists := r.limiters[identifier]
	if exists {
		lim.lastSeen = time.Now()
		return lim
	}

	rateLimit := rate.Limit(float64(r.config.MaxAttempts) / float64(r.config.WindowSeconds))
	burst := int(math.Ceil(float64(r.config.MaxAttempts) / 2.0))
	if burst < 1 {
		burst = 1
	}

	lim = &identLimiter{
		limiter:  rate.NewLimiter(rateLimit, burst),
		lastSeen: time.Now(),
	}
	r.limiters[identifier] = lim
	return lim
}

func (r *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-30 * time.Minute)
	for key, lim := range r.limiters {
		if lim.lastSeen.Before(cutoff) {
			delete(r.limiters, key)
		}
	}
	r.lastCleanup = time.Now()
}

// Allow checks whether a request from identifier should be permitted.
func (r *RateLimiter) Allow(identifier string) bool {
	if !r.config.Enabled {
		return true
	}

	lim := r.getLimiter(identifier)

	r.mu.RLock()
	if lim.lockedOut {
		if time.Now().Before(lim.lockoutEnd) {
			r.mu.RUnlock()
			return false
		}
		r.mu.RUnlock()
		r.mu.Lock()
		lim.lockedOut = false
		r.mu.Unlock()
	} else {
		r.mu.RUnlock()
	}

	if !lim.limiter.Allow() {
		r.mu.Lock()
		lim.lockedOut = true
		lim.lockoutEnd = time.Now().Add(time.Duration(r.config.LockoutSeconds) * time.Second)
		r.mu.Unlock()

		r.logger.Warn("Rate limit exceeded, applying lockout",
			zap.String("identifier", identifier),
			zap.Duration("lockout_duration", time.Duration(r.config.LockoutSeconds)*time.Second),
		)
		return false
	}

	return true
}

// RecordFailure consumes extra tokens on a failed attempt.
func (r *RateLimiter) RecordFailure(identifier string) {
	if !r.config.Enabled {
		return
	}
	lim := r.getLimiter(identifier)
	lim.limiter.AllowN(time.Now(), 2)
}

// RateLimitMiddleware returns middleware that rate-limits by client IP.
func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		identifier := c.ClientIP()

		if !rl.Allow(identifier) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
