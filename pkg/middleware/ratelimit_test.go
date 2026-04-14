package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestRateLimiterDisabled(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Enabled: false}, zap.NewNop())
	for i := 0; i < 100; i++ {
		assert.True(t, rl.Allow("test-ip"))
	}
}

func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:        true,
		MaxAttempts:    5,
		WindowSeconds:  1,
		LockoutSeconds: 10,
	}, zap.NewNop())

	// First few requests should be allowed
	for i := 0; i < 3; i++ {
		assert.True(t, rl.Allow("ip-1"), "request %d should be allowed", i)
	}
}

func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:        true,
		MaxAttempts:    3,
		WindowSeconds:  1,
		LockoutSeconds: 60,
	}, zap.NewNop())

	// Exhaust the burst
	blocked := false
	for i := 0; i < 20; i++ {
		if !rl.Allow("ip-flood") {
			blocked = true
			break
		}
	}
	assert.True(t, blocked, "should eventually block")

	// Subsequent requests should also be blocked (lockout)
	assert.False(t, rl.Allow("ip-flood"))
}

func TestRateLimiterPerIdentifier(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:        true,
		MaxAttempts:    3,
		WindowSeconds:  1,
		LockoutSeconds: 60,
	}, zap.NewNop())

	// Exhaust ip-a
	for i := 0; i < 20; i++ {
		rl.Allow("ip-a")
	}

	// ip-b should still be allowed
	assert.True(t, rl.Allow("ip-b"))
}

func TestRateLimiterRecordFailure(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:        true,
		MaxAttempts:    5,
		WindowSeconds:  1,
		LockoutSeconds: 60,
	}, zap.NewNop())

	// Record failures consumes extra tokens
	rl.RecordFailure("ip-fail")
	rl.RecordFailure("ip-fail")

	// Should have fewer remaining tokens
	// Eventually should be blocked
	blocked := false
	for i := 0; i < 10; i++ {
		if !rl.Allow("ip-fail") {
			blocked = true
			break
		}
	}
	assert.True(t, blocked)
}

func TestRateLimitConfigSetDefaults(t *testing.T) {
	cfg := RateLimitConfig{}
	cfg.SetDefaults()
	assert.Equal(t, 10, cfg.MaxAttempts)
	assert.Equal(t, 60, cfg.WindowSeconds)
	assert.Equal(t, 300, cfg.LockoutSeconds)
}
