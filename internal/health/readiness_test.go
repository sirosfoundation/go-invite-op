package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPinger struct {
	err error
}

func (m *mockPinger) Ping(ctx context.Context) error {
	return m.err
}

func TestReadinessManager_AllHealthy(t *testing.T) {
	rm := NewReadinessManager(WithCacheTTL(50*time.Millisecond), WithCheckTimeout(time.Second))
	rm.AddChecker(NewDatabaseChecker("db", &mockPinger{}))

	status := rm.CheckReady(context.Background())
	require.True(t, status.Ready)
	require.Len(t, status.Checks, 1)
	assert.Equal(t, "db", status.Checks[0].Name)
	assert.True(t, status.Checks[0].Ready)
}

func TestReadinessManager_Unhealthy(t *testing.T) {
	rm := NewReadinessManager(WithCacheTTL(50*time.Millisecond), WithCheckTimeout(time.Second))
	rm.AddChecker(NewDatabaseChecker("db", &mockPinger{err: errors.New("connection refused")}))

	status := rm.CheckReady(context.Background())
	assert.False(t, status.Ready)
	assert.Len(t, status.Checks, 1)
	assert.False(t, status.Checks[0].Ready)
	assert.Equal(t, "connection refused", status.Checks[0].Error)
}

func TestReadinessManager_NilPinger(t *testing.T) {
	rm := NewReadinessManager()
	rm.AddChecker(NewDatabaseChecker("db", nil))

	status := rm.CheckReady(context.Background())
	assert.True(t, status.Ready)
}

func TestReadinessManager_NoCheckers(t *testing.T) {
	rm := NewReadinessManager()

	status := rm.CheckReady(context.Background())
	assert.True(t, status.Ready)
	assert.Empty(t, status.Checks)
}

func TestReadinessManager_CachingWorks(t *testing.T) {
	p := &mockPinger{}
	rm := NewReadinessManager(WithCacheTTL(200 * time.Millisecond))
	rm.AddChecker(NewDatabaseChecker("db", p))

	status1 := rm.CheckReady(context.Background())
	require.True(t, status1.Ready)

	// Change pinger to fail - should still get cached healthy result
	p.err = errors.New("down")
	status2 := rm.CheckReady(context.Background())
	assert.True(t, status2.Ready)

	// Wait for cache to expire
	time.Sleep(250 * time.Millisecond)
	status3 := rm.CheckReady(context.Background())
	assert.False(t, status3.Ready)
}

func TestReadinessManager_BackgroundProbe(t *testing.T) {
	rm := NewReadinessManager(WithCacheTTL(50 * time.Millisecond))
	rm.AddChecker(NewDatabaseChecker("db", &mockPinger{}))
	rm.StartBackgroundProbe(100 * time.Millisecond)
	defer rm.Stop()

	time.Sleep(150 * time.Millisecond)
	status := rm.CheckReady(context.Background())
	assert.True(t, status.Ready)
}
