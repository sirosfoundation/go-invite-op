package health

import (
"context"
"sync"
"time"
)

// ReadinessChecker defines the interface for readiness checks.
type ReadinessChecker interface {
CheckReady(ctx context.Context) error
Name() string
}

// CheckResult holds the result of a single readiness check.
type CheckResult struct {
Name      string    `json:"name"`
Ready     bool      `json:"ready"`
Error     string    `json:"error,omitempty"`
Latency   float64   `json:"latency_ms"`
CheckedAt time.Time `json:"checked_at"`
}

// ReadinessStatus represents the overall readiness status.
type ReadinessStatus struct {
Ready     bool          `json:"ready"`
Checks    []CheckResult `json:"checks"`
CheckedAt time.Time     `json:"checked_at"`
}

// ReadinessManager aggregates multiple readiness checkers and caches results.
type ReadinessManager struct {
checkers     []ReadinessChecker
mu           sync.RWMutex
cachedStatus *ReadinessStatus
cacheTTL     time.Duration
checkTimeout time.Duration
stopCh       chan struct{}
stopOnce     sync.Once
}

// ReadinessOption configures the ReadinessManager.
type ReadinessOption func(*ReadinessManager)

// WithCacheTTL sets the cache TTL for readiness results.
func WithCacheTTL(ttl time.Duration) ReadinessOption {
return func(m *ReadinessManager) { m.cacheTTL = ttl }
}

// WithCheckTimeout sets the maximum time for each readiness check.
func WithCheckTimeout(timeout time.Duration) ReadinessOption {
return func(m *ReadinessManager) { m.checkTimeout = timeout }
}

// NewReadinessManager creates a new readiness manager.
func NewReadinessManager(opts ...ReadinessOption) *ReadinessManager {
m := &ReadinessManager{
checkers:     make([]ReadinessChecker, 0),
cacheTTL:     2 * time.Second,
checkTimeout: 2 * time.Second,
stopCh:       make(chan struct{}),
}
for _, opt := range opts {
opt(m)
}
return m
}

// AddChecker registers a readiness checker.
func (m *ReadinessManager) AddChecker(checker ReadinessChecker) {
m.mu.Lock()
defer m.mu.Unlock()
m.checkers = append(m.checkers, checker)
}

// CheckReady performs readiness checks and returns the aggregated status.
func (m *ReadinessManager) CheckReady(ctx context.Context) *ReadinessStatus {
m.mu.RLock()
if m.cachedStatus != nil && time.Since(m.cachedStatus.CheckedAt) < m.cacheTTL {
status := m.cachedStatus
m.mu.RUnlock()
return status
}
m.mu.RUnlock()
return m.runChecks(ctx)
}

func (m *ReadinessManager) runChecks(ctx context.Context) *ReadinessStatus {
m.mu.RLock()
checkers := make([]ReadinessChecker, len(m.checkers))
copy(checkers, m.checkers)
m.mu.RUnlock()

if len(checkers) == 0 {
status := &ReadinessStatus{
Ready:     true,
Checks:    []CheckResult{},
CheckedAt: time.Now(),
}
m.updateCache(status)
return status
}

checkCtx, cancel := context.WithTimeout(ctx, m.checkTimeout)
defer cancel()

results := make([]CheckResult, len(checkers))
var wg sync.WaitGroup

for i, checker := range checkers {
wg.Add(1)
go func(idx int, c ReadinessChecker) {
defer wg.Done()
start := time.Now()
err := c.CheckReady(checkCtx)
latency := time.Since(start).Seconds() * 1000

result := CheckResult{
Name:      c.Name(),
Ready:     err == nil,
Latency:   latency,
CheckedAt: time.Now(),
}
if err != nil {
result.Error = err.Error()
}
results[idx] = result
}(i, checker)
}

wg.Wait()

allReady := true
for _, r := range results {
if !r.Ready {
allReady = false
break
}
}

status := &ReadinessStatus{
Ready:     allReady,
Checks:    results,
CheckedAt: time.Now(),
}
m.updateCache(status)
return status
}

func (m *ReadinessManager) updateCache(status *ReadinessStatus) {
m.mu.Lock()
defer m.mu.Unlock()
m.cachedStatus = status
}

// StartBackgroundProbe starts periodic readiness checks.
func (m *ReadinessManager) StartBackgroundProbe(interval time.Duration) {
go func() {
ticker := time.NewTicker(interval)
defer ticker.Stop()
m.runChecks(context.Background())
for {
select {
case <-ticker.C:
m.runChecks(context.Background())
case <-m.stopCh:
return
}
}
}()
}

// Stop stops the background probe.
func (m *ReadinessManager) Stop() {
m.stopOnce.Do(func() { close(m.stopCh) })
}

// Pinger interface for database ping operations.
type Pinger interface {
Ping(ctx context.Context) error
}

// DatabaseChecker checks database connectivity.
type DatabaseChecker struct {
name   string
pinger Pinger
}

// NewDatabaseChecker creates a checker for database connectivity.
func NewDatabaseChecker(name string, pinger Pinger) *DatabaseChecker {
return &DatabaseChecker{name: name, pinger: pinger}
}

func (c *DatabaseChecker) Name() string { return c.name }

func (c *DatabaseChecker) CheckReady(ctx context.Context) error {
if c.pinger == nil {
return nil
}
return c.pinger.Ping(ctx)
}
