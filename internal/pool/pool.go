package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"aegis/internal/executor"
	"aegis/internal/observability"
	"aegis/internal/policy"

	"github.com/google/uuid"
)

const defaultReadyTimeout = 30 * time.Second

type Hooks struct {
	Build     func(context.Context, string) (*executor.VMInstance, error)
	WaitReady func(context.Context, *executor.VMInstance) error
	Pause     func(context.Context, *executor.VMInstance) error
	Resume    func(context.Context, *executor.VMInstance) error
	Teardown  func(*executor.VMInstance) error
}

type Config struct {
	Size         int
	MaxAge       time.Duration
	ReadyTimeout time.Duration
	AssetsDir    string
	RootfsPath   string
	Policy       *policy.Policy
	Profile      policy.ComputeProfile
	ProfileName  string
	Shapes       []ShapeConfig
}

type Status struct {
	Enabled             bool              `json:"enabled"`
	ConfiguredSize      int               `json:"configured_size"`
	Available           int               `json:"available"`
	Initializing        int               `json:"initializing"`
	MaxAgeSeconds       int64             `json:"max_age_seconds"`
	WarmClaims          uint64            `json:"warm_claims"`
	ColdFallbacks       uint64            `json:"cold_fallbacks"`
	ClaimErrors         uint64            `json:"claim_errors"`
	RecycledExpired     uint64            `json:"recycled_expired"`
	ConfiguredByShape   map[string]int    `json:"configured_by_shape,omitempty"`
	AvailableByShape    map[string]int    `json:"available_by_shape,omitempty"`
	InitializingByShape map[string]int    `json:"initializing_by_shape,omitempty"`
	ColdFallbackReasons map[string]uint64 `json:"cold_fallback_reasons,omitempty"`
}

type entry struct {
	id      string
	vm      *executor.VMInstance
	readyAt time.Time
}

type Manager struct {
	cfg    Config
	hooks  Hooks
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu           sync.Mutex
	ready        []*entry
	initializing int
	closed       bool

	warmClaims      atomic.Uint64
	coldFallbacks   atomic.Uint64
	claimErrors     atomic.Uint64
	recycledExpired atomic.Uint64

	shapeManagers   map[string]*shapeManager
	shapeOrder      []string
	fallbackReasons map[string]uint64
}

type shapeManager struct {
	label   string
	manager *Manager
}

func New(cfg Config) *Manager {
	if len(cfg.Shapes) > 0 {
		if cfg.MaxAge <= 0 {
			cfg.MaxAge = 5 * time.Minute
		}
		if cfg.ReadyTimeout <= 0 {
			cfg.ReadyTimeout = defaultReadyTimeout
		}
		mgr := &Manager{
			cfg:             cfg,
			shapeManagers:   map[string]*shapeManager{},
			fallbackReasons: map[string]uint64{},
		}
		for _, shape := range cfg.Shapes {
			if shape.Size <= 0 {
				continue
			}
			sub := newSingle(Config{
				Size:         shape.Size,
				MaxAge:       cfg.MaxAge,
				ReadyTimeout: cfg.ReadyTimeout,
				AssetsDir:    shape.AssetsDir,
				RootfsPath:   shape.RootfsPath,
				Policy:       shape.Policy,
				Profile:      shape.Profile,
				ProfileName:  shape.ProfileName,
			})
			mgr.shapeManagers[shape.Key] = &shapeManager{label: shape.Label, manager: sub}
			mgr.shapeOrder = append(mgr.shapeOrder, shape.Key)
		}
		return mgr
	}
	return newSingle(cfg)
}

func newSingle(cfg Config) *Manager {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 5 * time.Minute
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = defaultReadyTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &Manager{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
	mgr.hooks = Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			return executor.NewVM(id, "", cfg.Policy, cfg.Profile, cfg.AssetsDir, cfg.RootfsPath, nil)
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error {
			return executor.WaitForGuestReady(vm.VsockPath, buildTimeout(ctx))
		},
		Pause: executor.PauseVM,
		Resume: func(ctx context.Context, vm *executor.VMInstance) error {
			return executor.ResumeVM(ctx, vm)
		},
		Teardown: func(vm *executor.VMInstance) error {
			return executor.Teardown(vm, nil)
		},
	}
	return mgr
}

func NewWithHooks(cfg Config, hooks Hooks) *Manager {
	mgr := New(cfg)
	if hooks.Build != nil {
		mgr.hooks.Build = hooks.Build
	}
	if hooks.Pause != nil {
		mgr.hooks.Pause = hooks.Pause
	}
	if hooks.WaitReady != nil {
		mgr.hooks.WaitReady = hooks.WaitReady
	}
	if hooks.Resume != nil {
		mgr.hooks.Resume = hooks.Resume
	}
	if hooks.Teardown != nil {
		mgr.hooks.Teardown = hooks.Teardown
	}
	return mgr
}

func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	if len(m.shapeManagers) > 0 {
		return len(m.shapeManagers) > 0
	}
	return m.cfg.Size > 0
}

func (m *Manager) Start() {
	if !m.Enabled() {
		return
	}
	if len(m.shapeManagers) > 0 {
		for _, key := range m.shapeOrder {
			m.shapeManagers[key].manager.Start()
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCapacityLocked()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.recycleLoop()
	}()
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	if len(m.shapeManagers) > 0 {
		var firstErr error
		for _, key := range m.shapeOrder {
			if err := m.shapeManagers[key].manager.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	m.cancel()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	entries := append([]*entry(nil), m.ready...)
	m.ready = nil
	m.mu.Unlock()

	for _, e := range entries {
		if err := m.hooks.Teardown(e.vm); err != nil {
			observability.Warn("warm_pool_teardown_failed", observability.Fields{"pool_vm_id": e.id, "error": err.Error()})
		}
	}
	m.wg.Wait()
	return nil
}

func (m *Manager) Claim(ctx context.Context) (*executor.VMInstance, bool, error) {
	vm, warm, _, err := m.claimWithReason(ctx)
	return vm, warm, err
}

func (m *Manager) ClaimFor(ctx context.Context, shapeKey string) (*executor.VMInstance, bool, string, error) {
	if !m.Enabled() {
		return nil, false, FallbackPoolDisabled, nil
	}
	if len(m.shapeManagers) == 0 {
		return m.claimWithReason(ctx)
	}
	shape, ok := m.shapeManagers[shapeKey]
	if !ok {
		m.RecordColdFallbackReason(FallbackShapeMissing)
		return nil, false, FallbackShapeMissing, nil
	}
	vm, warm, reason, err := shape.manager.claimWithReason(ctx)
	if !warm {
		m.RecordColdFallbackReason(reason)
	}
	return vm, warm, reason, err
}

func (m *Manager) claimWithReason(ctx context.Context) (*executor.VMInstance, bool, string, error) {
	if !m.Enabled() {
		return nil, false, FallbackPoolDisabled, nil
	}
	staleFound := false
	for {
		var claimed *entry
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, false, FallbackClaimError, errors.New("warm pool closed")
		}
		now := time.Now()
		for len(m.ready) > 0 {
			candidate := m.ready[0]
			m.ready = m.ready[1:]
			if now.Sub(candidate.readyAt) > m.cfg.MaxAge {
				staleFound = true
				m.recycledExpired.Add(1)
				go m.recycle(candidate)
				continue
			}
			claimed = candidate
			break
		}
		m.ensureCapacityLocked()
		m.mu.Unlock()

		if claimed == nil {
			m.coldFallbacks.Add(1)
			if staleFound {
				return nil, false, FallbackStaleEntry, nil
			}
			return nil, false, FallbackPoolEmpty, nil
		}
		if err := m.hooks.Resume(ctx, claimed.vm); err != nil {
			m.claimErrors.Add(1)
			go m.recycle(claimed)
			m.coldFallbacks.Add(1)
			return nil, false, FallbackClaimError, err
		}
		m.warmClaims.Add(1)
		return claimed.vm, true, "", nil
	}
}

func (m *Manager) RecordColdFallback() {
	m.RecordColdFallbackReason(FallbackPoolEmpty)
}

func (m *Manager) SupportsShape(shapeKey string) bool {
	if m == nil || shapeKey == "" {
		return false
	}
	if len(m.shapeManagers) == 0 {
		return m.Enabled()
	}
	_, ok := m.shapeManagers[shapeKey]
	return ok
}

func (m *Manager) RecordColdFallbackReason(reason string) {
	if m == nil {
		return
	}
	if reason == "" {
		reason = FallbackPoolEmpty
	}
	if len(m.shapeManagers) > 0 {
		m.mu.Lock()
		m.fallbackReasons[reason]++
		m.mu.Unlock()
	}
	m.coldFallbacks.Add(1)
}

func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	if len(m.shapeManagers) > 0 {
		status := Status{
			Enabled:             len(m.shapeManagers) > 0,
			MaxAgeSeconds:       int64(m.cfg.MaxAge / time.Second),
			ConfiguredByShape:   map[string]int{},
			AvailableByShape:    map[string]int{},
			InitializingByShape: map[string]int{},
			ColdFallbackReasons: map[string]uint64{},
		}
		for _, key := range m.shapeOrder {
			shape := m.shapeManagers[key]
			subStatus := shape.manager.Status()
			status.ConfiguredSize += subStatus.ConfiguredSize
			status.Available += subStatus.Available
			status.Initializing += subStatus.Initializing
			status.WarmClaims += subStatus.WarmClaims
			status.ColdFallbacks += subStatus.ColdFallbacks
			status.ClaimErrors += subStatus.ClaimErrors
			status.RecycledExpired += subStatus.RecycledExpired
			status.ConfiguredByShape[shape.label] = subStatus.ConfiguredSize
			status.AvailableByShape[shape.label] = subStatus.Available
			status.InitializingByShape[shape.label] = subStatus.Initializing
		}
		status.ColdFallbacks += m.coldFallbacks.Load()
		m.mu.Lock()
		for reason, count := range m.fallbackReasons {
			status.ColdFallbackReasons[reason] = count
		}
		m.mu.Unlock()
		return status
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Enabled:         m.cfg.Size > 0,
		ConfiguredSize:  m.cfg.Size,
		Available:       len(m.ready),
		Initializing:    m.initializing,
		MaxAgeSeconds:   int64(m.cfg.MaxAge / time.Second),
		WarmClaims:      m.warmClaims.Load(),
		ColdFallbacks:   m.coldFallbacks.Load(),
		ClaimErrors:     m.claimErrors.Load(),
		RecycledExpired: m.recycledExpired.Load(),
	}
}

func (m *Manager) recycleLoop() {
	interval := m.cfg.MaxAge / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.expireStale()
		}
	}
}

func (m *Manager) expireStale() {
	now := time.Now()
	var expired []*entry
	m.mu.Lock()
	kept := m.ready[:0]
	for _, candidate := range m.ready {
		if now.Sub(candidate.readyAt) > m.cfg.MaxAge {
			expired = append(expired, candidate)
			continue
		}
		kept = append(kept, candidate)
	}
	m.ready = kept
	if len(expired) > 0 {
		m.recycledExpired.Add(uint64(len(expired)))
	}
	m.ensureCapacityLocked()
	m.mu.Unlock()

	for _, candidate := range expired {
		go m.recycle(candidate)
	}
}

func (m *Manager) recycle(candidate *entry) {
	if candidate == nil {
		return
	}
	if err := m.hooks.Teardown(candidate.vm); err != nil {
		observability.Warn("warm_pool_recycle_failed", observability.Fields{"pool_vm_id": candidate.id, "error": err.Error()})
	}
}

func (m *Manager) ensureCapacityLocked() {
	if m.closed || m.cfg.Size <= 0 {
		return
	}
	for len(m.ready)+m.initializing < m.cfg.Size {
		m.initializing++
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.buildOne()
		}()
	}
}

func (m *Manager) buildOne() {
	defer func() {
		m.mu.Lock()
		m.initializing--
		m.ensureCapacityLocked()
		m.mu.Unlock()
	}()

	buildCtx, cancel := context.WithTimeout(m.ctx, m.cfg.ReadyTimeout)
	defer cancel()

	id := uuid.New().String()
	vm, err := m.hooks.Build(buildCtx, id)
	if err != nil {
		if m.ctx.Err() == nil {
			observability.Warn("warm_pool_build_failed", observability.Fields{"pool_vm_id": id, "error": err.Error()})
		}
		return
	}
	if err := m.hooks.WaitReady(buildCtx, vm); err != nil {
		_ = m.hooks.Teardown(vm)
		if m.ctx.Err() == nil {
			observability.Warn("warm_pool_guest_ready_failed", observability.Fields{"pool_vm_id": id, "error": err.Error()})
		}
		return
	}
	if err := m.hooks.Pause(buildCtx, vm); err != nil {
		_ = m.hooks.Teardown(vm)
		if m.ctx.Err() == nil {
			observability.Warn("warm_pool_pause_failed", observability.Fields{"pool_vm_id": id, "error": err.Error()})
		}
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		go m.recycle(&entry{id: id, vm: vm})
		return
	}
	m.ready = append(m.ready, &entry{id: id, vm: vm, readyAt: time.Now()})
	observability.Info("warm_pool_vm_ready", observability.Fields{"pool_vm_id": id, "available": len(m.ready)})
}

func buildTimeout(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultReadyTimeout
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return time.Millisecond
	}
	return timeout
}
