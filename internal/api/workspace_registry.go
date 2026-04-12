package api

import "sync"

// WorkspaceRegistry tracks active executions per workspace for pre-admission overlap rejection.
type WorkspaceRegistry struct {
	mu     sync.Mutex
	active map[string]string
}

func NewWorkspaceRegistry() *WorkspaceRegistry {
	return &WorkspaceRegistry{active: make(map[string]string)}
}

func (r *WorkspaceRegistry) TryClaim(workspaceID string, execID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.active[workspaceID]; ok && existing != "" {
		return false
	}
	r.active[workspaceID] = execID
	return true
}

func (r *WorkspaceRegistry) Release(workspaceID string, execID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if current, ok := r.active[workspaceID]; ok && current == execID {
		delete(r.active, workspaceID)
	}
}
