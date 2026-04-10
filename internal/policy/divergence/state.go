package divergence

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

type BrokerState struct {
	RequestCount    int
	DeniedCount     int
	DeniedDomains   map[string]int
	DeniedBindings  map[string]int
}

type State struct {
	ExecutionID string
	Backend     models.RuntimeBackend
	StartedAt   time.Time
	UpdatedAt   time.Time
	SeenSeqs    map[uint64]struct{}
	LastSeq     uint64

	Process   ProcessState
	File      FileState
	Network   NetworkState
	Decisions DecisionState
	Broker    BrokerState

	RuleHits      []models.DivergenceRuleHit
	activeRuleIDs map[string]struct{}
	Verdict       models.DivergenceVerdict
}

type ProcessState struct {
	ExecCount           int
	ForkCount           int
	ExitCount           int
	ShellExecCount      int
	PackageInstallCount int
	ParentByPID         map[int]int
	BinaryByPID         map[int]string
	DistinctBinaries    map[string]int
	ChildPIDs           map[int]struct{}
}

type FileState struct {
	OpenCount              int
	ReadOpenCount          int
	WriteIntentCount       int
	DistinctPaths          map[string]int
	DeniedPaths            map[string]int
	DeniedWritePaths       map[string]int
	WorkspaceDistinctPaths map[string]int
	DeclaredTargetTouched  bool
	DestructiveWriteCount  int
}

type NetworkState struct {
	ConnectCount         int
	DeniedConnectCount   int
	DistinctDestinations map[string]int
}

type DecisionState struct {
	AllowCount         int
	DenyCount          int
	NotApplicableCount int
}

func newState(intent contract.IntentContract) *State {
	return &State{
		ExecutionID: intent.ExecutionID,
		Backend:     intent.BackendHint,
		SeenSeqs:    map[uint64]struct{}{},
		Process: ProcessState{
			ParentByPID:      map[int]int{},
			BinaryByPID:      map[int]string{},
			DistinctBinaries: map[string]int{},
			ChildPIDs:        map[int]struct{}{},
		},
		File: FileState{
			DistinctPaths:          map[string]int{},
			DeniedPaths:            map[string]int{},
			DeniedWritePaths:       map[string]int{},
			WorkspaceDistinctPaths: map[string]int{},
		},
		Network: NetworkState{
			DistinctDestinations: map[string]int{},
		},
		activeRuleIDs: map[string]struct{}{},
		Verdict:       models.DivergenceAllow,
		Broker: BrokerState{
			DeniedDomains:  map[string]int{},
			DeniedBindings: map[string]int{},
		},
	}
}

func (s *State) applyEvent(intent contract.IntentContract, event models.RuntimeEvent, decision *models.PolicyPointDecision) {
	ts := eventTime(event)
	if s.StartedAt.IsZero() {
		s.StartedAt = ts
	}
	s.UpdatedAt = ts
	if s.ExecutionID == "" {
		s.ExecutionID = event.ExecutionID
	}
	if s.Backend == "" {
		s.Backend = event.Backend
	}
	if event.Seq > 0 {
		s.SeenSeqs[event.Seq] = struct{}{}
		if event.Seq > s.LastSeq {
			s.LastSeq = event.Seq
		}
	}

	switch event.Type {
	case models.EventProcessExec:
		s.Process.ExecCount++
		if event.PPID > 0 {
			s.Process.ParentByPID[event.PID] = event.PPID
			s.Process.ChildPIDs[event.PID] = struct{}{}
		}
		binary := eventBinary(event)
		if binary != "" {
			s.Process.BinaryByPID[event.PID] = binary
			s.Process.DistinctBinaries[binary]++
			if isShellBinary(binary) {
				s.Process.ShellExecCount++
			}
			if isPackageInstaller(binary) {
				s.Process.PackageInstallCount++
			}
		}
	case models.EventProcessFork:
		s.Process.ForkCount++
		if event.PPID > 0 {
			s.Process.ParentByPID[event.PID] = event.PPID
		}
		s.Process.ChildPIDs[event.PID] = struct{}{}
	case models.EventProcessExit:
		s.Process.ExitCount++
	case models.EventFileOpen:
		s.File.OpenCount++
		path := cleanPath(event.Path)
		writeIntent := models.FileOpenHasWriteIntent(event.Flags)
		if writeIntent {
			s.File.WriteIntentCount++
			if models.FileOpenHasDestructiveFlags(event.Flags) {
				s.File.DestructiveWriteCount++
			}
		} else {
			s.File.ReadOpenCount++
		}
		if path != "" {
			s.File.DistinctPaths[path]++
			if strings.HasPrefix(path, cleanPath(intent.ResourceScope.WorkspaceRoot)+"/") || path == cleanPath(intent.ResourceScope.WorkspaceRoot) {
				s.File.WorkspaceDistinctPaths[path]++
			}
			if pathMatchesAny(path, intent.ResourceScope.ReadPaths) || pathMatchesAny(path, intent.ResourceScope.WritePaths) {
				s.File.DeclaredTargetTouched = true
			}
			if decision != nil && decision.Decision == models.DecisionDeny {
				if writeIntent {
					s.File.DeniedWritePaths[path]++
				} else {
					s.File.DeniedPaths[path]++
				}
			}
		}
	case models.EventNetConnect:
		s.Network.ConnectCount++
		dest := connectDestination(event)
		if dest != "" {
			s.Network.DistinctDestinations[dest]++
		}
		if decision != nil && decision.Decision == models.DecisionDeny {
			s.Network.DeniedConnectCount++
		}
	}

	if decision != nil {
		switch decision.Decision {
		case models.DecisionAllow:
			s.Decisions.AllowCount++
		case models.DecisionDeny:
			s.Decisions.DenyCount++
		case models.DecisionNotApplicable:
			s.Decisions.NotApplicableCount++
		}
	}
}

func (s *State) addRuleHit(hit models.DivergenceRuleHit) bool {
	if _, ok := s.activeRuleIDs[hit.RuleID]; ok {
		return false
	}
	s.activeRuleIDs[hit.RuleID] = struct{}{}
	s.RuleHits = append(s.RuleHits, hit)
	s.escalateVerdict(hit.Severity)
	return true
}

func (s *State) escalateVerdict(severity models.DivergenceSeverity) {
	switch severity {
	case models.DivergenceSeverityKillCandidate:
		s.Verdict = models.DivergenceKillCandidate
	case models.DivergenceSeverityWarn:
		if s.Verdict == models.DivergenceAllow {
			s.Verdict = models.DivergenceWarn
		}
	}
}

func (s *State) result(intent contract.IntentContract) models.PolicyDivergenceResult {
	reasons := make([]string, 0, len(s.RuleHits))
	for _, hit := range s.RuleHits {
		reasons = append(reasons, hit.Message)
	}
	sort.Strings(reasons)
	metadata := map[string]string{}
	if !s.File.DeclaredTargetTouched {
		metadata["declared_target_touched"] = "false"
	} else {
		metadata["declared_target_touched"] = "true"
	}
	metadata["file_semantics"] = "read-and-write-intent-file-open"
	metadata["workflow_id"] = intent.WorkflowID
	metadata["task_class"] = intent.TaskClass
	return models.PolicyDivergenceResult{
		ExecutionID:    s.ExecutionID,
		Backend:        s.Backend,
		StartedAt:      s.StartedAt,
		UpdatedAt:      s.UpdatedAt,
		LastSeq:        s.LastSeq,
		CurrentVerdict: s.Verdict,
		TriggeredRules: append([]models.DivergenceRuleHit(nil), s.RuleHits...),
		Reasons:        reasons,
		Counters: models.DivergenceCounters{
			ExecCount:                  s.Process.ExecCount,
			ForkCount:                  s.Process.ForkCount,
			ExitCount:                  s.Process.ExitCount,
			FileOpenCount:              s.File.OpenCount,
			FileReadCount:              s.File.ReadOpenCount,
			FileWriteIntentCount:       s.File.WriteIntentCount,
			ConnectCount:               s.Network.ConnectCount,
			DistinctBinaryCount:        len(s.Process.DistinctBinaries),
			DistinctPathCount:          len(s.File.DistinctPaths),
			DistinctConnectDestCount:   len(s.Network.DistinctDestinations),
			ChildProcessCount:          len(s.Process.ChildPIDs),
			ShellExecCount:             s.Process.ShellExecCount,
			PackageInstallCount:        s.Process.PackageInstallCount,
			DeniedFileOpenCount:        deniedFileCount(s.File.DeniedPaths) + deniedFileCount(s.File.DeniedWritePaths),
			DeniedWriteIntentCount:     deniedFileCount(s.File.DeniedWritePaths),
			DeniedConnectCount:         s.Network.DeniedConnectCount,
			AllowDecisionCount:         s.Decisions.AllowCount,
			DenyDecisionCount:          s.Decisions.DenyCount,
			NotApplicableDecisionCount: s.Decisions.NotApplicableCount,
			BrokerRequestCount:         s.Broker.RequestCount,
			BrokerDeniedCount:          s.Broker.DeniedCount,
		},
		Metadata: metadata,
	}
}

func deniedFileCount(denied map[string]int) int {
	total := 0
	for _, count := range denied {
		total += count
	}
	return total
}

func eventBinary(event models.RuntimeEvent) string {
	if clean := strings.TrimSpace(event.Exe); clean != "" {
		return filepath.Base(clean)
	}
	return filepath.Base(strings.TrimSpace(event.Comm))
}

func connectDestination(event models.RuntimeEvent) string {
	if strings.TrimSpace(event.Domain) != "" {
		return strings.TrimSpace(event.Domain)
	}
	if strings.TrimSpace(event.DstIP) != "" {
		return strings.TrimSpace(event.DstIP)
	}
	return ""
}

func eventTime(event models.RuntimeEvent) time.Time {
	if event.TsUnixNano > 0 {
		return time.Unix(0, event.TsUnixNano).UTC()
	}
	return time.Now().UTC()
}

func cleanPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}

func pathMatchesAny(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		cleaned := cleanPath(prefix)
		if cleaned == "" {
			continue
		}
		if path == cleaned {
			return true
		}
		if strings.HasPrefix(path, cleaned+"/") {
			return true
		}
	}
	return false
}

func isShellBinary(name string) bool {
	switch name {
	case "sh", "ash", "bash", "dash", "zsh", "ksh", "fish":
		return true
	default:
		return false
	}
}

func isPackageInstaller(name string) bool {
	switch name {
	case "pip", "pip3", "npm", "pnpm", "yarn", "apk", "apt", "apt-get", "dnf", "yum", "gem", "cargo", "brew":
		return true
	default:
		return false
	}
}
