package cedar

import (
	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

type Principal struct {
	ExecutionID        string
	WorkflowID         string
	ReadPaths          []string
	WritePaths         []string
	DenyPaths          []string
	AllowedBinaries    []string
	AllowedDomains     []string
	AllowedIPs         []string
	AllowedDelegations []string
	Attributes         map[string]string
}

type Context struct {
	TaskClass           string
	DeclaredPurpose     string
	Language            string
	Backend             models.RuntimeBackend
	AllowNetwork        bool
	AllowShell          bool
	AllowPackageInstall bool
	TimeoutSec          int
	MemoryMB            int
	CPUQuota            int
	StdoutBytes         int
	RequireHostConsent  bool
	PolicyAttributes    map[string]string
}

type CompiledContract struct {
	Principal Principal
	Context   Context
}

func Compile(intent contract.IntentContract) CompiledContract {
	return CompiledContract{
		Principal: Principal{
			ExecutionID:        intent.ExecutionID,
			WorkflowID:         intent.WorkflowID,
			ReadPaths:          append([]string(nil), intent.ResourceScope.ReadPaths...),
			WritePaths:         append([]string(nil), intent.ResourceScope.WritePaths...),
			DenyPaths:          append([]string(nil), intent.ResourceScope.DenyPaths...),
			AllowedBinaries:    append([]string(nil), intent.ProcessScope.AllowedBinaries...),
			AllowedDomains:     append([]string(nil), intent.NetworkScope.AllowedDomains...),
			AllowedIPs:         append([]string(nil), intent.NetworkScope.AllowedIPs...),
			AllowedDelegations: append([]string(nil), intent.BrokerScope.AllowedDelegations...),
			Attributes:         cloneStringMap(intent.Attributes),
		},
		Context: Context{
			TaskClass:           intent.TaskClass,
			DeclaredPurpose:     intent.DeclaredPurpose,
			Language:            intent.Language,
			Backend:             intent.BackendHint,
			AllowNetwork:        intent.NetworkScope.AllowNetwork,
			AllowShell:          intent.ProcessScope.AllowShell,
			AllowPackageInstall: intent.ProcessScope.AllowPackageInstall,
			TimeoutSec:          intent.Budgets.TimeoutSec,
			MemoryMB:            intent.Budgets.MemoryMB,
			CPUQuota:            intent.Budgets.CPUQuota,
			StdoutBytes:         intent.Budgets.StdoutBytes,
			RequireHostConsent:  intent.BrokerScope.RequireHostConsent,
			PolicyAttributes:    cloneStringMap(intent.Attributes),
		},
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
