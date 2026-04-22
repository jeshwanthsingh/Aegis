package api

import (
	"fmt"
	"strings"

	"aegis/internal/policy"
)

type AdmissionPreview struct {
	ExecutionID       string
	PolicyDigest      string
	AuthorityDigest   string
	ApprovalMode      string
	BrokerActionTypes []string
	BrokerRepoLabels  []string
}

// PreviewAdmission computes the same frozen authority and digests used at
// runtime admission without starting an execution.
func PreviewAdmission(req ExecuteRequest, pol *policy.Policy, assetsDir string, rootfsPath string) (AdmissionPreview, error) {
	if pol == nil {
		return AdmissionPreview{}, fmt.Errorf("policy is required")
	}
	defaultTimeoutMs := pol.DefaultTimeoutMs
	_, intent, err := buildPointEvaluator(&req, defaultTimeoutMs)
	if err != nil {
		return AdmissionPreview{}, err
	}
	timeoutMs := req.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = pol.DefaultTimeoutMs
	}
	req.TimeoutMs = timeoutMs
	req.Profile = resolveRequestedProfile(req, pol)
	if _, ok := pol.Profiles[req.Profile]; !ok {
		return AdmissionPreview{}, fmt.Errorf("invalid compute profile %q", req.Profile)
	}
	if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
		return AdmissionPreview{}, err
	}
	effectiveNetwork, err := resolveEffectiveNetworkPolicy(pol.Network, intent)
	if err != nil {
		return AdmissionPreview{}, err
	}
	execPolicy := clonePolicyWithNetwork(pol, effectiveNetwork)
	policyEvidence, err := policyEvidenceForExecution(req, execPolicy, timeoutMs)
	if err != nil {
		return AdmissionPreview{}, err
	}
	execID, err := chooseExecutionID(requestedExecutionID(req, intent))
	if err != nil {
		return AdmissionPreview{}, err
	}
	frozen, err := freezeAuthorityForExecution(execID, req, intent, policyEvidence, execPolicy, assetsDir, rootfsPath)
	if err != nil {
		return AdmissionPreview{}, err
	}
	return AdmissionPreview{
		ExecutionID:       strings.TrimSpace(frozen.ExecutionID),
		PolicyDigest:      strings.TrimSpace(frozen.PolicyDigest),
		AuthorityDigest:   strings.TrimSpace(frozen.AuthorityDigest),
		ApprovalMode:      string(frozen.ApprovalMode),
		BrokerActionTypes: append([]string(nil), frozen.BrokerActionTypes...),
		BrokerRepoLabels:  append([]string(nil), frozen.BrokerRepoLabels...),
	}, nil
}
