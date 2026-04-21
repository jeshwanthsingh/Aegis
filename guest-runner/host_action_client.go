package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

const hostRepoApplyActionType = "host_repo_apply_patch"

type hostActionRequest struct {
	Class          string                     `json:"class"`
	RepoApplyPatch *hostRepoApplyPatchRequest `json:"repo_apply_patch,omitempty"`
}

type hostRepoApplyPatchRequest struct {
	RepoLabel    string   `json:"repo_label"`
	PatchBase64  string   `json:"patch_base64"`
	TargetScope  []string `json:"target_scope,omitempty"`
	BaseRevision string   `json:"base_revision"`
}

type hostActionResponse struct {
	Class          string                      `json:"class,omitempty"`
	RepoApplyPatch *hostRepoApplyPatchResponse `json:"repo_apply_patch,omitempty"`
}

type hostRepoApplyPatchResponse struct {
	RepoLabel       string   `json:"repo_label"`
	AppliedPaths    []string `json:"applied_paths,omitempty"`
	PatchDigest     string   `json:"patch_digest"`
	PatchDigestAlgo string   `json:"patch_digest_algo"`
	BaseRevision    string   `json:"base_revision"`
}

func brokerHostRepoApplyPatch(repoLabel string, patch []byte, baseRevision string, targetScope []string, approvalTicket json.RawMessage) (*hostRepoApplyPatchResponse, error) {
	action := hostActionRequest{
		Class: hostRepoApplyActionType,
		RepoApplyPatch: &hostRepoApplyPatchRequest{
			RepoLabel:    strings.TrimSpace(repoLabel),
			PatchBase64:  base64.StdEncoding.EncodeToString(patch),
			TargetScope:  append([]string(nil), targetScope...),
			BaseRevision: strings.TrimSpace(baseRevision),
		},
	}
	actionJSON, err := json.Marshal(action)
	if err != nil {
		return nil, fmt.Errorf("marshal host action: %w", err)
	}

	conn, err := vsock.Dial(brokerVsockCID, brokerVsockPort, nil)
	if err != nil {
		return nil, fmt.Errorf("broker unavailable: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(brokerTimeout)); err != nil {
		return nil, fmt.Errorf("set broker deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(proxyRequest{
		ActionType:     hostRepoApplyActionType,
		HostAction:     actionJSON,
		ApprovalTicket: approvalTicket,
	}); err != nil {
		return nil, fmt.Errorf("send host action request: %w", err)
	}

	var resp proxyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode host action response: %w", err)
	}
	if resp.Denied {
		return nil, fmt.Errorf("broker denied: %s", resp.DenyReason)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("broker error: %s", resp.Error)
	}
	if len(resp.HostAction) == 0 {
		return nil, fmt.Errorf("broker response missing host_action payload")
	}

	var decoded hostActionResponse
	if err := json.Unmarshal(resp.HostAction, &decoded); err != nil {
		return nil, fmt.Errorf("decode host action payload: %w", err)
	}
	if decoded.Class != hostRepoApplyActionType || decoded.RepoApplyPatch == nil {
		return nil, fmt.Errorf("unexpected host action response class %q", decoded.Class)
	}
	return decoded.RepoApplyPatch, nil
}
