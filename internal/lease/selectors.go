package lease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"aegis/internal/approval"
)

func CanonicalizeSelector(selector ResourceSelector) (ResourceSelector, error) {
	switch selector.Kind {
	case SelectorKindHTTPRequestV1:
		if selector.HTTP == nil {
			return ResourceSelector{}, fmt.Errorf("http selector payload is required")
		}
		return canonicalizeHTTPSelector(*selector.HTTP)
	case SelectorKindHostRepoApplyPatchV1:
		if selector.HostRepoApplyPatch == nil {
			return ResourceSelector{}, fmt.Errorf("host_repo_apply_patch selector payload is required")
		}
		return canonicalizeHostRepoApplyPatchSelector(*selector.HostRepoApplyPatch)
	default:
		return ResourceSelector{}, fmt.Errorf("unexpected selector kind %q", selector.Kind)
	}
}

func DigestSelector(selector ResourceSelector) (string, string, error) {
	canonical, err := CanonicalizeSelector(selector)
	if err != nil {
		return "", "", err
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", "", fmt.Errorf("marshal selector: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), approval.ResourceDigestAlgo, nil
}

func MatchSelector(selector ResourceSelector, actionKind ActionKind, resource approval.Resource) error {
	resource, err := approval.CanonicalizeResource(resource)
	if err != nil {
		return fmt.Errorf("canonicalize resource: %w", err)
	}
	canonical, err := CanonicalizeSelector(selector)
	if err != nil {
		return err
	}
	switch actionKind {
	case ActionKindHTTPRequest:
		if canonical.Kind != SelectorKindHTTPRequestV1 || canonical.HTTP == nil {
			return fmt.Errorf("http action requires http_request_v1 selector")
		}
		if resource.Kind != approval.ResourceKindHTTPRequestV1 || resource.HTTP == nil {
			return fmt.Errorf("http selector mismatch")
		}
		parsed, err := url.Parse(resource.HTTP.URL)
		if err != nil {
			return fmt.Errorf("parse resource URL: %w", err)
		}
		host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		if !selectorDomainAllowed(canonical.HTTP.Domain, host) {
			return fmt.Errorf("http domain %q is outside selector %q", host, canonical.HTTP.Domain)
		}
		if len(canonical.HTTP.Methods) > 0 && !containsString(canonical.HTTP.Methods, resource.HTTP.Method) {
			return fmt.Errorf("http method %q is outside selector", resource.HTTP.Method)
		}
		if len(canonical.HTTP.PathPrefixes) > 0 {
			matched := false
			for _, prefix := range canonical.HTTP.PathPrefixes {
				if strings.HasPrefix(parsed.EscapedPath(), prefix) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("http path %q is outside selector", parsed.EscapedPath())
			}
		}
		return nil
	case ActionKindHostRepoApplyPatch:
		if canonical.Kind != SelectorKindHostRepoApplyPatchV1 || canonical.HostRepoApplyPatch == nil {
			return fmt.Errorf("host_repo_apply_patch action requires host_repo_apply_patch_v1 selector")
		}
		if resource.Kind != approval.ResourceKindHostRepoApplyPatchV1 || resource.HostRepoApplyPatch == nil {
			return fmt.Errorf("host_repo_apply_patch selector mismatch")
		}
		if strings.TrimSpace(resource.HostRepoApplyPatch.RepoLabel) != canonical.HostRepoApplyPatch.RepoLabel {
			return fmt.Errorf("repo label %q is outside selector %q", resource.HostRepoApplyPatch.RepoLabel, canonical.HostRepoApplyPatch.RepoLabel)
		}
		if len(canonical.HostRepoApplyPatch.TargetScope) == 0 {
			return nil
		}
		for _, value := range resource.HostRepoApplyPatch.TargetScope {
			if !pathWithinScopes(value, canonical.HostRepoApplyPatch.TargetScope) {
				return fmt.Errorf("target scope %q is outside selector", value)
			}
		}
		for _, value := range resource.HostRepoApplyPatch.AffectedPaths {
			if !pathWithinScopes(value, canonical.HostRepoApplyPatch.TargetScope) {
				return fmt.Errorf("affected path %q is outside selector", value)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported action kind %q", actionKind)
	}
}

func canonicalizeHTTPSelector(selector HTTPRequestSelector) (ResourceSelector, error) {
	domain := strings.TrimSpace(strings.ToLower(selector.Domain))
	if domain == "" {
		return ResourceSelector{}, fmt.Errorf("http selector domain is required")
	}
	methods := canonicalizeHTTPMethods(selector.Methods)
	prefixes, err := canonicalizeHTTPPathPrefixes(selector.PathPrefixes)
	if err != nil {
		return ResourceSelector{}, err
	}
	result := ResourceSelector{
		Kind: SelectorKindHTTPRequestV1,
		HTTP: &HTTPRequestSelector{
			Domain: domain,
		},
	}
	if len(methods) > 0 {
		result.HTTP.Methods = methods
	}
	if len(prefixes) > 0 {
		result.HTTP.PathPrefixes = prefixes
	}
	return result, nil
}

func canonicalizeHostRepoApplyPatchSelector(selector HostRepoApplyPatchSelector) (ResourceSelector, error) {
	repoLabel := strings.TrimSpace(strings.ToLower(selector.RepoLabel))
	if repoLabel == "" {
		return ResourceSelector{}, fmt.Errorf("host_repo_apply_patch selector repo_label is required")
	}
	targetScope, err := canonicalizeRelativePathList(selector.TargetScope)
	if err != nil {
		return ResourceSelector{}, err
	}
	result := ResourceSelector{
		Kind: SelectorKindHostRepoApplyPatchV1,
		HostRepoApplyPatch: &HostRepoApplyPatchSelector{
			RepoLabel: repoLabel,
		},
	}
	if len(targetScope) > 0 {
		result.HostRepoApplyPatch.TargetScope = targetScope
	}
	return result, nil
}

func canonicalizeHTTPMethods(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	methods := make([]string, 0, len(values))
	for _, raw := range values {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return methods
}

func canonicalizeHTTPPathPrefixes(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	prefixes := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			return nil, fmt.Errorf("http path_prefix %q must start with /", value)
		}
		if strings.ContainsAny(value, "?#") {
			return nil, fmt.Errorf("http path_prefix %q must not contain query or fragment", value)
		}
		cleaned := path.Clean(value)
		if cleaned == "." {
			cleaned = "/"
		}
		if cleaned != value {
			return nil, fmt.Errorf("http path_prefix %q must be canonical", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		prefixes = append(prefixes, value)
	}
	sort.Strings(prefixes)
	return prefixes, nil
}

func canonicalizeRelativePathList(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
			return nil, fmt.Errorf("relative path %q must be slash-separated and relative", value)
		}
		cleaned := path.Clean(value)
		if cleaned == "." || cleaned == "" || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return nil, fmt.Errorf("relative path %q must not escape", value)
		}
		for _, segment := range strings.Split(cleaned, "/") {
			if segment == ".git" {
				return nil, fmt.Errorf("relative path %q must not include .git", value)
			}
		}
		if cleaned != value {
			return nil, fmt.Errorf("relative path %q must be canonical", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func pathWithinScopes(value string, scopes []string) bool {
	for _, scope := range scopes {
		if value == scope || strings.HasPrefix(value, scope+"/") {
			return true
		}
	}
	return false
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func selectorDomainAllowed(allowed string, host string) bool {
	allowed = strings.TrimSpace(strings.ToLower(allowed))
	host = strings.TrimSpace(strings.ToLower(host))
	if allowed == "" || host == "" {
		return false
	}
	if strings.HasPrefix(allowed, "*.") {
		suffix := allowed[1:]
		return strings.HasSuffix(host, suffix)
	}
	allowedHost := allowed
	if idx := strings.LastIndex(allowed, ":"); idx >= 0 {
		allowedHost = allowed[:idx]
	}
	return host == allowedHost || host == allowed
}
