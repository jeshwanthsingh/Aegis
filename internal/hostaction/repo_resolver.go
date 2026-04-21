package hostaction

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type StaticRepoResolver struct {
	repos map[string]RepoBinding
}

func NewStaticRepoResolver(bindings map[string]string) (*StaticRepoResolver, error) {
	repos := make(map[string]RepoBinding, len(bindings))
	for rawLabel, rawRoot := range bindings {
		label := strings.ToLower(strings.TrimSpace(rawLabel))
		root := filepath.Clean(strings.TrimSpace(rawRoot))
		if label == "" {
			return nil, fmt.Errorf("host repo label is required")
		}
		if root == "" {
			return nil, fmt.Errorf("host repo root is required for %s", label)
		}
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("host repo root for %s must be absolute", label)
		}
		repos[label] = RepoBinding{Label: label, Root: root}
	}
	return &StaticRepoResolver{repos: repos}, nil
}

func ParseRepoBindingsJSON(raw string) (*StaticRepoResolver, error) {
	if strings.TrimSpace(raw) == "" {
		return NewStaticRepoResolver(map[string]string{})
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("decode host repo bindings: %w", err)
	}
	return NewStaticRepoResolver(decoded)
}

func NewEnvRepoResolver() (*StaticRepoResolver, error) {
	return ParseRepoBindingsJSON(strings.TrimSpace(os.Getenv(EnvRepoRootsJSON)))
}

func (r *StaticRepoResolver) ResolveRepo(_ context.Context, label string) (RepoBinding, error) {
	if r == nil {
		return RepoBinding{}, errorf("broker.host_action_repo_root_mismatch", nil, "host repo resolver is not configured")
	}
	cleanLabel := strings.ToLower(strings.TrimSpace(label))
	if cleanLabel == "" {
		return RepoBinding{}, errorf("broker.host_action_repo_root_mismatch", nil, "repo label is required")
	}
	binding, ok := r.repos[cleanLabel]
	if !ok {
		return RepoBinding{}, errorf("broker.host_action_repo_root_mismatch", map[string]string{"repo_label": cleanLabel}, "host repo label %q is not configured", cleanLabel)
	}
	return binding, nil
}

func (r *StaticRepoResolver) Labels() []string {
	if r == nil || len(r.repos) == 0 {
		return []string{}
	}
	labels := make([]string, 0, len(r.repos))
	for label := range r.repos {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}
