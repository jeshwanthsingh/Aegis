package pool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"

	"aegis/internal/policy"
)

const (
	FallbackPoolDisabled = "pool_disabled"
	FallbackWorkspace    = "workspace_attached"
	FallbackProfile      = "profile_not_warmable"
	FallbackShapeMissing = "shape_unconfigured"
	FallbackPoolEmpty    = "pool_empty"
	FallbackClaimError   = "claim_error"
	FallbackStaleEntry   = "stale_entry"
	WarmShapeStandard    = "standard"
	WarmShapeNano        = "nano"
)

type ShapeConfig struct {
	Key         string
	Label       string
	Size        int
	AssetsDir   string
	RootfsPath  string
	Policy      *policy.Policy
	Profile     policy.ComputeProfile
	ProfileName string
}

func SupportedWarmProfile(profile string) bool {
	switch strings.TrimSpace(profile) {
	case WarmShapeStandard, WarmShapeNano:
		return true
	default:
		return false
	}
}

func ShapeKey(profileName, assetsDir, rootfsPath string, pol *policy.Policy) string {
	normalizedProfile := strings.TrimSpace(profileName)
	if normalizedProfile == "" {
		normalizedProfile = "unknown"
	}
	normalizedAssets := normalizeShapePath(assetsDir)
	normalizedRootfs := normalizeShapePath(rootfsPath)
	return normalizedProfile + "|" + normalizedAssets + "|" + normalizedRootfs + "|" + bootPolicyDigest(pol)
}

func DefaultShapes(totalSize int, assetsDir, rootfsPath string, pol *policy.Policy) []ShapeConfig {
	if totalSize <= 0 || pol == nil {
		return nil
	}
	orderedProfiles := []string{WarmShapeStandard, WarmShapeNano}
	var shapes []ShapeConfig
	for _, profileName := range orderedProfiles {
		profile, ok := pol.Profiles[profileName]
		if !ok {
			continue
		}
		shapes = append(shapes, ShapeConfig{
			Key:         ShapeKey(profileName, assetsDir, rootfsPath, pol),
			Label:       profileName,
			Size:        0,
			AssetsDir:   assetsDir,
			RootfsPath:  rootfsPath,
			Policy:      pol,
			Profile:     profile,
			ProfileName: profileName,
		})
	}
	remaining := totalSize
	for i := range shapes {
		if remaining == 0 {
			break
		}
		shapes[i].Size++
		remaining--
	}
	for remaining > 0 && len(shapes) > 0 {
		shapes[0].Size++
		remaining--
	}
	kept := shapes[:0]
	for _, shape := range shapes {
		if shape.Size > 0 {
			kept = append(kept, shape)
		}
	}
	return kept
}

func normalizeShapePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "<default>"
	}
	return filepath.Clean(path)
}

func bootPolicyDigest(pol *policy.Policy) string {
	if pol == nil {
		return "none"
	}
	payload, err := json.Marshal(struct {
		Network policy.NetworkPolicy `json:"network"`
	}{Network: pol.Network})
	if err != nil {
		return "invalid"
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:8])
}
