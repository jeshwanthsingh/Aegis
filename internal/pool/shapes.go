package pool

import (
	"path/filepath"
	"strings"

	"aegis/internal/authority"
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
	Boot        authority.BootContext
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

func ShapeKey(profileName, assetsDir string, boot authority.BootContext) string {
	normalizedProfile := strings.TrimSpace(profileName)
	if normalizedProfile == "" {
		normalizedProfile = "unknown"
	}
	normalizedAssets := normalizeShapePath(assetsDir)
	return normalizedProfile + "|" + normalizedAssets + "|" + authority.BootDigest(boot)
}

func DefaultShapes(totalSize int, assetsDir, rootfsPath string, pol *policy.Policy) ([]ShapeConfig, error) {
	if totalSize <= 0 || pol == nil {
		return nil, nil
	}
	boot, err := authority.FreezeBoot(assetsDir, rootfsPath, false, pol.Network)
	if err != nil {
		return nil, err
	}
	orderedProfiles := []string{WarmShapeStandard, WarmShapeNano}
	var shapes []ShapeConfig
	for _, profileName := range orderedProfiles {
		profile, ok := pol.Profiles[profileName]
		if !ok {
			continue
		}
		shapes = append(shapes, ShapeConfig{
			Key:         ShapeKey(profileName, assetsDir, boot),
			Label:       profileName,
			Size:        0,
			AssetsDir:   assetsDir,
			Boot:        boot,
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
	return kept, nil
}

func normalizeShapePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "<default>"
	}
	return filepath.Clean(path)
}
