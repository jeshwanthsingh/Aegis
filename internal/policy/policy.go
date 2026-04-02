package policy

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

var NetworkPresets = map[string][]string{
	"pypi": {
		"pypi.org",
		"files.pythonhosted.org",
		"pypi.python.org",
	},
	"npm": {
		"registry.npmjs.org",
		"npmjs.com",
	},
	"huggingface": {
		"huggingface.co",
		"cdn-lfs.huggingface.co",
	},
	"docker": {
		"registry-1.docker.io",
		"auth.docker.io",
		"production.cloudflare.docker.com",
	},
}

type Policy struct {
	AllowedLanguages []string                  `yaml:"allowed_languages"`
	MaxCodeBytes     int                       `yaml:"max_code_bytes"`
	MaxOutputBytes   int                       `yaml:"max_output_bytes"`
	DefaultTimeoutMs int                       `yaml:"default_timeout_ms"`
	MaxTimeoutMs     int                       `yaml:"max_timeout_ms"`
	Profiles         map[string]ComputeProfile `yaml:"profiles"`
	DefaultProfile   string                    `yaml:"default_profile"`
	Network          NetworkPolicy             `yaml:"network"`
	Resources        ResourcePolicy            `yaml:"resources"`
}

type ComputeProfile struct {
	VCPUCount int `yaml:"vcpu_count"`
	MemoryMB  int `yaml:"memory_mb"`
}

type NetworkPolicy struct {
	Mode    string   `yaml:"mode"`
	Presets []string `yaml:"presets"`
}

type ResourcePolicy struct {
	MemoryMaxMB int `yaml:"memory_max_mb"`
	CPUPercent  int `yaml:"cpu_percent"`
	PidsMax     int `yaml:"pids_max"`
	TimeoutMs   int `yaml:"timeout_ms"`
}

func Default() *Policy {
	return &Policy{
		AllowedLanguages: []string{"python", "bash", "node"},
		MaxCodeBytes:     65536,
		MaxOutputBytes:   65536,
		DefaultTimeoutMs: 5000,
		MaxTimeoutMs:     10000,
		Profiles: map[string]ComputeProfile{
			"nano": {
				VCPUCount: 1,
				MemoryMB:  128,
			},
			"standard": {
				VCPUCount: 2,
				MemoryMB:  512,
			},
			"crunch": {
				VCPUCount: 4,
				MemoryMB:  2048,
			},
		},
		DefaultProfile: "nano",
		Network: NetworkPolicy{
			Mode:    "none",
			Presets: []string{},
		},
		Resources: ResourcePolicy{
			MemoryMaxMB: 128,
			CPUPercent:  50,
			PidsMax:     100,
			TimeoutMs:   5000,
		},
	}
}

func Load(path string) (*Policy, error) {
	if path == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	p := Default()
	if err := yaml.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}
	return p, nil
}

func (p *Policy) Validate(lang string, codeLen int, timeoutMs int) error {
	if !slices.Contains(p.AllowedLanguages, lang) {
		return fmt.Errorf("language not allowed: %s", lang)
	}
	if codeLen > p.MaxCodeBytes {
		return fmt.Errorf("code exceeds %d bytes", p.MaxCodeBytes)
	}
	if timeoutMs < 0 {
		return fmt.Errorf("timeout_ms must be greater than 0")
	}
	if timeoutMs > p.MaxTimeoutMs {
		return fmt.Errorf("timeout_ms exceeds maximum of %d", p.MaxTimeoutMs)
	}
	switch p.Network.Mode {
	case "", "none", "isolated", "allowlist":
	default:
		return fmt.Errorf("network.mode not allowed: %s", p.Network.Mode)
	}
	for _, preset := range p.Network.Presets {
		if _, ok := NetworkPresets[preset]; !ok {
			return fmt.Errorf("network preset not allowed: %s", preset)
		}
	}
	return nil
}
