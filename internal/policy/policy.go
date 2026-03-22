package policy

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	AllowedLanguages []string       `yaml:"allowed_languages"`
	MaxCodeBytes     int            `yaml:"max_code_bytes"`
	MaxOutputBytes   int            `yaml:"max_output_bytes"`
	DefaultTimeoutMs int            `yaml:"default_timeout_ms"`
	MaxTimeoutMs     int            `yaml:"max_timeout_ms"`
	Network          NetworkPolicy  `yaml:"network"`
	Resources        ResourcePolicy `yaml:"resources"`
}

type NetworkPolicy struct {
	Mode         string   `yaml:"mode"`
	AllowedHosts []string `yaml:"allowed_hosts"`
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
		Network: NetworkPolicy{
			Mode:         "deny-all",
			AllowedHosts: []string{},
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
	if timeoutMs > p.MaxTimeoutMs {
		return fmt.Errorf("timeout_ms exceeds maximum of %d", p.MaxTimeoutMs)
	}
	return nil
}
