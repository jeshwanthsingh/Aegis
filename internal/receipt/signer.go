package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"aegis/internal/dsse"
)

const (
	EnvSigningMode = "AEGIS_RECEIPT_SIGNING_MODE"
	EnvSigningSeed = "AEGIS_RECEIPT_SIGNING_SEED_B64"
)

type SigningMode string

type KeySource string

const (
	SigningModeDev    SigningMode = "dev"
	SigningModeStrict SigningMode = "strict"

	KeySourceConfiguredSeed KeySource = "configured_seed"
	// KeySourceDevFallback remains for verification of older proof bundles created
	// before the deterministic dev fallback signer was removed.
	KeySourceDevFallback KeySource = "dev_fallback"
)

type SigningConfig struct {
	Mode    SigningMode
	SeedB64 string
}

type Signer struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
	Mode       SigningMode
	KeySource  KeySource
}

func ParseSigningMode(raw string) (SigningMode, error) {
	mode := SigningMode(strings.ToLower(strings.TrimSpace(raw)))
	if mode == "" {
		return SigningModeStrict, nil
	}
	switch mode {
	case SigningModeDev, SigningModeStrict:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported receipt signing mode %q", raw)
	}
}

func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Signer{PrivateKey: privateKey, PublicKey: publicKey, KeyID: KeyIDFromPublicKey(publicKey)}, nil
}

func NewSigner(config SigningConfig) (*Signer, error) {
	mode, err := ParseSigningMode(string(config.Mode))
	if err != nil {
		return nil, err
	}
	seedB64 := strings.TrimSpace(config.SeedB64)
	if seedB64 != "" {
		seed, err := base64.StdEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, fmt.Errorf("decode receipt signing seed: %w", err)
		}
		signer, err := NewSignerFromSeed(seed)
		if err != nil {
			return nil, err
		}
		signer.Mode = mode
		signer.KeySource = KeySourceConfiguredSeed
		return signer, nil
	}
	return nil, missingSigningSeedError(mode)
}

func NewSignerFromEnv() (*Signer, error) {
	mode, err := ParseSigningMode(strings.TrimSpace(os.Getenv(EnvSigningMode)))
	if err != nil {
		return nil, err
	}
	return NewSigner(SigningConfig{Mode: mode, SeedB64: strings.TrimSpace(os.Getenv(EnvSigningSeed))})
}

func missingSigningSeedError(mode SigningMode) error {
	if mode == SigningModeDev {
		return fmt.Errorf("receipt signing mode %q is explicit non-production only and requires %s; deterministic fallback signing is disabled", mode, EnvSigningSeed)
	}
	return fmt.Errorf("receipt signing mode %q requires %s", mode, EnvSigningSeed)
}

func KeyIDFromPublicKey(publicKey ed25519.PublicKey) string {
	return dsse.KeyIDFromPublicKey(publicKey)
}
