package lease

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"aegis/internal/dsse"
)

type LocalIssuer struct {
	IssuerName string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
}

func NewLocalIssuerFromSeed(seed []byte, issuer string) (*LocalIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("lease signing seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &LocalIssuer{
		IssuerName: strings.TrimSpace(issuer),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		KeyID:      dsse.KeyIDFromPublicKey(publicKey),
	}, nil
}

func NewLocalIssuerFromEnv() (*LocalIssuer, error) {
	seedB64 := strings.TrimSpace(os.Getenv(EnvSigningSeed))
	if seedB64 == "" {
		return nil, fmt.Errorf("lease signing requires %s", EnvSigningSeed)
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode lease signing seed: %w", err)
	}
	return NewLocalIssuerFromSeed(seed, IssuerNameFromEnv())
}

func (i *LocalIssuer) Issue(_ context.Context, payload Lease) (SignedLease, error) {
	if i == nil {
		return SignedLease{}, fmt.Errorf("lease issuer is not configured")
	}
	return SignLease(payload, i.PrivateKey)
}

func SignLease(payload Lease, privateKey ed25519.PrivateKey) (SignedLease, error) {
	statement := Statement{
		Type:          dsse.StatementType,
		Subject:       []dsse.StatementSubject{},
		PredicateType: PredicateType,
		Predicate:     payload,
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return SignedLease{}, fmt.Errorf("marshal lease statement: %w", err)
	}
	envelope, err := dsse.SignEnvelope(dsse.PayloadType, statementBytes, privateKey)
	if err != nil {
		return SignedLease{}, err
	}
	return SignedLease{Envelope: envelope, Statement: statement}, nil
}
