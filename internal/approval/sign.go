package approval

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
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	KeyID      string
}

func NewLocalIssuerFromSeed(seed []byte) (*LocalIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("approval signing seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &LocalIssuer{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		KeyID:      dsse.KeyIDFromPublicKey(publicKey),
	}, nil
}

func NewLocalIssuerFromEnv() (*LocalIssuer, error) {
	seedB64 := strings.TrimSpace(os.Getenv(EnvSigningSeed))
	if seedB64 == "" {
		return nil, fmt.Errorf("approval signing requires %s", EnvSigningSeed)
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode approval signing seed: %w", err)
	}
	return NewLocalIssuerFromSeed(seed)
}

func (i *LocalIssuer) Issue(_ context.Context, payload Ticket) (SignedTicket, error) {
	if i == nil {
		return SignedTicket{}, fmt.Errorf("approval issuer is not configured")
	}
	return SignTicket(payload, i.PrivateKey)
}

func SignTicket(payload Ticket, privateKey ed25519.PrivateKey) (SignedTicket, error) {
	statement := Statement{
		Type:          dsse.StatementType,
		Subject:       []dsse.StatementSubject{},
		PredicateType: TicketPredicateType,
		Predicate:     payload,
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return SignedTicket{}, fmt.Errorf("marshal approval ticket statement: %w", err)
	}
	envelope, err := dsse.SignEnvelope(dsse.PayloadType, statementBytes, privateKey)
	if err != nil {
		return SignedTicket{}, err
	}
	return SignedTicket{Envelope: envelope, Statement: statement}, nil
}
