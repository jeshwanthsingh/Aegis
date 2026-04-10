package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func VerifySignedReceipt(receipt SignedReceipt, publicKey ed25519.PublicKey) (Statement, error) {
	if receipt.Envelope.PayloadType != PayloadType {
		return Statement{}, fmt.Errorf("unexpected payload type: %s", receipt.Envelope.PayloadType)
	}
	if len(receipt.Envelope.Signatures) == 0 {
		return Statement{}, fmt.Errorf("dsse envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(receipt.Envelope.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("decode dsse payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(receipt.Envelope.Signatures[0].Sig)
	if err != nil {
		return Statement{}, fmt.Errorf("decode dsse signature: %w", err)
	}
	if !ed25519.Verify(publicKey, pae(receipt.Envelope.PayloadType, payload), sig) {
		return Statement{}, fmt.Errorf("dsse signature verification failed")
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return Statement{}, fmt.Errorf("decode receipt statement: %w", err)
	}
	if statement.Type != StatementType {
		return Statement{}, fmt.Errorf("unexpected statement type: %s", statement.Type)
	}
	if statement.PredicateType != PredicateType {
		return Statement{}, fmt.Errorf("unexpected predicate type: %s", statement.PredicateType)
	}
	if statement.Predicate.SignerKeyID == "" {
		return Statement{}, fmt.Errorf("statement signer key id is required")
	}
	if statement.Predicate.SignerKeyID != receipt.Envelope.Signatures[0].KeyID {
		return Statement{}, fmt.Errorf("statement signer key id does not match DSSE key id")
	}
	if statement.Predicate.Trust.SigningMode != SigningModeDev && statement.Predicate.Trust.SigningMode != SigningModeStrict {
		return Statement{}, fmt.Errorf("unexpected signing mode: %s", statement.Predicate.Trust.SigningMode)
	}
	if statement.Predicate.Trust.KeySource != KeySourceConfiguredSeed && statement.Predicate.Trust.KeySource != KeySourceDevFallback {
		return Statement{}, fmt.Errorf("unexpected key source: %s", statement.Predicate.Trust.KeySource)
	}
	if statement.Predicate.Trust.Attestation == "" {
		return Statement{}, fmt.Errorf("statement trust attestation field is required")
	}
	for _, subject := range statement.Subject {
		if subject.Name == "" {
			return Statement{}, fmt.Errorf("statement subject name is required")
		}
		if subject.Digest == nil || subject.Digest["sha256"] == "" {
			return Statement{}, fmt.Errorf("statement subject sha256 digest is required")
		}
	}
	return statement, nil
}
