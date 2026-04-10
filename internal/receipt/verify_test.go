package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestVerifySignedReceiptRejectsMalformedEnvelopeAndStatement(t *testing.T) {
	signer := mustDevSigner(t)
	base, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*SignedReceipt)
		wantErr string
	}{
		{
			name: "missing signatures",
			mutate: func(sr *SignedReceipt) {
				sr.Envelope.Signatures = nil
			},
			wantErr: "dsse envelope has no signatures",
		},
		{
			name: "bad payload base64",
			mutate: func(sr *SignedReceipt) {
				sr.Envelope.Payload = "%%%not-base64%%%"
			},
			wantErr: "decode dsse payload",
		},
		{
			name: "bad signature base64",
			mutate: func(sr *SignedReceipt) {
				sr.Envelope.Signatures[0].Sig = "%%%not-base64%%%"
			},
			wantErr: "decode dsse signature",
		},
		{
			name: "bad signature bytes",
			mutate: func(sr *SignedReceipt) {
				sr.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString([]byte("wrong"))
			},
			wantErr: "dsse signature verification failed",
		},
		{
			name: "bad statement json",
			mutate: func(sr *SignedReceipt) {
				reSignBytes(t, sr, signer, []byte("{"))
			},
			wantErr: "decode receipt statement",
		},
		{
			name: "bad statement type",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Type = "https://example.invalid/statement"
				reSignStatement(t, sr, signer)
			},
			wantErr: "unexpected statement type",
		},
		{
			name: "bad predicate type",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.PredicateType = "https://example.invalid/predicate"
				reSignStatement(t, sr, signer)
			},
			wantErr: "unexpected predicate type",
		},
		{
			name: "missing signer key id",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Predicate.SignerKeyID = ""
				reSignStatement(t, sr, signer)
			},
			wantErr: "statement signer key id is required",
		},
		{
			name: "mismatched signer key id",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Predicate.SignerKeyID = "ed25519:mismatch"
				reSignStatement(t, sr, signer)
			},
			wantErr: "statement signer key id does not match DSSE key id",
		},
		{
			name: "unexpected signing mode",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Predicate.Trust.SigningMode = "bad-mode"
				reSignStatement(t, sr, signer)
			},
			wantErr: "unexpected signing mode",
		},
		{
			name: "unexpected key source",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Predicate.Trust.KeySource = "bad-source"
				reSignStatement(t, sr, signer)
			},
			wantErr: "unexpected key source",
		},
		{
			name: "missing attestation",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Predicate.Trust.Attestation = ""
				reSignStatement(t, sr, signer)
			},
			wantErr: "statement trust attestation field is required",
		},
		{
			name: "missing subject name",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Subject = []StatementSubject{{Name: "", Digest: map[string]string{"sha256": "abc"}}}
				reSignStatement(t, sr, signer)
			},
			wantErr: "statement subject name is required",
		},
		{
			name: "missing subject digest",
			mutate: func(sr *SignedReceipt) {
				sr.Statement.Subject = []StatementSubject{{Name: "stdout.txt", Digest: map[string]string{}}}
				reSignStatement(t, sr, signer)
			},
			wantErr: "statement subject sha256 digest is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sr := base
			tc.mutate(&sr)
			_, err := VerifySignedReceipt(sr, signer.PublicKey)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVerifyReceiptFileRejectsBadPublicKeyAndReceiptFiles(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "ok\n", "warn\n", true)
	signedReceipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	paths, err := WriteProofBundle(t.TempDir(), input.ExecutionID, signedReceipt, signer.PublicKey, "ok\n", "warn\n", true)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}

	if _, err := VerifyReceiptFile(paths.ReceiptPath, paths.PublicKeyPath); err != nil {
		t.Fatalf("VerifyReceiptFile(valid): %v", err)
	}
	if _, err := LoadSignedReceiptFile(paths.ReceiptPath + ".missing"); err == nil {
		t.Fatal("expected missing receipt file error")
	}
	if _, err := LoadPublicKeyFile(paths.PublicKeyPath + ".missing"); err == nil {
		t.Fatal("expected missing public key file error")
	}
	if _, err := ParsePublicKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("expected invalid PEM error")
	}

	wrongSigner, err := NewSigner(
		SigningConfig{
			Mode:    SigningModeStrict,
			SeedB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.SeedSize)),
		},
	)
	if err != nil {
		t.Fatalf("NewSigner(strict): %v", err)
	}
	pubPEM, err := MarshalPublicKeyPEM(wrongSigner.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	if err := os.WriteFile(paths.PublicKeyPath, pubPEM, 0o644); err != nil {
		t.Fatalf("WriteFile(public key): %v", err)
	}
	if _, err := VerifyReceiptFile(paths.ReceiptPath, paths.PublicKeyPath); err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func reSignStatement(t *testing.T, sr *SignedReceipt, signer *Signer) {
	t.Helper()
	payload, err := json.Marshal(sr.Statement)
	if err != nil {
		t.Fatalf("json.Marshal(statement): %v", err)
	}
	reSignBytes(t, sr, signer, payload)
}

func reSignBytes(t *testing.T, sr *SignedReceipt, signer *Signer, payload []byte) {
	t.Helper()
	sr.Envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	sr.Envelope.Signatures = []Signature{{
		KeyID: signer.KeyID,
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(signer.PrivateKey, pae(sr.Envelope.PayloadType, payload))),
	}}
}
