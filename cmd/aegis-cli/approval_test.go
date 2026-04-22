package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
)

func TestApprovalIssueHTTPProducesVerifierAcceptedTicket(t *testing.T) {
	setApprovalTestDeterminism(t)
	seed, seedB64, resolver, keyID := approvalTestMaterial(t)
	_ = seed
	bodyPath := filepath.Join(t.TempDir(), "body.txt")
	bodyValue := "super-secret-body"
	if err := os.WriteFile(bodyPath, []byte(bodyValue), 0o644); err != nil {
		t.Fatalf("WriteFile(body): %v", err)
	}
	ticketPath := filepath.Join(t.TempDir(), "http-ticket.json")
	t.Setenv(approval.EnvSigningSeed, seedB64)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{
		"approval", "issue", "http",
		"--execution-id", "exec-http",
		"--policy-digest", "policy-http",
		"--method", "POST",
		"--url", "https://api.example.com/v1/items?b=2&a=1",
		"--header", "X-Test: value",
		"--header", "Authorization: Bearer top-secret",
		"--body-file", bodyPath,
		"--out", ticketPath,
	})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), bodyValue) {
		t.Fatalf("stdout leaked raw body: %s", stdout.String())
	}
	for _, needle := range []string{"a=1", "b=2"} {
		if strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout leaked raw query data %q: %s", needle, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), seedB64) {
		t.Fatalf("stdout leaked signing seed: %s", stdout.String())
	}
	summary := parseSummaryLines(t, stdout.String())
	if summary["approval_header_name"] != approval.ApprovalTicketHeader {
		t.Fatalf("approval_header_name = %q", summary["approval_header_name"])
	}
	if got := summary["resource"]; !strings.HasPrefix(got, "POST https://api.example.com/v1/items?query_keys=2 headers=") || !strings.Contains(got, " body=") {
		t.Fatalf("resource = %q", got)
	}
	if summary["ticket_file"] != ticketPath {
		t.Fatalf("ticket_file = %q want %q", summary["ticket_file"], ticketPath)
	}
	token := summary["approval_ticket_token"]
	if token == "" {
		t.Fatalf("missing approval_ticket_token in stdout: %s", stdout.String())
	}
	ticket := decodeTicketToken(t, token)
	expected, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method: "POST",
		URL:    "https://api.example.com/v1/items?a=1&b=2",
		Headers: map[string][]string{
			"X-Test":        {"value"},
			"Authorization": {"Bearer top-secret"},
		},
		Body: []byte(bodyValue),
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	if !reflect.DeepEqual(ticket.Statement.Predicate.Resource, expected.Resource) {
		t.Fatalf("ticket resource mismatch:\n got: %#v\nwant: %#v", ticket.Statement.Predicate.Resource, expected.Resource)
	}
	verified, err := approval.NewVerifier(resolver).Verify(context.Background(), ticket, approval.VerificationRequest{
		ExecutionID:  "exec-http",
		PolicyDigest: "policy-http",
		ActionType:   governance.ActionHTTPRequest,
		Resource:     expected.Resource,
		Now:          testTime().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IssuerKeyID != keyID {
		t.Fatalf("IssuerKeyID = %q want %q", verified.IssuerKeyID, keyID)
	}
	var fromFile approval.SignedTicket
	raw, err := os.ReadFile(ticketPath)
	if err != nil {
		t.Fatalf("ReadFile(ticket): %v", err)
	}
	if err := json.Unmarshal(raw, &fromFile); err != nil {
		t.Fatalf("json.Unmarshal(ticket file): %v", err)
	}
	if !reflect.DeepEqual(fromFile, ticket) {
		t.Fatalf("file ticket mismatch token ticket")
	}
}

func TestApprovalIssueHostPatchProducesVerifierAcceptedTicket(t *testing.T) {
	setApprovalTestDeterminism(t)
	_, seedB64, resolver, keyID := approvalTestMaterial(t)
	patchPath := filepath.Join(t.TempDir(), "demo.patch")
	patchBody := strings.Join([]string{
		"diff --git a/README.md b/README.md",
		"--- a/README.md",
		"+++ b/README.md",
		"@@ -1 +1 @@",
		"-old",
		"+new",
		"",
	}, "\n")
	if err := os.WriteFile(patchPath, []byte(patchBody), 0o644); err != nil {
		t.Fatalf("WriteFile(patch): %v", err)
	}
	t.Setenv(approval.EnvSigningSeed, seedB64)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{
		"approval", "issue", "host-repo-apply-patch",
		"--execution-id", "exec-patch",
		"--policy-digest", "policy-patch",
		"--repo-label", "demo",
		"--patch-file", patchPath,
		"--base-revision", "abc123",
		"--target-scope", "README.md",
	})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), patchPath) {
		t.Fatalf("stdout leaked patch file path: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), seedB64) {
		t.Fatalf("stdout leaked signing seed: %s", stdout.String())
	}
	summary := parseSummaryLines(t, stdout.String())
	token := summary["approval_ticket_token"]
	if token == "" {
		t.Fatalf("missing approval_ticket_token in stdout: %s", stdout.String())
	}
	ticket := decodeTicketToken(t, token)
	expected, err := hostaction.CanonicalizeRequest(hostaction.Request{
		Class: hostaction.ClassRepoApplyPatchV1,
		RepoApplyPatch: &hostaction.RepoApplyPatchRequest{
			RepoLabel:    "demo",
			PatchBase64:  base64.StdEncoding.EncodeToString([]byte(patchBody)),
			TargetScope:  []string{"README.md"},
			BaseRevision: "abc123",
		},
	})
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	if !reflect.DeepEqual(ticket.Statement.Predicate.Resource, expected.Resource) {
		t.Fatalf("ticket resource mismatch:\n got: %#v\nwant: %#v", ticket.Statement.Predicate.Resource, expected.Resource)
	}
	verified, err := approval.NewVerifier(resolver).Verify(context.Background(), ticket, approval.VerificationRequest{
		ExecutionID:  "exec-patch",
		PolicyDigest: "policy-patch",
		ActionType:   governance.ActionHostRepoApply,
		Resource:     expected.Resource,
		Now:          testTime().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IssuerKeyID != keyID {
		t.Fatalf("IssuerKeyID = %q want %q", verified.IssuerKeyID, keyID)
	}
}

func TestApprovalInspectPrintsTruthfulSummary(t *testing.T) {
	setApprovalTestDeterminism(t)
	_, seedB64, _, _ := approvalTestMaterial(t)
	t.Setenv(approval.EnvSigningSeed, seedB64)
	ticketPath := filepath.Join(t.TempDir(), "inspect-ticket.json")
	token := issueHTTPToken(t, "https://api.example.com/v1/data?token=inspect-secret", nil, "", ticketPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"approval", "inspect", "--file", ticketPath})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, needle := range []string{
		"verification=verified",
		"ticket_id=",
		"execution_id=exec-http",
		"policy_digest=policy-http",
		"action_type=http_request",
		"resource=POST https://api.example.com/v1/data?query_keys=1",
		"issuer_key_id=",
	} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "inspect-secret") {
		t.Fatalf("stdout leaked raw query string: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "?token=") || strings.Contains(stdout.String(), "secret") {
		t.Fatalf("stdout leaked raw query data: %s", stdout.String())
	}
	var tokenStdout bytes.Buffer
	var tokenStderr bytes.Buffer
	code = runMain(&tokenStdout, &tokenStderr, []string{"approval", "inspect", "--token", token})
	if code != 0 {
		t.Fatalf("runMain(token) exit=%d stderr=%s stdout=%s", code, tokenStderr.String(), tokenStdout.String())
	}
}

func TestApprovalInspectRejectsMalformedTicket(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"approval", "inspect", "--token", "not-base64"})
	if code == 0 {
		t.Fatal("expected inspect failure")
	}
	if !strings.Contains(stderr.String(), "decode approval ticket token") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestApprovalIssueFailureModesAreClean(t *testing.T) {
	setApprovalTestDeterminism(t)
	_, seedB64, _, _ := approvalTestMaterial(t)

	t.Run("invalid ttl", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, seedB64)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "http",
			"--execution-id", "exec-http",
			"--policy-digest", "policy-http",
			"--method", "GET",
			"--url", "https://api.example.com/v1/data",
			"--ttl", "bad-ttl",
		})
		if code == 0 {
			t.Fatal("expected invalid ttl failure")
		}
		if !strings.Contains(stderr.String(), "ttl must be a positive duration") {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
	})

	t.Run("missing signer config", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, "")
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "http",
			"--execution-id", "exec-http",
			"--policy-digest", "policy-http",
			"--method", "GET",
			"--url", "https://api.example.com/v1/data",
		})
		if code == 0 {
			t.Fatal("expected missing signer config failure")
		}
		if !strings.Contains(stderr.String(), approval.EnvSigningSeed) {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, seedB64)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "http",
			"--execution-id", "exec-http",
			"--policy-digest", "policy-http",
			"--method", "GET",
			"--url", "https://api.example.com/v1/data",
			"--header", "badheader",
		})
		if code == 0 {
			t.Fatal("expected malformed header failure")
		}
		if !strings.Contains(stderr.String(), "headers must use 'Name: Value'") {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
	})

	t.Run("unreadable body file hides path", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, seedB64)
		missingBody := filepath.Join(t.TempDir(), "missing-body.txt")
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "http",
			"--execution-id", "exec-http",
			"--policy-digest", "policy-http",
			"--method", "GET",
			"--url", "https://api.example.com/v1/data",
			"--body-file", missingBody,
		})
		if code == 0 {
			t.Fatal("expected unreadable body file failure")
		}
		if !strings.Contains(stderr.String(), "read body file:") {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
		if strings.Contains(stderr.String(), missingBody) {
			t.Fatalf("stderr leaked body path: %s", stderr.String())
		}
	})

	t.Run("unreadable patch file hides path", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, seedB64)
		missingPatch := filepath.Join(t.TempDir(), "missing.patch")
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "host-repo-apply-patch",
			"--execution-id", "exec-patch",
			"--policy-digest", "policy-patch",
			"--repo-label", "demo",
			"--patch-file", missingPatch,
			"--base-revision", "abc123",
		})
		if code == 0 {
			t.Fatal("expected unreadable patch file failure")
		}
		if !strings.Contains(stderr.String(), "read patch file:") {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
		if strings.Contains(stderr.String(), missingPatch) {
			t.Fatalf("stderr leaked patch path: %s", stderr.String())
		}
	})

	t.Run("invalid patch content fails cleanly", func(t *testing.T) {
		t.Setenv(approval.EnvSigningSeed, seedB64)
		patchPath := filepath.Join(t.TempDir(), "bad.patch")
		if err := os.WriteFile(patchPath, []byte("not a patch"), 0o644); err != nil {
			t.Fatalf("WriteFile(patch): %v", err)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runMain(&stdout, &stderr, []string{
			"approval", "issue", "host-repo-apply-patch",
			"--execution-id", "exec-patch",
			"--policy-digest", "policy-patch",
			"--repo-label", "demo",
			"--patch-file", patchPath,
			"--base-revision", "abc123",
		})
		if code == 0 {
			t.Fatal("expected invalid patch failure")
		}
		if !strings.Contains(stderr.String(), "canonicalize host repo apply patch approval resource:") {
			t.Fatalf("unexpected stderr: %s", stderr.String())
		}
	})
}

func TestApprovalPublicKeysDerivesVerifierConfig(t *testing.T) {
	setApprovalTestDeterminism(t)
	_, seedB64, _, keyID := approvalTestMaterial(t)
	t.Setenv(approval.EnvSigningSeed, seedB64)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"approval", "public-keys"})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), seedB64) {
		t.Fatalf("stdout leaked signing seed: %s", stdout.String())
	}
	summary := parseSummaryLines(t, stdout.String())
	if got := summary["status"]; got != "derived" {
		t.Fatalf("status = %q", got)
	}
	if got := summary["issuer_key_id"]; got != keyID {
		t.Fatalf("issuer_key_id = %q want %q", got, keyID)
	}
	resolver, err := approval.ParsePublicKeysJSON(summary["public_keys_json"])
	if err != nil {
		t.Fatalf("ParsePublicKeysJSON: %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), keyID); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func issueHTTPToken(t *testing.T, rawURL string, headers []string, body string, outPath string) string {
	t.Helper()
	args := []string{
		"approval", "issue", "http",
		"--execution-id", "exec-http",
		"--policy-digest", "policy-http",
		"--method", "POST",
		"--url", rawURL,
	}
	for _, header := range headers {
		args = append(args, "--header", header)
	}
	if body != "" {
		args = append(args, "--body", body)
	}
	if strings.TrimSpace(outPath) != "" {
		args = append(args, "--out", outPath)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, args)
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	return parseSummaryLines(t, stdout.String())["approval_ticket_token"]
}

func parseSummaryLines(t *testing.T, raw string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("summary line missing '=': %q", line)
		}
		out[key] = value
	}
	return out
}

func decodeTicketToken(t *testing.T, token string) approval.SignedTicket {
	t.Helper()
	ticket, err := approval.DecodeTicketHeaderValue(token)
	if err != nil {
		t.Fatalf("DecodeTicketHeaderValue: %v", err)
	}
	if ticket == nil {
		t.Fatal("decoded ticket was nil")
	}
	return *ticket
}

func setApprovalTestDeterminism(t *testing.T) {
	t.Helper()
	oldNow := approvalNow
	oldRand := approvalRandReader
	approvalNow = testTime
	approvalRandReader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	t.Cleanup(func() {
		approvalNow = oldNow
		approvalRandReader = oldRand
	})
}

func approvalTestMaterial(t *testing.T) ([]byte, string, approval.KeyResolver, string) {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := dsse.KeyIDFromPublicKey(publicKey)
	return seed, seedB64, approval.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		keyID: publicKey,
	}), keyID
}
