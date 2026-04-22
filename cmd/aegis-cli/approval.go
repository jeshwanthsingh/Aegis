package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"aegis/internal/approval"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
)

const defaultApprovalTTL = 5 * time.Minute

var (
	approvalNow                  = func() time.Time { return time.Now().UTC() }
	approvalRandReader io.Reader = rand.Reader
)

type repeatedValues []string

func (r *repeatedValues) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatedValues) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func approvalCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: aegis approval <issue|inspect|public-keys>")
		return 2
	}
	switch args[0] {
	case "issue":
		return approvalIssueCmd(stdout, stderr, args[1:])
	case "inspect":
		return approvalInspect(stdout, stderr, args[1:])
	case "public-keys":
		return approvalPublicKeys(stdout, stderr, args[1:])
	default:
		fmt.Fprintln(stderr, "usage: aegis approval <issue|inspect|public-keys>")
		return 2
	}
}

func approvalIssueCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: aegis approval issue <http|host-repo-apply-patch>")
		return 2
	}
	switch args[0] {
	case "http":
		return approvalIssueHTTP(stdout, stderr, args[1:])
	case "host-repo-apply-patch":
		return approvalIssueHostRepoApplyPatch(stdout, stderr, args[1:])
	default:
		fmt.Fprintln(stderr, "usage: aegis approval issue <http|host-repo-apply-patch>")
		return 2
	}
}

func approvalIssueHTTP(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("approval issue http", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	executionID := fs.String("execution-id", "", "execution id")
	policyDigest := fs.String("policy-digest", "", "frozen policy digest")
	method := fs.String("method", "", "http method")
	rawURL := fs.String("url", "", "absolute url")
	ttlRaw := fs.String("ttl", defaultApprovalTTL.String(), "ticket ttl")
	body := fs.String("body", "", "literal request body")
	bodyFile := fs.String("body-file", "", "path to a request body file")
	outPath := fs.String("out", "", "path to write the full signed ticket json")
	var headerInputs repeatedValues
	fs.Var(&headerInputs, "header", "request header in 'Name: Value' form; repeat for multiple headers")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--execution-id", *executionID); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--policy-digest", *policyDigest); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--method", *method); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--url", *rawURL); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	headers, err := parseHeaderInputs(headerInputs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	bodyBytes, err := resolveLiteralOrFileBody(*body, *bodyFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ttl, err := parseApprovalTTL(*ttlRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	issuer, err := approval.NewLocalIssuerFromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	canonical, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method:  *method,
		URL:     *rawURL,
		Headers: headers,
		Body:    bodyBytes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "canonicalize http approval resource: %v\n", err)
		return 1
	}
	signed, err := issueApprovalTicket(issuer, *executionID, *policyDigest, governance.ActionHTTPRequest, canonical.Resource, ttl)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := maybeWriteTicket(*outPath, signed); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	token, err := approval.EncodeTicketHeaderValue(signed)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printIssuedApproval(stdout, issuedApprovalSummary{
		Ticket:             signed,
		IssuerKeyID:        issuer.KeyID,
		ResourceDigest:     canonical.ResourceDigest,
		ResourceDigestAlgo: canonical.ResourceDigestAlgo,
		Token:              token,
		OutPath:            strings.TrimSpace(*outPath),
	})
	return 0
}

func approvalIssueHostRepoApplyPatch(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("approval issue host-repo-apply-patch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	executionID := fs.String("execution-id", "", "execution id")
	policyDigest := fs.String("policy-digest", "", "frozen policy digest")
	repoLabel := fs.String("repo-label", "", "configured repo label")
	patchFile := fs.String("patch-file", "", "path to a unified diff patch file")
	baseRevision := fs.String("base-revision", "", "expected base revision")
	ttlRaw := fs.String("ttl", defaultApprovalTTL.String(), "ticket ttl")
	outPath := fs.String("out", "", "path to write the full signed ticket json")
	var targetScope repeatedValues
	fs.Var(&targetScope, "target-scope", "relative target-scope entry; repeat for multiple entries")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--execution-id", *executionID); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--policy-digest", *policyDigest); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--repo-label", *repoLabel); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--patch-file", *patchFile); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireStringFlag("--base-revision", *baseRevision); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ttl, err := parseApprovalTTL(*ttlRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	patchBytes, err := os.ReadFile(strings.TrimSpace(*patchFile))
	if err != nil {
		fmt.Fprintln(stderr, sanitizePathError("read patch file", err))
		return 1
	}
	issuer, err := approval.NewLocalIssuerFromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	canonical, err := hostaction.CanonicalizeRequest(hostaction.Request{
		Class: hostaction.ClassRepoApplyPatchV1,
		RepoApplyPatch: &hostaction.RepoApplyPatchRequest{
			RepoLabel:    *repoLabel,
			PatchBase64:  base64.StdEncoding.EncodeToString(patchBytes),
			TargetScope:  append([]string(nil), targetScope...),
			BaseRevision: *baseRevision,
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "canonicalize host repo apply patch approval resource: %v\n", err)
		return 1
	}
	signed, err := issueApprovalTicket(issuer, *executionID, *policyDigest, governance.ActionHostRepoApply, canonical.Resource, ttl)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := maybeWriteTicket(*outPath, signed); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	token, err := approval.EncodeTicketHeaderValue(signed)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printIssuedApproval(stdout, issuedApprovalSummary{
		Ticket:             signed,
		IssuerKeyID:        issuer.KeyID,
		ResourceDigest:     canonical.ResourceDigest,
		ResourceDigestAlgo: canonical.ResourceDigestAlgo,
		Token:              token,
		OutPath:            strings.TrimSpace(*outPath),
	})
	return 0
}

func approvalInspect(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("approval inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("file", "", "path to a signed approval ticket json file")
	token := fs.String("token", "", "encoded approval ticket token")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	signed, err := loadSignedApprovalTicket(*filePath, *token)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	resolver, err := approvalInspectResolverFromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	verified, err := approval.NewVerifier(resolver).Inspect(context.Background(), signed)
	if err != nil {
		fmt.Fprintf(stderr, "approval inspect failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "verification=verified")
	fmt.Fprintf(stdout, "ticket_id=%s\n", verified.Ticket.TicketID)
	fmt.Fprintf(stdout, "execution_id=%s\n", verified.Ticket.ExecutionID)
	fmt.Fprintf(stdout, "policy_digest=%s\n", verified.Ticket.PolicyDigest)
	fmt.Fprintf(stdout, "action_type=%s\n", verified.Ticket.ActionType)
	fmt.Fprintf(stdout, "resource=%s\n", approval.CanonicalRequestDescription(verified.Ticket.Resource))
	fmt.Fprintf(stdout, "resource_digest=%s:%s\n", verified.ResourceDigestAlgo, verified.ResourceDigest)
	fmt.Fprintf(stdout, "expires_at=%s\n", verified.Ticket.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "issuer_key_id=%s\n", verified.IssuerKeyID)
	return 0
}

func approvalPublicKeys(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("approval public-keys", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	issuer, err := approval.NewLocalIssuerFromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	rawJSON, err := json.Marshal(map[string]string{
		issuer.KeyID: base64.StdEncoding.EncodeToString(issuer.PublicKey),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "status=derived")
	fmt.Fprintf(stdout, "issuer_key_id=%s\n", issuer.KeyID)
	fmt.Fprintf(stdout, "public_keys_json=%s\n", string(rawJSON))
	return 0
}

type issuedApprovalSummary struct {
	Ticket             approval.SignedTicket
	IssuerKeyID        string
	ResourceDigest     string
	ResourceDigestAlgo string
	Token              string
	OutPath            string
}

func printIssuedApproval(stdout io.Writer, summary issuedApprovalSummary) {
	predicate := summary.Ticket.Statement.Predicate
	fmt.Fprintln(stdout, "status=issued")
	fmt.Fprintf(stdout, "ticket_id=%s\n", predicate.TicketID)
	fmt.Fprintf(stdout, "execution_id=%s\n", predicate.ExecutionID)
	fmt.Fprintf(stdout, "policy_digest=%s\n", predicate.PolicyDigest)
	fmt.Fprintf(stdout, "action_type=%s\n", predicate.ActionType)
	fmt.Fprintf(stdout, "resource=%s\n", approval.CanonicalRequestDescription(predicate.Resource))
	fmt.Fprintf(stdout, "resource_digest=%s:%s\n", summary.ResourceDigestAlgo, summary.ResourceDigest)
	fmt.Fprintf(stdout, "expires_at=%s\n", predicate.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "issuer_key_id=%s\n", summary.IssuerKeyID)
	fmt.Fprintf(stdout, "approval_header_name=%s\n", approval.ApprovalTicketHeader)
	fmt.Fprintf(stdout, "approval_ticket_token=%s\n", summary.Token)
	if summary.OutPath != "" {
		fmt.Fprintf(stdout, "ticket_file=%s\n", summary.OutPath)
	}
}

func issueApprovalTicket(issuer *approval.LocalIssuer, executionID string, policyDigest string, actionType string, resource approval.Resource, ttl time.Duration) (approval.SignedTicket, error) {
	issuedAt := approvalNow().UTC()
	ticketID, err := randomHexToken("ticket")
	if err != nil {
		return approval.SignedTicket{}, err
	}
	nonce, err := randomHexToken("nonce")
	if err != nil {
		return approval.SignedTicket{}, err
	}
	return issuer.Issue(context.Background(), approval.Ticket{
		Version:      approval.TicketVersion,
		TicketID:     ticketID,
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(ttl),
		Nonce:        nonce,
		ExecutionID:  strings.TrimSpace(executionID),
		PolicyDigest: strings.TrimSpace(policyDigest),
		ActionType:   strings.TrimSpace(actionType),
		Resource:     resource,
	})
}

func randomHexToken(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(approvalRandReader, buf); err != nil {
		return "", fmt.Errorf("generate %s: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

func parseApprovalTTL(raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("ttl is required")
	}
	ttl, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("ttl must be a positive duration")
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("ttl must be a positive duration")
	}
	return ttl, nil
}

func requireStringFlag(name string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func parseHeaderInputs(values []string) (map[string][]string, error) {
	headers := make(map[string][]string, len(values))
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("headers must use 'Name: Value'")
		}
		headers[strings.TrimSpace(name)] = append(headers[strings.TrimSpace(name)], strings.TrimSpace(value))
	}
	return headers, nil
}

func resolveLiteralOrFileBody(literal string, filePath string) ([]byte, error) {
	if literal != "" && strings.TrimSpace(filePath) != "" {
		return nil, fmt.Errorf("--body and --body-file cannot be combined")
	}
	if strings.TrimSpace(filePath) == "" {
		return []byte(literal), nil
	}
	body, err := os.ReadFile(strings.TrimSpace(filePath))
	if err != nil {
		return nil, sanitizePathError("read body file", err)
	}
	return body, nil
}

func maybeWriteTicket(path string, ticket approval.SignedTicket) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(ticket, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signed approval ticket: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return sanitizePathError("write ticket file", err)
	}
	return nil
}

func loadSignedApprovalTicket(filePath string, token string) (approval.SignedTicket, error) {
	filePath = strings.TrimSpace(filePath)
	token = strings.TrimSpace(token)
	if (filePath == "" && token == "") || (filePath != "" && token != "") {
		return approval.SignedTicket{}, fmt.Errorf("exactly one of --file or --token is required")
	}
	if token != "" {
		decoded, err := approval.DecodeTicketHeaderValue(token)
		if err != nil {
			return approval.SignedTicket{}, fmt.Errorf("decode approval ticket token: %w", err)
		}
		if decoded == nil {
			return approval.SignedTicket{}, fmt.Errorf("decode approval ticket token: token is empty")
		}
		return *decoded, nil
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return approval.SignedTicket{}, sanitizePathError("read ticket file", err)
	}
	var ticket approval.SignedTicket
	if err := json.Unmarshal(raw, &ticket); err != nil {
		return approval.SignedTicket{}, fmt.Errorf("decode ticket file: %w", err)
	}
	return ticket, nil
}

func approvalInspectResolverFromEnv() (approval.KeyResolver, error) {
	return approval.NewEnvInspectKeyResolver()
}

func sanitizePathError(prefix string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %v", prefix, pathErr.Err)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
