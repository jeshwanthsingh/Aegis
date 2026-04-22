package approval

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	ApprovalTicketHeader = "X-Aegis-Approval-Ticket"
)

var requestHeaderDenylist = map[string]struct{}{
	"authorization":           {},
	"cookie":                  {},
	"proxy-authorization":     {},
	"set-cookie":              {},
	"x-aegis-approval-ticket": {},
	"x-aegis-governed-action": {},
	"x-amz-security-token":    {},
	"x-goog-auth":             {},
}

type canonicalHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type PublicHTTPURL struct {
	Scheme        string
	Host          string
	Path          string
	QueryPresent  bool
	QueryKeyCount int
}

func CanonicalizeHTTPRequest(input HTTPRequestInput) (CanonicalResource, error) {
	canonicalURL, err := canonicalizeURL(input.URL)
	if err != nil {
		return CanonicalResource{}, err
	}
	headers := sanitizeHeaders(input.Headers)
	headersDigest := digestJSON(canonicalHeaders(headers))
	bodyDigest := digestBytes(input.Body)
	resource, err := CanonicalizeResource(Resource{
		Kind: ResourceKindHTTPRequestV1,
		HTTP: &HTTPRequestResource{
			Method:            strings.ToUpper(strings.TrimSpace(input.Method)),
			URL:               canonicalURL,
			HeadersDigest:     headersDigest,
			HeadersDigestAlgo: ResourceDigestAlgo,
			BodyDigest:        bodyDigest,
			BodyDigestAlgo:    ResourceDigestAlgo,
		},
	})
	if err != nil {
		return CanonicalResource{}, err
	}
	resourceDigest, resourceDigestAlgo, err := DigestResource(resource)
	if err != nil {
		return CanonicalResource{}, err
	}
	return CanonicalResource{
		Resource:           resource,
		SanitizedHeaders:   headers,
		Body:               append([]byte(nil), input.Body...),
		ResourceDigest:     resourceDigest,
		ResourceDigestAlgo: resourceDigestAlgo,
	}, nil
}

func CanonicalizeResource(resource Resource) (Resource, error) {
	switch resource.Kind {
	case ResourceKindHTTPRequestV1:
		if resource.HTTP == nil {
			return Resource{}, fmt.Errorf("http resource payload is required")
		}
		canonicalURL, err := canonicalizeURL(resource.HTTP.URL)
		if err != nil {
			return Resource{}, err
		}
		headersDigest := strings.TrimSpace(strings.ToLower(resource.HTTP.HeadersDigest))
		headersDigestAlgo := strings.TrimSpace(strings.ToLower(resource.HTTP.HeadersDigestAlgo))
		bodyDigest := strings.TrimSpace(strings.ToLower(resource.HTTP.BodyDigest))
		bodyDigestAlgo := strings.TrimSpace(strings.ToLower(resource.HTTP.BodyDigestAlgo))
		if headersDigest == "" || bodyDigest == "" {
			return Resource{}, fmt.Errorf("http resource digests are required")
		}
		if headersDigestAlgo != ResourceDigestAlgo || bodyDigestAlgo != ResourceDigestAlgo {
			return Resource{}, fmt.Errorf("http resource digests must use %s", ResourceDigestAlgo)
		}
		return Resource{
			Kind: ResourceKindHTTPRequestV1,
			HTTP: &HTTPRequestResource{
				Method:            strings.ToUpper(strings.TrimSpace(resource.HTTP.Method)),
				URL:               canonicalURL,
				HeadersDigest:     headersDigest,
				HeadersDigestAlgo: headersDigestAlgo,
				BodyDigest:        bodyDigest,
				BodyDigestAlgo:    bodyDigestAlgo,
			},
		}, nil
	case ResourceKindHostRepoApplyPatchV1:
		if resource.HostRepoApplyPatch == nil {
			return Resource{}, fmt.Errorf("host_repo_apply_patch resource payload is required")
		}
		repoLabel := strings.ToLower(strings.TrimSpace(resource.HostRepoApplyPatch.RepoLabel))
		if repoLabel == "" {
			return Resource{}, fmt.Errorf("host_repo_apply_patch repo_label is required")
		}
		affectedPaths, err := canonicalStringList(resource.HostRepoApplyPatch.AffectedPaths)
		if err != nil {
			return Resource{}, err
		}
		if len(affectedPaths) == 0 {
			return Resource{}, fmt.Errorf("host_repo_apply_patch affected_paths are required")
		}
		targetScope, err := canonicalStringList(resource.HostRepoApplyPatch.TargetScope)
		if err != nil {
			return Resource{}, err
		}
		patchDigest := strings.TrimSpace(strings.ToLower(resource.HostRepoApplyPatch.PatchDigest))
		patchDigestAlgo := strings.TrimSpace(strings.ToLower(resource.HostRepoApplyPatch.PatchDigestAlgo))
		if patchDigest == "" {
			return Resource{}, fmt.Errorf("host_repo_apply_patch patch_digest is required")
		}
		if patchDigestAlgo != ResourceDigestAlgo {
			return Resource{}, fmt.Errorf("host_repo_apply_patch patch_digest must use %s", ResourceDigestAlgo)
		}
		baseRevision := strings.TrimSpace(resource.HostRepoApplyPatch.BaseRevision)
		if baseRevision == "" {
			return Resource{}, fmt.Errorf("host_repo_apply_patch base_revision is required")
		}
		return Resource{
			Kind: ResourceKindHostRepoApplyPatchV1,
			HostRepoApplyPatch: &HostRepoApplyPatchResource{
				RepoLabel:       repoLabel,
				TargetScope:     targetScope,
				AffectedPaths:   affectedPaths,
				PatchDigest:     patchDigest,
				PatchDigestAlgo: patchDigestAlgo,
				BaseRevision:    baseRevision,
			},
		}, nil
	default:
		return Resource{}, fmt.Errorf("unsupported approval resource kind %q", resource.Kind)
	}
}

func DigestResource(resource Resource) (string, string, error) {
	canonical, err := CanonicalizeResource(resource)
	if err != nil {
		return "", "", err
	}
	return digestJSON(canonical), ResourceDigestAlgo, nil
}

func EncodeTicketHeaderValue(ticket SignedTicket) (string, error) {
	raw, err := json.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("marshal approval ticket header: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeTicketHeaderValue(raw string) (*SignedTicket, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode approval ticket header: %w", err)
	}
	var ticket SignedTicket
	if err := json.Unmarshal(decoded, &ticket); err != nil {
		return nil, fmt.Errorf("decode approval ticket header payload: %w", err)
	}
	return &ticket, nil
}

func sanitizeHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return map[string][]string{}
	}
	sanitized := make(map[string][]string, len(headers))
	for key, values := range headers {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}
		if _, denied := requestHeaderDenylist[normalizedKey]; denied {
			continue
		}
		cleanValues := make([]string, 0, len(values))
		for _, value := range values {
			cleanValues = append(cleanValues, strings.TrimSpace(value))
		}
		sort.Strings(cleanValues)
		sanitized[normalizedKey] = cleanValues
	}
	if len(sanitized) == 0 {
		return map[string][]string{}
	}
	return sanitized
}

func canonicalHeaders(headers map[string][]string) []canonicalHeader {
	if len(headers) == 0 {
		return []canonicalHeader{}
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]canonicalHeader, 0, len(keys))
	for _, key := range keys {
		values := append([]string(nil), headers[key]...)
		sort.Strings(values)
		out = append(out, canonicalHeader{Name: key, Values: values})
	}
	return out
}

func canonicalizeURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("absolute url is required")
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	switch {
	case port == "":
		parsed.Host = host
	case defaultPort(parsed.Scheme, port):
		parsed.Host = host
	default:
		parsed.Host = host + ":" + port
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	query := parsed.Query()
	if len(query) == 0 {
		parsed.RawQuery = ""
	} else {
		keys := make([]string, 0, len(query))
		for key := range query {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make(url.Values, len(query))
		for _, key := range keys {
			items := append([]string(nil), query[key]...)
			sort.Strings(items)
			values[key] = items
		}
		parsed.RawQuery = values.Encode()
	}
	return parsed.String(), nil
}

func defaultPort(scheme string, port string) bool {
	switch {
	case scheme == "http" && port == "80":
		return true
	case scheme == "https" && port == "443":
		return true
	default:
		return false
	}
}

func PublicHTTPURLString(raw string) string {
	publicURL, err := PublicHTTPURLForDisplay(raw)
	if err != nil {
		return ""
	}
	value := publicURL.Scheme + "://" + publicURL.Host + publicURL.Path
	if publicURL.QueryPresent {
		value += "?query_keys=" + strconv.Itoa(publicURL.QueryKeyCount)
	}
	return value
}

func PublicHTTPURLForDisplay(raw string) (PublicHTTPURL, error) {
	canonicalURL, err := canonicalizeURL(raw)
	if err != nil {
		return PublicHTTPURL{}, err
	}
	parsed, err := url.Parse(canonicalURL)
	if err != nil {
		return PublicHTTPURL{}, fmt.Errorf("parse canonical url: %w", err)
	}
	query := parsed.Query()
	keyCount := 0
	for range query {
		keyCount++
	}
	pathValue := parsed.EscapedPath()
	if pathValue == "" {
		pathValue = "/"
	}
	return PublicHTTPURL{
		Scheme:        parsed.Scheme,
		Host:          parsed.Host,
		Path:          pathValue,
		QueryPresent:  keyCount > 0,
		QueryKeyCount: keyCount,
	}, nil
}

func digestJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("approval digest json: %v", err))
	}
	return digestBytes(raw)
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ResourceDigestSummary(resource Resource) string {
	digest, algo, err := DigestResource(resource)
	if err != nil {
		return ""
	}
	return algo + ":" + digest
}

func resourceAuditPayload(resource Resource) map[string]string {
	digest, algo, err := DigestResource(resource)
	if err != nil {
		return map[string]string{}
	}
	return map[string]string{
		"resource_kind":        string(resource.Kind),
		"resource_digest":      digest,
		"resource_digest_algo": algo,
	}
}

func ResourceToAuditPayload(resource Resource) map[string]string {
	payload := resourceAuditPayload(resource)
	switch resource.Kind {
	case ResourceKindHTTPRequestV1:
		if resource.HTTP != nil {
			payload["resource_method"] = resource.HTTP.Method
			publicURL, err := PublicHTTPURLForDisplay(resource.HTTP.URL)
			if err == nil {
				payload["resource_url_scheme"] = publicURL.Scheme
				payload["resource_url_host"] = publicURL.Host
				payload["resource_url_path"] = publicURL.Path
				if publicURL.QueryPresent {
					payload["resource_url_query_present"] = "true"
					payload["resource_url_query_key_count"] = strconv.Itoa(publicURL.QueryKeyCount)
				}
			}
		}
	case ResourceKindHostRepoApplyPatchV1:
		if resource.HostRepoApplyPatch != nil {
			payload["repo_label"] = resource.HostRepoApplyPatch.RepoLabel
			payload["patch_digest"] = resource.HostRepoApplyPatch.PatchDigest
			payload["base_revision"] = resource.HostRepoApplyPatch.BaseRevision
			payload["affected_path_count"] = strconv.Itoa(len(resource.HostRepoApplyPatch.AffectedPaths))
		}
	}
	return payload
}

func CanonicalRequestDescription(resource Resource) string {
	switch resource.Kind {
	case ResourceKindHTTPRequestV1:
		if resource.HTTP == nil {
			return string(resource.Kind)
		}
		return resource.HTTP.Method + " " + PublicHTTPURLString(resource.HTTP.URL) + " headers=" + resource.HTTP.HeadersDigest + " body=" + resource.HTTP.BodyDigest
	case ResourceKindHostRepoApplyPatchV1:
		if resource.HostRepoApplyPatch == nil {
			return string(resource.Kind)
		}
		return resource.HostRepoApplyPatch.RepoLabel + " patch=" + resource.HostRepoApplyPatch.PatchDigest + " base=" + resource.HostRepoApplyPatch.BaseRevision
	default:
		return string(resource.Kind)
	}
}

func ParseHeaderValueCount(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("count is required")
	}
	return strconv.Atoi(value)
}

func canonicalStringList(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	seen := map[string]struct{}{}
	canonical := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("list entries must not be empty")
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		canonical = append(canonical, value)
	}
	sort.Strings(canonical)
	return canonical, nil
}
