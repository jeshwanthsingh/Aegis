package approval

import (
	"reflect"
	"testing"
)

func TestCanonicalizeHTTPRequestStable(t *testing.T) {
	first, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method: "post",
		URL:    "HTTPS://Example.com:443/v1/items?b=2&a=1",
		Headers: map[string][]string{
			"X-Test":                  {" two ", "one"},
			"Authorization":           {"Bearer secret"},
			"X-Aegis-Approval-Ticket": {"ignored"},
		},
		Body: []byte("payload"),
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest(first): %v", err)
	}
	second, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method: "POST",
		URL:    "https://example.com/v1/items?a=1&b=2",
		Headers: map[string][]string{
			"x-test": {"one", "two"},
		},
		Body: []byte("payload"),
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest(second): %v", err)
	}
	if !reflect.DeepEqual(first.Resource, second.Resource) {
		t.Fatalf("resource mismatch:\nfirst=%+v\nsecond=%+v", first.Resource, second.Resource)
	}
	if first.ResourceDigest != second.ResourceDigest {
		t.Fatalf("resource digest mismatch: %q vs %q", first.ResourceDigest, second.ResourceDigest)
	}
	if first.Resource.HTTP.URL != "https://example.com/v1/items?a=1&b=2" {
		t.Fatalf("canonical URL = %q", first.Resource.HTTP.URL)
	}
	if _, ok := first.SanitizedHeaders["authorization"]; ok {
		t.Fatalf("authorization header leaked into sanitized headers: %+v", first.SanitizedHeaders)
	}
}
