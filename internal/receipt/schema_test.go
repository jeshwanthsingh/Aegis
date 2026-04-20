package receipt

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	policycfg "aegis/internal/policy"
)

func TestReceiptPredicateMatchesSchema(t *testing.T) {
	schema := loadReceiptPredicateSchema(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	payload, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("Marshal predicate: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("Unmarshal predicate: %v", err)
	}
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("predicate does not match schema: %v\npayload=%s", err, string(payload))
	}
}

func TestReceiptPredicateMatchesSchemaWithDirectWebEgressMode(t *testing.T) {
	schema := loadReceiptPredicateSchema(t)
	input := testReceiptInput()
	input.Policy.Baseline.Network.Mode = policycfg.NetworkModeDirectWebEgress
	input.Runtime.Network.Mode = policycfg.NetworkModeDirectWebEgress

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	payload, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("Marshal predicate: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("Unmarshal predicate: %v", err)
	}
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("predicate does not match schema with direct_web_egress: %v\npayload=%s", err, string(payload))
	}
}

func TestLegacyDirectWebEgressFixturePredicateMatchesSchema(t *testing.T) {
	schema := loadReceiptPredicateSchema(t)
	signed, err := LoadSignedReceiptFile(filepath.Join("testdata", "legacy_direct_web_egress_receipt.json"))
	if err != nil {
		t.Fatalf("LoadSignedReceiptFile: %v", err)
	}
	payload, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("Marshal predicate: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("Unmarshal predicate: %v", err)
	}
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("legacy fixture predicate does not match schema: %v\npayload=%s", err, string(payload))
	}
}

func TestReceiptPredicateSchemaExcludesLegacyFields(t *testing.T) {
	schema := loadReceiptPredicateSchema(t)
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties missing or invalid: %#v", schema["properties"])
	}
	for _, field := range []string{
		"verdict",
		"violations",
		"broker_actions",
		"resource_summary",
		"network_summary",
		"cleanup_summary",
		"telemetry_summary",
		"host_attestation",
		"event_log_digest",
	} {
		if _, exists := properties[field]; exists {
			t.Fatalf("legacy field %q still present in schema properties", field)
		}
	}
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("schema required missing or invalid: %#v", schema["required"])
	}
	requiredSet := map[string]struct{}{}
	for _, raw := range required {
		name, ok := raw.(string)
		if !ok {
			t.Fatalf("required entry has non-string type: %#v", raw)
		}
		requiredSet[name] = struct{}{}
	}
	for _, field := range []string{
		"verdict",
		"violations",
		"broker_actions",
		"resource_summary",
		"network_summary",
		"cleanup_summary",
		"telemetry_summary",
		"host_attestation",
		"event_log_digest",
	} {
		if _, exists := requiredSet[field]; exists {
			t.Fatalf("legacy field %q still present in schema required list", field)
		}
	}
}

func loadReceiptPredicateSchema(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "schemas", "receipt-predicate-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal schema: %v", err)
	}
	return schema
}

func validateSchemaValue(value any, schema map[string]any, root map[string]any, path string) error {
	if ref, ok := schema["$ref"].(string); ok && ref != "" {
		resolved, err := resolveSchemaRef(root, ref)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return validateSchemaValue(value, resolved, root, path)
	}
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(value, constant) {
		return fmt.Errorf("%s: const mismatch got=%#v want=%#v", path, value, constant)
	}
	if enum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range enum {
			if reflect.DeepEqual(value, candidate) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: %#v not in enum %#v", path, value, enum)
		}
	}
	switch rawType := schema["type"].(type) {
	case string:
		if err := validateType(value, schema, root, path, rawType); err != nil {
			return err
		}
	case []any:
		var errs []string
		for _, candidate := range rawType {
			typeName, ok := candidate.(string)
			if !ok {
				return fmt.Errorf("%s: invalid schema type entry %T", path, candidate)
			}
			if typeName == "null" {
				if value == nil {
					return nil
				}
				errs = append(errs, fmt.Sprintf("expected null, got %T", value))
				continue
			}
			if err := validateType(value, schema, root, path, typeName); err == nil {
				return nil
			} else {
				errs = append(errs, err.Error())
			}
		}
		return fmt.Errorf("%s: value did not match any allowed schema type: %s", path, strings.Join(errs, "; "))
	}
	return nil
}

func validateType(value any, schema map[string]any, root map[string]any, path string, typeName string) error {
	switch typeName {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected object, got %T", path, value)
		}
		properties := map[string]any{}
		if rawProps, ok := schema["properties"].(map[string]any); ok {
			properties = rawProps
		}
		required := map[string]struct{}{}
		if rawRequired, ok := schema["required"].([]any); ok {
			for _, entry := range rawRequired {
				name, ok := entry.(string)
				if !ok {
					return fmt.Errorf("%s: required entry has invalid type %T", path, entry)
				}
				required[name] = struct{}{}
			}
		}
		for name := range required {
			if _, exists := object[name]; !exists {
				return fmt.Errorf("%s: missing required property %q", path, name)
			}
		}
		additionalAllowed := true
		var additionalSchema map[string]any
		switch raw := schema["additionalProperties"].(type) {
		case bool:
			additionalAllowed = raw
		case map[string]any:
			additionalSchema = raw
		}
		for key, item := range object {
			childPath := path + "." + key
			if propSchemaRaw, ok := properties[key]; ok {
				propSchema, ok := propSchemaRaw.(map[string]any)
				if !ok {
					return fmt.Errorf("%s: property schema for %q is invalid", path, key)
				}
				if err := validateSchemaValue(item, propSchema, root, childPath); err != nil {
					return err
				}
				continue
			}
			if additionalSchema != nil {
				if err := validateSchemaValue(item, additionalSchema, root, childPath); err != nil {
					return err
				}
				continue
			}
			if !additionalAllowed {
				return fmt.Errorf("%s: unexpected property %q", path, key)
			}
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s: expected array, got %T", path, value)
		}
		itemSchema, _ := schema["items"].(map[string]any)
		for idx, item := range items {
			if itemSchema == nil {
				continue
			}
			if err := validateSchemaValue(item, itemSchema, root, fmt.Sprintf("%s[%d]", path, idx)); err != nil {
				return err
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: expected string, got %T", path, value)
		}
		if min, ok := schema["minLength"].(float64); ok && len(text) < int(min) {
			return fmt.Errorf("%s: string shorter than minLength %d", path, int(min))
		}
		if pattern, ok := schema["pattern"].(string); ok && pattern != "" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("%s: invalid schema pattern %q: %w", path, pattern, err)
			}
			if !re.MatchString(text) {
				return fmt.Errorf("%s: %q does not match %q", path, text, pattern)
			}
		}
		if format, ok := schema["format"].(string); ok && format == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return fmt.Errorf("%s: invalid date-time %q: %w", path, text, err)
			}
		}
	case "integer":
		number, ok := value.(float64)
		if !ok {
			return fmt.Errorf("%s: expected integer, got %T", path, value)
		}
		if math.Trunc(number) != number {
			return fmt.Errorf("%s: expected integer, got %v", path, number)
		}
		if min, ok := schema["minimum"].(float64); ok && number < min {
			return fmt.Errorf("%s: integer %v below minimum %v", path, number, min)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: expected boolean, got %T", path, value)
		}
	default:
		return fmt.Errorf("%s: unsupported schema type %q", path, typeName)
	}
	return nil
}

func resolveSchemaRef(root map[string]any, ref string) (map[string]any, error) {
	if len(ref) == 0 || ref[0] != '#' {
		return nil, fmt.Errorf("unsupported schema ref %q", ref)
	}
	current := any(root)
	for _, part := range splitJSONPointer(ref[1:]) {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema ref %q traversed non-object", ref)
		}
		next, ok := object[part]
		if !ok {
			return nil, fmt.Errorf("schema ref %q missing %q", ref, part)
		}
		current = next
	}
	resolved, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema ref %q did not resolve to an object", ref)
	}
	return resolved, nil
}

func splitJSONPointer(pointer string) []string {
	if pointer == "" {
		return nil
	}
	rawParts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		if part == "" {
			continue
		}
		parts = append(parts, decodeJSONPointerPart(part))
	}
	return parts
}

func decodeJSONPointerPart(part string) string {
	return strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
}
