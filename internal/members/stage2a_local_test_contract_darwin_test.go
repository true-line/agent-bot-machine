//go:build darwin

package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Copied unchanged from soul-contracts v0.10.4, commit
// 99a597a9c372326e100ccf8d7a178afd4590586f. This test intentionally
// handles only the vocabulary in that exact schema and refuses new keywords.
const stage2aLocalTestSchemaSHA = "85afd9e3ead736470f1d811615a0f25de2ecdd37db3fe5a091a8cbabd4a1cef4"

func stage2aContractJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("extra contract JSON: %v", err)
	}
	return value, nil
}

func stage2aSchemaInt(value any) (int, error) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("schema number is %T", value)
	}
	return strconv.Atoi(string(n))
}

func stage2aValidatePinnedSchema(schema, value any, path string) error {
	if allowed, ok := schema.(bool); ok {
		if !allowed {
			return fmt.Errorf("%s: schema false", path)
		}
		return nil
	}
	rules, ok := schema.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: invalid schema", path)
	}
	for keyword := range rules {
		switch keyword {
		case "$id", "$schema", "description", "title", "additionalProperties", "properties", "required",
			"type", "const", "pattern", "minimum", "maximum", "minLength", "format",
			"items", "minItems", "maxItems", "prefixItems":
		default:
			return fmt.Errorf("%s: unhandled schema keyword %q", path, keyword)
		}
	}
	if expected, exists := rules["const"]; exists && !reflect.DeepEqual(value, expected) {
		return fmt.Errorf("%s: const mismatch", path)
	}
	if kind, exists := rules["type"]; exists {
		valid := false
		switch kind {
		case "object":
			_, valid = value.(map[string]any)
		case "array":
			_, valid = value.([]any)
		case "string":
			_, valid = value.(string)
		case "integer":
			if number, ok := value.(json.Number); ok {
				_, err := strconv.ParseInt(string(number), 10, 64)
				valid = err == nil
			}
		default:
			return fmt.Errorf("%s: unhandled schema type %v", path, kind)
		}
		if !valid {
			return fmt.Errorf("%s: type mismatch", path)
		}
	}
	if text, ok := value.(string); ok {
		if minimum, exists := rules["minLength"]; exists {
			length, err := stage2aSchemaInt(minimum)
			if err != nil || utf8.RuneCountInString(text) < length {
				return fmt.Errorf("%s: minLength", path)
			}
		}
		if pattern, exists := rules["pattern"]; exists {
			expression, ok := pattern.(string)
			if !ok {
				return fmt.Errorf("%s: invalid schema pattern", path)
			}
			compiled, err := regexp.Compile(expression)
			if err != nil || !compiled.MatchString(text) {
				return fmt.Errorf("%s: pattern", path)
			}
		}
	}
	if number, ok := value.(json.Number); ok {
		actual, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil {
			return fmt.Errorf("%s: invalid integer", path)
		}
		for keyword, within := range map[string]func(int64, int64) bool{
			"minimum": func(n, limit int64) bool { return n >= limit },
			"maximum": func(n, limit int64) bool { return n <= limit },
		} {
			if bound, exists := rules[keyword]; exists {
				limit, err := stage2aSchemaInt(bound)
				if err != nil || !within(actual, int64(limit)) {
					return fmt.Errorf("%s: %s", path, keyword)
				}
			}
		}
	}
	if object, ok := value.(map[string]any); ok {
		properties, _ := rules["properties"].(map[string]any)
		if required, exists := rules["required"]; exists {
			names, ok := required.([]any)
			if !ok {
				return fmt.Errorf("%s: invalid required list", path)
			}
			for _, name := range names {
				field, ok := name.(string)
				if !ok {
					return fmt.Errorf("%s: invalid required field", path)
				}
				if _, exists := object[field]; !exists {
					return fmt.Errorf("%s/%s: required", path, field)
				}
			}
		}
		for name, child := range object {
			childSchema, exists := properties[name]
			if !exists {
				if rules["additionalProperties"] == false {
					return fmt.Errorf("%s/%s: additional property", path, name)
				}
				continue
			}
			if err := stage2aValidatePinnedSchema(childSchema, child, path+"/"+name); err != nil {
				return err
			}
		}
	}
	if array, ok := value.([]any); ok {
		for keyword, within := range map[string]func(int, int) bool{
			"minItems": func(n, limit int) bool { return n >= limit },
			"maxItems": func(n, limit int) bool { return n <= limit },
		} {
			if bound, exists := rules[keyword]; exists {
				limit, err := stage2aSchemaInt(bound)
				if err != nil || !within(len(array), limit) {
					return fmt.Errorf("%s: %s", path, keyword)
				}
			}
		}
		prefix, _ := rules["prefixItems"].([]any)
		for index, child := range array {
			childSchema := rules["items"]
			if index < len(prefix) {
				childSchema = prefix[index]
			}
			if childSchema != nil {
				if err := stage2aValidatePinnedSchema(childSchema, child, fmt.Sprintf("%s/%d", path, index)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func TestStage2aLocalTestReservationMatchesReleasedContract(t *testing.T) {
	if stage2aLocalTestContractsTag != "v0.10.4" ||
		stage2aLocalTestContractsCommit != "99a597a9c372326e100ccf8d7a178afd4590586f" {
		t.Fatal("contract source changed without a schema gate refresh")
	}
	schemaRaw, err := os.ReadFile("testdata/stage2a-local-test-v0104-reservation.schema.json")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(schemaRaw)) != stage2aLocalTestSchemaSHA {
		t.Fatal("released local-test schema bytes changed", err)
	}
	schema, err := stage2aContractJSON(schemaRaw)
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := stage2aLoadContractVectorV3(t)
	var base stage2aReservationPayloadV3
	if err := stage2aDecodeExact([]byte(vector.ReservationPayloadJCS), &base); err != nil {
		t.Fatal(err)
	}
	base.Contract, base.Kind, base.SchemaVersion = "machine/local-test-v1", "stage2a-observed-body-local-test-reservation", 1
	base.Assignment.Schema = stage2aLocalTestAssignmentSchemaV1
	base.MeasurementBinding.Contract, base.MeasurementBinding.SchemaVersion = "machine/local-test-v1", 1
	payload, err := marshalStage2aReservationJCS(stage2aLocalTestReservationV1{base, stage2aLocalTestStartScopeV1{
		Mode: "provider-pending-local-test/v1", OneUseStartClaimName: soulStartClaimName(base.Assignment.InstallationID, base.Assignment.StartID),
	}})
	if err != nil {
		t.Fatal(err)
	}
	decodePayload := func() map[string]any {
		t.Helper()
		value, err := stage2aContractJSON(payload)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	if err := stage2aValidatePinnedSchema(schema, decodePayload(), ""); err != nil {
		t.Fatal("Machine reservation violates released contract:", err)
	}
	for _, mutant := range []struct {
		name, wantPath string
		change         func(map[string]any)
	}{
		{"stale R kind", "/measurement_binding/r_inventory/kind", func(p map[string]any) {
			p["measurement_binding"].(map[string]any)["r_inventory"].(map[string]any)["kind"] = "stage2a-domain-inventory"
		}},
		{"world-readable sidecar", "/measurement_binding/r_inventory/sidecar/mode", func(p map[string]any) {
			p["measurement_binding"].(map[string]any)["r_inventory"].(map[string]any)["sidecar"].(map[string]any)["mode"] = "0555"
		}},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			changed := decodePayload()
			mutant.change(changed)
			if err := stage2aValidatePinnedSchema(schema, changed, ""); err == nil || !strings.HasPrefix(err.Error(), mutant.wantPath+":") {
				t.Fatalf("released schema did not reject %s at %s: %v", mutant.name, mutant.wantPath, err)
			}
		})
	}
}
