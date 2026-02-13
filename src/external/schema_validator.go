package external

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

type SchemaField struct {
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
}

type SchemaError struct {
	Field    string `json:"field"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

func ValidateAndFilterClaims(schemaJSON string, payload map[string]any) (map[string]any, []SchemaError, error) {
	if strings.TrimSpace(schemaJSON) == "" {
		return payload, nil, nil
	}

	schema, err := parseSchema(schemaJSON)
	if err != nil {
		return nil, nil, err
	}

	filtered := make(map[string]any)
	var errorsList []SchemaError
	for fieldName, fieldSchema := range schema {
		value, ok := payload[fieldName]
		if !ok {
			continue
		}
		matches, actualType := matchesType(fieldSchema.Type, value)
		if !matches {
			errorsList = append(errorsList, SchemaError{
				Field:    fieldName,
				Expected: strings.ToLower(strings.TrimSpace(fieldSchema.Type)),
				Actual:   actualType,
			})
			continue
		}
		filtered[fieldName] = value
	}

	return filtered, errorsList, nil
}

func parseSchema(schemaJSON string) (map[string]SchemaField, error) {
	var wrapped struct {
		Schema map[string]SchemaField `json:"schema"`
	}
	if err := json.Unmarshal([]byte(schemaJSON), &wrapped); err == nil && len(wrapped.Schema) > 0 {
		return wrapped.Schema, nil
	}

	var direct map[string]SchemaField
	if err := json.Unmarshal([]byte(schemaJSON), &direct); err != nil {
		return nil, err
	}
	if len(direct) == 0 {
		return nil, fmt.Errorf("schema is empty")
	}
	return direct, nil
}

func matchesType(expectedType string, value any) (bool, string) {
	expectedType = strings.ToLower(strings.TrimSpace(expectedType))
	if expectedType == "" {
		return true, actualTypeName(value)
	}

	kind, isInteger := detectType(value)
	switch expectedType {
	case "string":
		return kind == "string", kind
	case "boolean":
		return kind == "boolean", kind
	case "number":
		return kind == "number", kind
	case "integer":
		return kind == "number" && isInteger, actualNumberType(kind, isInteger)
	case "object":
		return kind == "object", kind
	case "array":
		return kind == "array", kind
	default:
		return false, kind
	}
}

func detectType(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return "string", false
	case bool:
		return "boolean", false
	case json.Number:
		return numberKindFromString(v.String())
	case float64:
		return "number", math.Mod(v, 1) == 0
	case float32:
		return "number", math.Mod(float64(v), 1) == 0
	case int, int8, int16, int32, int64:
		return "number", true
	case uint, uint8, uint16, uint32, uint64:
		return "number", true
	case map[string]any:
		return "object", false
	case []any:
		return "array", false
	default:
		return "unknown", false
	}
}

func numberKindFromString(value string) (string, bool) {
	if strings.Contains(value, ".") {
		return "number", false
	}
	return "number", true
}

func actualNumberType(kind string, isInteger bool) string {
	if kind == "number" && isInteger {
		return "integer"
	}
	return kind
}

func actualTypeName(value any) string {
	kind, isInteger := detectType(value)
	return actualNumberType(kind, isInteger)
}
