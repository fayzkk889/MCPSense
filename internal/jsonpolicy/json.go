// Package jsonpolicy rejects ambiguous JSON before decoding security inputs.
// Field names in JSON-RPC and MCP are case-sensitive. encoding/json otherwise
// accepts case/Unicode-folded aliases and lets later members overwrite earlier
// ones. Map keys (schema properties, extension names, environment names) remain
// case-sensitive and are not compared to each other using Unicode folding.
package jsonpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"
)

const maxDepth = 128
const maxTokens = 1_000_000

var rawType = reflect.TypeOf(json.RawMessage{})
var fieldCache sync.Map // reflect.Type -> map of exact JSON field names

// Validate checks a single JSON value against the field names of target before
// any values are assigned. Unknown extensions are allowed; aliases of known
// fields and duplicate members anywhere (including RawMessage) are rejected.
// Callers still enforce input byte limits and their own required-field schema.
func Validate(data []byte, target interface{}) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON contains invalid UTF-8")
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Ptr {
		return fmt.Errorf("JSON target must be a pointer")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	w := walker{decoder: d}
	if err := w.value(t.Elem(), 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON value")
	}
	return nil
}

// Unmarshal is encoding/json.Unmarshal preceded by the input policy. Validation
// errors leave the destination untouched and must fail scan coverage visibly.
func Unmarshal(data []byte, target interface{}) error {
	if err := Validate(data, target); err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

type walker struct {
	decoder *json.Decoder
	tokens  int
}

func (w *walker) token() (json.Token, error) {
	w.tokens++
	if w.tokens > maxTokens {
		return nil, fmt.Errorf("JSON token budget exceeded")
	}
	return w.decoder.Token()
}

func (w *walker) value(t reflect.Type, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("JSON nesting limit exceeded")
	}
	for t != nil && t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == rawType {
		t = nil // still check duplicate keys and budgets inside opaque schemas
	}
	tok, err := w.token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		var fields map[string]reflect.Type
		var element reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields, err = structFields(t)
			if err != nil {
				return err
			}
		} else if t != nil && t.Kind() == reflect.Map {
			element = t.Elem()
		}
		seen := map[string]bool{}
		for w.decoder.More() {
			tok, err := w.token()
			if err != nil {
				return err
			}
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("JSON object member must have a string name")
			}
			if seen[key] {
				return fmt.Errorf("ambiguous JSON: duplicate object member")
			}
			seen[key] = true
			next := element
			if fields != nil {
				var exact bool
				next, exact = fields[key]
				if !exact {
					for name := range fields {
						if strings.EqualFold(name, key) {
							return fmt.Errorf("ambiguous JSON: non-canonical field casing")
						}
					}
				}
			}
			if err := w.value(next, depth+1); err != nil {
				return err
			}
		}
		end, err := w.token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case json.Delim('['):
		var element reflect.Type
		if t != nil && (t.Kind() == reflect.Array || t.Kind() == reflect.Slice) {
			element = t.Elem()
		}
		for w.decoder.More() {
			if err := w.value(element, depth+1); err != nil {
				return err
			}
		}
		end, err := w.token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	case json.Delim('}'), json.Delim(']'):
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

// Security-boundary structs use explicit tags and no anonymous fields. Keep
// field discovery aligned with exported direct fields; maps stay open-ended.
func structFields(t reflect.Type) (map[string]reflect.Type, error) {
	if cached, ok := fieldCache.Load(t); ok {
		return cached.(map[string]reflect.Type), nil
	}
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if f.Anonymous && name == "" {
			return nil, fmt.Errorf("JSON policy requires explicitly tagged anonymous fields")
		}
		if f.PkgPath != "" {
			continue
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("JSON policy requires unique struct field tags")
		}
		fields[name] = f.Type
	}
	fieldCache.Store(t, fields)
	return fields, nil
}
