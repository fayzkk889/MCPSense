package checks

import (
	"encoding/json"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/models"
	"sort"
)

type metadataText struct {
	owner, field, text string
	instructions       bool
}

// Enumerate the metadata the peer supplies without invoking tools, reading
// resources, fetching prompt bodies or following schema references.
func metadataTexts(m *models.MCPManifest) ([]metadataText, error) {
	var out []metadataText
	budget := 0
	add := func(owner, field, text string, instructions bool) error {
		budget += len(text)
		if budget > 64<<20 || len(out) >= 100000 {
			return fmt.Errorf("metadata inspection budget exceeded")
		}
		if text != "" {
			out = append(out, metadataText{owner, field, text, instructions})
		}
		return nil
	}
	raw := func(owner, field string, data json.RawMessage) error {
		if len(data) == 0 {
			return nil
		}
		var root interface{}
		if err := json.Unmarshal(data, &root); err != nil {
			return fmt.Errorf("invalid metadata JSON in %s", field)
		}
		type item struct {
			value interface{}
			depth int
		}
		stack := []item{{root, 0}}
		for len(stack) > 0 {
			entry := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if entry.depth > 128 {
				return fmt.Errorf("metadata nesting exceeds inspection limit")
			}
			switch v := entry.value.(type) {
			case string:
				if err := add(owner, field, v, false); err != nil {
					return err
				}
			case []interface{}:
				for i := len(v) - 1; i >= 0; i-- {
					stack = append(stack, item{v[i], entry.depth + 1})
				}
			case map[string]interface{}:
				keys := make([]string, 0, len(v))
				for k := range v {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if err := add(owner, field+".key", k, false); err != nil {
						return err
					}
					stack = append(stack, item{v[k], entry.depth + 1})
				}
			}
		}
		return nil
	}
	for _, v := range []metadataText{{"server", "description", m.Description, false}, {"server", "instructions", m.Instructions, true}} {
		if err := add(v.owner, v.field, v.text, v.instructions); err != nil {
			return nil, err
		}
	}
	for _, t := range m.Tools {
		for _, v := range []metadataText{{t.Name, "name", t.Name, false}, {t.Name, "title", t.Title, false}, {t.Name, "description", t.Description, false}} {
			if err := add(v.owner, v.field, v.text, v.instructions); err != nil {
				return nil, err
			}
		}
		if err := raw(t.Name, "inputSchema", t.InputSchema); err != nil {
			return nil, err
		}
		if err := raw(t.Name, "outputSchema", t.OutputSchema); err != nil {
			return nil, err
		}
		if t.Annotations != nil {
			if err := add(t.Name, "annotation.title", t.Annotations.Title, false); err != nil {
				return nil, err
			}
		}
	}
	for _, r := range m.Resources {
		for _, v := range []metadataText{{"resource:" + r.Name, "name", r.Name, false}, {"resource:" + r.Name, "description", r.Description, false}, {"resource:" + r.Name, "uri", r.URI, false}} {
			if err := add(v.owner, v.field, v.text, false); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range m.Prompts {
		if err := add("prompt:"+p.Name, "description", p.Description, false); err != nil {
			return nil, err
		}
		if err := add("prompt:"+p.Name, "name", p.Name, false); err != nil {
			return nil, err
		}
		if err := raw("prompt:"+p.Name, "arguments", p.Arguments); err != nil {
			return nil, err
		}
	}
	return out, nil
}
