package jsonpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

type sample struct {
	Description string `json:"description"`
	Params      *struct {
		Token string `json:"token"`
	} `json:"params"`
	Tools []struct {
		Description string `json:"description"`
	} `json:"tools"`
	Entries map[string]struct {
		URL string `json:"url"`
	} `json:"entries"`
	Schema json.RawMessage `json:"schema"`
}

func TestAmbiguousSecurityInputsRejectedBeforeAssignment(t *testing.T) {
	for _, data := range []string{
		`{"description":"hostile","Description":"benign"}`,
		`{"Description":"benign"}`, `{"DESCRIPTION":"benign"}`,
		`{"deſcription":"benign"}`, `{"paramſ":{"token":"x"}}`,
		`{"params":{"toKen":"x"}}`,
		`{"tools":[{"description":"hostile","Description":"benign"}]}`,
		`{"entries":{"server":{"URL":"https://example.invalid"}}}`,
		`{"description":"one","description":"two"}`,
		`{"description":"one","de\u0073cription":"two"}`,
		`{"schema":{"properties":{"x":{},"x":{}}}}`,
		`{"extension":{"x":1,"x":2}}`,
		`{} {}`, `{"description":`, `{"description":1}`,
		"{\"description\":\"\xff\"}",
		strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2),
	} {
		t.Run(data[:min(len(data), 80)], func(t *testing.T) {
			got := sample{Description: "unchanged"}
			if err := Unmarshal([]byte(data), &got); err == nil {
				t.Fatalf("ambiguous/invalid input accepted: %s", data)
			}
			// Policy violations must not partially decode before detection.
			if err := Validate([]byte(data), &got); err != nil && got.Description != "unchanged" {
				t.Fatal("validation mutated its target")
			}
		})
	}
}

func TestCanonicalFieldsAndOpenMapKeysPreserved(t *testing.T) {
	data := `{"description":"original","params":{"token":"selected"},"tools":[{"description":"record"}],"entries":{"A":{"url":"one"},"a":{"url":"two"}},"schema":{"properties":{"X":{"description":"upper"},"x":{"description":"lower"},"token":{},"toKen":{}}},"vendor_extension":{"Description":"allowed","description":"also allowed"},"large":9007199254740993}`
	var got sample
	if err := Unmarshal([]byte(data), &got); err != nil {
		t.Fatal(err)
	}
	if got.Description != "original" || got.Params.Token != "selected" || got.Entries["A"].URL != "one" || got.Entries["a"].URL != "two" {
		t.Fatalf("canonical content changed: %+v", got)
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(got.Schema, &schema); err != nil || !strings.Contains(string(got.Schema), `"X"`) || !strings.Contains(string(got.Schema), `"x"`) {
		t.Fatal("schema keys lost")
	}
	for _, value := range []string{`null`, `[]`, `123`, `"text"`, `true`, `{"Method":1,"method":2}`} {
		var arbitrary interface{}
		if err := Unmarshal([]byte(value), &arbitrary); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBudgetAndTargetContract(t *testing.T) {
	var got interface{}
	if err := Validate([]byte("["+strings.Repeat("0,", maxTokens)+"0]"), &got); err == nil {
		t.Fatal("token budget ignored")
	}
	if err := Validate([]byte(`{}`), nil); err == nil {
		t.Fatal("nil target accepted")
	}
	if err := Validate([]byte(`{}`), sample{}); err == nil {
		t.Fatal("nonpointer target accepted")
	}
	type embedded struct{ sample }
	if err := Validate([]byte(`{}`), &embedded{}); err == nil {
		t.Fatal("unsupported embedding silently accepted")
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, s := range []string{`{}`, `{"Description":"shadow"}`, `{"schema":{"x":{},"X":{}}}`, `{"params":{"token":"a","toKen":"b"}}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { var got sample; _ = Unmarshal([]byte(s), &got) })
}
