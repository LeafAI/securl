package climode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// kind is how a field is typed on the command line.
type kind int

const (
	kString   kind = iota // --name value
	kInt                  // --name 12
	kBool                 // --name, --name=false
	kJSON                 // --name '{"any":"json"}'
	kStrMap               // --name key=value, repeated: a map of strings
	kMultiMap             // --name key=value, repeated: a value, or a list when a key repeats
)

type field struct {
	name     string // the field in the tool's input
	flag     string // --flag-name
	kind     kind
	required bool
	desc     string
}

// command is the command-line shape of one tool, read from the tool's own input schema, so a field added to a tool
// is a flag from the next build on and nothing here can fall out of step with it.
type command struct {
	tool, title, desc string
	group, sub        string // the words of the command: `session open` is group "session", sub "open"
	words             int    // how many words name it: 1 for `request`, 2 for `session open`
	fields            []field
	byFlag            map[string]*field
}

func newCommand(tool, title, desc string, schema *jsonschema.Schema) (*command, error) {
	c := &command{tool: tool, title: title, desc: desc, byFlag: map[string]*field{}}
	if schema == nil {
		return c, nil
	}
	required := map[string]bool{}
	for _, r := range schema.Required {
		required[r] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for n := range schema.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		k, err := kindOf(schema.Properties[n])
		if err != nil {
			return nil, fmt.Errorf("%s: field %q: %w", tool, n, err)
		}
		f := field{name: n, flag: flagName(n), kind: k, required: required[n], desc: schema.Properties[n].Description}
		c.fields = append(c.fields, f)
	}
	for i := range c.fields {
		c.byFlag[c.fields[i].flag] = &c.fields[i]
	}
	return c, nil
}

// kindOf reads the type of one property. A type it does not know is an error at build time of the command, never a silent
// "string": a tool whose input cannot be given on the command line must be noticed, not half-supported.
func kindOf(s *jsonschema.Schema) (kind, error) {
	types := s.Types
	if s.Type != "" {
		types = []string{s.Type}
	}
	var real []string // "null" is left out: a flag that is not given is not sent, so a field that may be null needs nothing more
	for _, t := range types {
		if t != "null" {
			real = append(real, t)
		}
	}
	if len(real) == 0 {
		return kJSON, nil // no type: any JSON value
	}
	if len(real) > 1 {
		return 0, fmt.Errorf("a union of types %v has no flag", real)
	}
	switch real[0] {
	case "string":
		return kString, nil
	case "integer":
		return kInt, nil
	case "boolean":
		return kBool, nil
	case "object":
		if s.AdditionalProperties != nil && len(s.AdditionalProperties.AnyOf) > 0 {
			return kMultiMap, nil
		}
		if s.AdditionalProperties != nil && s.AdditionalProperties.Type == "string" {
			return kStrMap, nil
		}
		return kJSON, nil
	}
	return 0, fmt.Errorf("type %q has no flag", real[0])
}

// parse reads the arguments after the command's name into the input of the tool. stdin serves a value of "-".
func (c *command) parse(args []string, stdin io.Reader) (map[string]any, error) {
	out := map[string]any{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") || a == "--" {
			return nil, fmt.Errorf("unexpected argument %q (every value is given with a --flag; see --help)", a)
		}
		name, val, hasVal := strings.Cut(a[2:], "=")
		f := c.lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown flag --%s (see --help)", name)
		}
		if !hasVal && f.kind == kBool {
			out[f.name] = true
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--%s needs a value", f.flag)
			}
			i++
			val = args[i]
		}
		if err := c.set(out, f, val, stdin); err != nil {
			return nil, fmt.Errorf("--%s: %w", f.flag, err)
		}
	}
	for _, f := range c.fields {
		if _, ok := out[f.name]; f.required && !ok {
			return nil, fmt.Errorf("--%s is required (see --help)", f.flag)
		}
	}
	return out, nil
}

// lookup finds a flag by its name; the singular of a map flag (--header for headers) is accepted too.
func (c *command) lookup(name string) *field {
	if f := c.byFlag[name]; f != nil {
		return f
	}
	for i := range c.fields {
		if (c.fields[i].kind == kStrMap || c.fields[i].kind == kMultiMap) && strings.TrimSuffix(c.fields[i].flag, "s") == name {
			return &c.fields[i]
		}
	}
	return nil
}

func (c *command) set(out map[string]any, f *field, raw string, stdin io.Reader) error {
	switch f.kind {
	case kString:
		v, err := textValue(raw, stdin)
		if err != nil {
			return err
		}
		out[f.name] = v
	case kInt:
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a whole number", raw)
		}
		out[f.name] = n
	case kBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("%q is not true or false", raw)
		}
		out[f.name] = b
	case kJSON:
		v, err := textValue(raw, stdin)
		if err != nil {
			return err
		}
		var any any
		if err := json.Unmarshal([]byte(v), &any); err != nil {
			return fmt.Errorf("not valid JSON: %v", err)
		}
		out[f.name] = any
	case kStrMap, kMultiMap:
		k, v, ok := strings.Cut(raw, "=")
		if !ok || k == "" {
			return errors.New("expected name=value")
		}
		addPair(out, f, k, v)
	}
	return nil
}

// addPair adds one name=value. A name given twice becomes a list, for the maps that take one.
func addPair(out map[string]any, f *field, k, v string) {
	m, _ := out[f.name].(map[string]any)
	next := make(map[string]any, len(m)+1)
	for kk, vv := range m {
		next[kk] = vv
	}
	if prev, ok := next[k]; ok && f.kind == kMultiMap {
		switch p := prev.(type) {
		case []any:
			next[k] = append(append([]any{}, p...), v)
		default:
			next[k] = []any{p, v}
		}
	} else {
		next[k] = v
	}
	out[f.name] = next
}

// textValue is the value of a text flag: "-" is standard input, "@path" is a file, "@@x" is the text "@x". The line ending
// that ends a file or a pipe is not part of the text.
func textValue(raw string, stdin io.Reader) (string, error) {
	switch {
	case raw == "-":
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("reading standard input: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case strings.HasPrefix(raw, "@@"):
		return raw[1:], nil
	case strings.HasPrefix(raw, "@"):
		b, err := os.ReadFile(raw[1:])
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", raw[1:], err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return raw, nil
}

func writeFile(path, text string) error { return os.WriteFile(path, []byte(text), 0o600) }

// help is the text of `--help` for the command.
func (c *command) help() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%s\n\nFlags:\n", c.title, c.desc)
	for _, f := range c.fields {
		line := "  --" + f.flag
		switch f.kind {
		case kString:
			line += " string"
		case kInt:
			line += " int"
		case kBool:
		case kJSON:
			line += " JSON"
		case kStrMap, kMultiMap:
			line = "  --" + strings.TrimSuffix(f.flag, "s") + " name=value"
		}
		if f.required {
			line += "  (required)"
		}
		fmt.Fprintln(&b, line)
		if f.desc != "" {
			fmt.Fprintf(&b, "        %s\n", f.desc)
		}
	}
	return b.String()
}

// SplitConfig takes the program's own -config flag out of the arguments, wherever it stands, and returns the rest and the
// path ("" when it was not given). -config, --config, -config=x and --config=x are all accepted. The input is not changed.
// A tool has no flag of this name (its flags are all --long-names of its fields), so nothing of a tool is taken by mistake.
func SplitConfig(args []string) ([]string, string) {
	rest := make([]string, 0, len(args))
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-config" || a == "--config") && i+1 < len(args):
			path = args[i+1]
			i++
		case strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config="):
			_, path, _ = strings.Cut(a, "=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, path
}
