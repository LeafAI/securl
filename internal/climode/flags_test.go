package climode

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func schemaOf(t *testing.T, js string) *jsonschema.Schema {
	t.Helper()
	var s jsonschema.Schema
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

const sampleSchema = `{"type":"object","required":["url","workflow_id"],"properties":{
 "url":{"type":"string","description":"Base URL."},
 "workflow_id":{"type":"integer"},
 "force_refresh":{"type":"boolean"},
 "wait":{"type":["null","boolean"]},
 "limit":{"type":"integer"},
 "headers":{"type":"object","additionalProperties":{"type":"string"}},
 "query":{"type":"object","additionalProperties":{"anyOf":[{"type":"string"},{"type":"number"}]}},
 "json":{"description":"any JSON"}
}}`

func parse(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	cmd, err := newCommand("x_y", "Title", "desc", schemaOf(t, sampleSchema))
	if err != nil {
		t.Fatal(err)
	}
	return cmd.parse(args, strings.NewReader(""))
}

func TestFlagsBuildTheArgumentsOfATool(t *testing.T) {
	got, err := parse(t, "--url", "https://a.example", "--workflow-id", "42", "--force-refresh", "--limit=7",
		"--header", "Accept=text/html", "--header", "X-A=b", "--query", "q=1", "--query", "q=2", "--query", "p=x")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"url": "https://a.example", "workflow_id": int64(42), "force_refresh": true, "limit": int64(7),
		"headers": map[string]any{"Accept": "text/html", "X-A": "b"},
		"query":   map[string]any{"q": []any{"1", "2"}, "p": "x"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}
}

func TestANullableBooleanIsSetOnlyWhenGiven(t *testing.T) {
	if got, _ := parse(t, "--url", "u", "--workflow-id", "1"); got["wait"] != nil {
		t.Errorf("an unset flag must not be sent: %v", got)
	}
	got, err := parse(t, "--url", "u", "--workflow-id", "1", "--wait=false")
	if err != nil || got["wait"] != false {
		t.Errorf("--wait=false must be sent as false: %v %v", got, err)
	}
}

func TestARequiredFlagIsNamedWhenMissing(t *testing.T) {
	_, err := parse(t, "--url", "u")
	if err == nil || !strings.Contains(err.Error(), "--workflow-id") {
		t.Errorf("the error must name the missing flag: %v", err)
	}
	if _, err := parse(t); err == nil || !strings.Contains(err.Error(), "--url") {
		t.Errorf("%v", err)
	}
}

func TestAWrongTypeIsRefusedBeforeAnythingIsSent(t *testing.T) {
	if _, err := parse(t, "--url", "u", "--workflow-id", "abc"); err == nil {
		t.Error("a word is not an integer")
	}
	if _, err := parse(t, "--url", "u", "--workflow-id", "1", "--limit", "1.5"); err == nil {
		t.Error("1.5 is not an integer")
	}
}

func TestAnUnknownFlagIsRefusedAndNamed(t *testing.T) {
	_, err := parse(t, "--url", "u", "--workflow-id", "1", "--nope", "x")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("%v", err)
	}
}

func TestAJSONFlagTakesAnyJSONValueAndRefusesBrokenText(t *testing.T) {
	got, err := parse(t, "--url", "u", "--workflow-id", "1", "--json", `{"a":[1,2,{"b":null}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["json"], map[string]any{"a": []any{float64(1), float64(2), map[string]any{"b": nil}}}) {
		t.Errorf("%#v", got["json"])
	}
	if _, err := parse(t, "--url", "u", "--workflow-id", "1", "--json", `{broken`); err == nil {
		t.Error("broken JSON must be refused")
	}
}

func TestAKeyValueFlagNeedsAnEqualsSign(t *testing.T) {
	if _, err := parse(t, "--url", "u", "--workflow-id", "1", "--header", "no-equals"); err == nil {
		t.Error("--header needs name=value")
	}
}

func TestAFlagValueCanComeFromAFileOrStdin(t *testing.T) {
	cmd, err := newCommand("x_y", "T", "d", schemaOf(t, `{"type":"object","required":["sql"],"properties":{"sql":{"type":"string"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cmd.parse([]string{"--sql", "-"}, strings.NewReader("SELECT 1\nFROM t\n"))
	if err != nil || got["sql"] != "SELECT 1\nFROM t" {
		t.Errorf("--sql - reads stdin, without the final line ending: %#v %v", got, err)
	}
	p := t.TempDir() + "/q.sql"
	if err := writeFile(p, "SELECT 2;\n"); err != nil {
		t.Fatal(err)
	}
	got, err = cmd.parse([]string{"--sql", "@" + p}, strings.NewReader(""))
	if err != nil || got["sql"] != "SELECT 2;" {
		t.Errorf("--sql @file reads the file: %#v %v", got, err)
	}
	if _, err := cmd.parse([]string{"--sql", "@/no/such/file"}, strings.NewReader("")); err == nil {
		t.Error("a missing file is an error")
	}
	got, _ = cmd.parse([]string{"--sql", "@@literal"}, strings.NewReader(""))
	if got["sql"] != "@literal" {
		t.Errorf("@@ is a literal @: %#v", got)
	}
}

func TestTheHelpListsEveryFlagWithItsTypeAndWhetherItIsRequired(t *testing.T) {
	cmd, _ := newCommand("x_y", "Title of it", "What it does.", schemaOf(t, sampleSchema))
	h := cmd.help()
	for _, want := range []string{"Title of it", "What it does.", "--url string", "(required)", "--workflow-id int", "--force-refresh", "--header name=value", "--query name=value", "--json JSON", "Base URL."} {
		if !strings.Contains(h, want) {
			t.Errorf("help lacks %q:\n%s", want, h)
		}
	}
}

// -config is the one flag that belongs to the program and not to a tool: it may stand anywhere among the arguments, as it
// does for `securl vault` and `securl config`.
func TestTheConfigFlagIsTakenOutWhereverItStands(t *testing.T) {
	for _, tc := range []struct {
		in       []string
		wantArgs []string
		wantPath string
	}{
		{[]string{"site", "list"}, []string{"site", "list"}, ""},
		{[]string{"-config", "a.yaml", "site", "list"}, []string{"site", "list"}, "a.yaml"},
		{[]string{"site", "list", "-config", "a.yaml"}, []string{"site", "list"}, "a.yaml"},
		{[]string{"site", "-config", "a.yaml", "list"}, []string{"site", "list"}, "a.yaml"},
		{[]string{"site", "list", "--config=a.yaml"}, []string{"site", "list"}, "a.yaml"},
		{[]string{"session", "open", "--url", "u", "--config", "b.yaml"}, []string{"session", "open", "--url", "u"}, "b.yaml"},
		{[]string{"site", "list", "-config"}, []string{"site", "list", "-config"}, ""}, // no value: left for the parser to refuse
	} {
		gotArgs, gotPath := SplitConfig(tc.in)
		if !reflect.DeepEqual(gotArgs, tc.wantArgs) || gotPath != tc.wantPath {
			t.Errorf("SplitConfig(%v) = %v, %q; want %v, %q", tc.in, gotArgs, gotPath, tc.wantArgs, tc.wantPath)
		}
	}
}

func TestSplitConfigDoesNotChangeItsInput(t *testing.T) {
	in := []string{"site", "list", "-config", "a.yaml"}
	SplitConfig(in)
	if !reflect.DeepEqual(in, []string{"site", "list", "-config", "a.yaml"}) {
		t.Errorf("the caller's arguments were changed: %v", in)
	}
}
