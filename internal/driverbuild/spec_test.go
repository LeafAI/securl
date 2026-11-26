package driverbuild

import (
	"strings"
	"testing"
)

const goodHash = "4b5a6fc17bbd68ba7390b6b944aa1cf43140271e"

func TestASpecIsHostPathAtARevision(t *testing.T) {
	for in, want := range map[string]Spec{
		"gitlab.example.com/group/repo@" + goodHash:      {Host: "gitlab.example.com", Path: "group/repo", Rev: goodHash},
		"gitlab.example.com/a/b/c/repo@v1.2.3":           {Host: "gitlab.example.com", Path: "a/b/c/repo", Rev: "v1.2.3"},
		"gitlab.example.com/group/repo.git@v1.2.3":       {Host: "gitlab.example.com", Path: "group/repo", Rev: "v1.2.3"},
		"git.example.org:2222/group/repo@v0.1.0-rc.1":    {Host: "git.example.org:2222", Path: "group/repo", Rev: "v0.1.0-rc.1"},
		"gitlab.example.com/group/repo/sub/pkg@v1.0.0":   {Host: "gitlab.example.com", Path: "group/repo/sub/pkg", Rev: "v1.0.0"},
		"gitlab.example.com/g/Repo_Name-2.x@" + goodHash: {Host: "gitlab.example.com", Path: "g/Repo_Name-2.x", Rev: goodHash},
	} {
		got, err := ParseSpec(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.Host != want.Host || got.Path != want.Path || got.Rev != want.Rev {
			t.Errorf("%q: got %+v, want %+v", in, got, want)
		}
	}
}

// What a spec may not be. Each is checked on its own, because one that another guard also catches would hide a guard that has
// been lost. The value ends up in a Go source file and in the arguments of git and go, so nothing that is not a plain path,
// a plain host and a plain revision gets through.
func TestWhatIsNotASpecIsRefusedForItsOwnReason(t *testing.T) {
	for name, tc := range map[string]struct{ in, why string }{
		"empty":                      {"", "empty"},
		"blank":                      {"   ", "empty"},
		"no revision":                {"gitlab.example.com/g/r", "revision"},
		"an empty revision":          {"gitlab.example.com/g/r@", "revision"},
		"a floating revision":        {"gitlab.example.com/g/r@latest", "pinned"},
		"a branch name":              {"gitlab.example.com/g/r@main", "pinned"},
		"upgrade":                    {"gitlab.example.com/g/r@upgrade", "pinned"},
		"patch":                      {"gitlab.example.com/g/r@patch", "pinned"},
		"a short hash":               {"gitlab.example.com/g/r@abc123", "pinned"},
		"a 12 character hash":        {"gitlab.example.com/g/r@" + goodHash[:12], "short hash"},
		"a 39 character hash":        {"gitlab.example.com/g/r@" + goodHash[:39], "short hash"},
		"a 41 character hash":        {"gitlab.example.com/g/r@" + goodHash + "a", "pinned"},
		"a version without the v":    {"gitlab.example.com/g/r@1.2.3", "pinned"},
		"two revisions":              {"gitlab.example.com/g/r@v1.0.0@v2.0.0", "revision"},
		"no path":                    {"gitlab.example.com@v1.0.0", "path"},
		"only a group":               {"gitlab.example.com/g@v1.0.0", "path"},
		"a scheme":                   {"https://gitlab.example.com/g/r@v1.0.0", "scheme"},
		"an ssh url":                 {"git@gitlab.example.com:g/r@v1.0.0", "scheme"},
		"a file path":                {"/tmp/driver@v1.0.0", "path"},
		"a relative path":            {"./driver@v1.0.0", "path"},
		"a path with dot dot":        {"gitlab.example.com/g/../r@v1.0.0", "path"},
		"a path ending in dot dot":   {"gitlab.example.com/g/r/..@v1.0.0", "path"},
		"a double slash":             {"gitlab.example.com/g//r@v1.0.0", "path"},
		"a trailing slash":           {"gitlab.example.com/g/r/@v1.0.0", "path"},
		"a space":                    {"gitlab.example.com/g/r x@v1.0.0", "character"},
		"a tab":                      {"gitlab.example.com/g/r\t@v1.0.0", "character"},
		"a newline":                  {"gitlab.example.com/g/r\n@v1.0.0", "character"},
		"a carriage return":          {"gitlab.example.com/g/r\r@v1.0.0", "character"},
		"a quote":                    {"gitlab.example.com/g/r\"@v1.0.0", "character"},
		"a backtick":                 {"gitlab.example.com/g/r`@v1.0.0", "character"},
		"a backslash":                {"gitlab.example.com/g/r\\@v1.0.0", "character"},
		"a semicolon":                {"gitlab.example.com/g/r;x@v1.0.0", "character"},
		"a dollar":                   {"gitlab.example.com/g/$r@v1.0.0", "character"},
		"a pipe":                     {"gitlab.example.com/g/r|x@v1.0.0", "character"},
		"an ampersand":               {"gitlab.example.com/g/r&x@v1.0.0", "character"},
		"a parenthesis":              {"gitlab.example.com/g/r(x)@v1.0.0", "character"},
		"a non-ascii letter":         {"gitlab.example.com/g/réo@v1.0.0", "character"},
		"a null":                     {"gitlab.example.com/g/r\x00@v1.0.0", "character"},
		"an option":                  {"-gitlab.example.com/g/r@v1.0.0", "host"},
		"a host that is an option":   {"--upload-pack=x/g/r@v1.0.0", "character"},
		"a path that is an option":   {"gitlab.example.com/-g/r@v1.0.0", "path"},
		"a host with a user":         {"user@gitlab.example.com/g/r@v1.0.0", "host"},
		"a host with a bad port":     {"gitlab.example.com:99999/g/r@v1.0.0", "host"},
		"a host with an empty port":  {"gitlab.example.com:/g/r@v1.0.0", "host"},
		"a host with a letter port":  {"gitlab.example.com:ssh/g/r@v1.0.0", "host"},
		"a host without a dot":       {"localhost/g/r@v1.0.0", "host"},
		"an ip address":              {"10.0.0.1/g/r@v1.0.0", "host"},
		"a bracketed ip":             {"[::1]/g/r@v1.0.0", "character"},
		"a host that is empty":       {"/g/r@v1.0.0", "host"},
		"a revision with a slash":    {"gitlab.example.com/g/r@v1.0.0/x", "revision"},
		"a revision with an option":  {"gitlab.example.com/g/r@--x", "pinned"},
		"a revision with a colon":    {"gitlab.example.com/g/r@v1.0.0:x", "revision"},
		"a revision with a space":    {"gitlab.example.com/g/r@v1.0.0 x", "character"},
		"a version with a build tag": {"gitlab.example.com/g/r@v1.0.0+incompatible", "pinned"},
		"a path too deep":            {"gitlab.example.com/" + strings.Repeat("a/", 20) + "r@v1.0.0", "deep"},
		"a spec too long":            {"gitlab.example.com/" + strings.Repeat("a", 300) + "/r@v1.0.0", "long"},
		"a mixed-case hash":          {"gitlab.example.com/g/r@" + strings.ToUpper(goodHash), "pinned"},
		"the securl module itself":   {"github.com/LeafAI/securl@v1.0.0", "securl"},
		"a package inside securl":    {"github.com/LeafAI/securl/internal/site/x@v1.0.0", "securl"},
		"securl in other case":       {"github.com/leafai/SECURL@v1.0.0", "securl"},
	} {
		_, err := ParseSpec(tc.in)
		if err == nil {
			t.Errorf("%s: %q was accepted", name, tc.in)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tc.why) {
			t.Errorf("%s: %q refused, but the reason does not say %q: %v", name, tc.in, tc.why, err)
		}
	}
}

// The refusal never repeats the value: it may hold a secret that someone pasted by mistake, and it ends up in a build log.
func TestARefusalDoesNotRepeatWhatWasGiven(t *testing.T) {
	for _, in := range []string{"https://user:hunter2-SECRET@gitlab.example.com/g/r@v1.0.0", "gitlab.example.com/g/r;hunter2-SECRET@v1.0.0", "hunter2-SECRET"} {
		_, err := ParseSpec(in)
		if err == nil {
			t.Fatalf("%q was accepted", in)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the refusal repeats the secret: %v", err)
		}
	}
}

func TestTheSpecsAreSplitOnWhitespaceAndCommasAndNothingElse(t *testing.T) {
	got, err := ParseList("gitlab.example.com/a/b@v1.0.0, gitlab.example.com/c/d@v2.0.0\n gitlab.example.com/e/f@v3.0.0\t")
	if err != nil || len(got) != 3 || got[0].Path != "a/b" || got[1].Path != "c/d" || got[2].Path != "e/f" {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := ParseList(""); err != nil || len(got) != 0 {
		t.Errorf("nothing asked for is nothing: %+v %v", got, err)
	}
	if got, err := ParseList(" , \n "); err != nil || len(got) != 0 {
		t.Errorf("only separators is nothing: %+v %v", got, err)
	}
	if _, err := ParseList("gitlab.example.com/a/b@v1.0.0 gitlab.example.com/a/b@v2.0.0"); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("the same module twice, at two revisions, is a mistake: %v", err)
	}
	if _, err := ParseList("gitlab.example.com/a/b@v1.0.0 nonsense"); err == nil {
		t.Error("one bad spec spoils the list")
	}
	many := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		many = append(many, "gitlab.example.com/g/r"+string(rune('a'+i%26))+string(rune('a'+i/26))+"@v1.0.0")
	}
	if _, err := ParseList(strings.Join(many, " ")); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("a list has a bound: %v", err)
	}
}

func TestTheModulePathAndTheCloneAddressAreWhatGoAndGitNeed(t *testing.T) {
	s, _ := ParseSpec("gitlab.example.com/platform/internal-tools/securl-driver-console@" + goodHash)
	if s.Module() != "gitlab.example.com/platform/internal-tools/securl-driver-console" {
		t.Errorf("%s", s.Module())
	}
	if s.CloneURL() != "git@gitlab.example.com:platform/internal-tools/securl-driver-console.git" {
		t.Errorf("%s", s.CloneURL())
	}
	p, _ := ParseSpec("git.example.org:2222/g/r@v1.0.0")
	if p.CloneURL() != "ssh://git@git.example.org:2222/g/r.git" {
		t.Errorf("a port needs the ssh:// form: %s", p.CloneURL())
	}
	if s.String() != "gitlab.example.com/platform/internal-tools/securl-driver-console@"+goodHash {
		t.Errorf("%s", s.String())
	}
	d, _ := ParseSpec("gitlab.example.com/g/r.git@v1.0.0")
	if d.Module() != "gitlab.example.com/g/r" || d.CloneURL() != "git@gitlab.example.com:g/r.git" {
		t.Errorf(".git is not doubled: %s %s", d.Module(), d.CloneURL())
	}
}

func TestAPortIsAWholeNumberFromOneToSixtyFiveThousandFiveHundredThirtyFive(t *testing.T) {
	for _, p := range []string{"1", "22", "2222", "65535"} {
		if _, err := ParseSpec("git.example.org:" + p + "/g/r@v1.0.0"); err != nil {
			t.Errorf("port %s: %v", p, err)
		}
	}
	for _, p := range []string{"0", "65536", "70000", "080", "-1", "+22", "1e3", "22a", ""} {
		if _, err := ParseSpec("git.example.org:" + p + "/g/r@v1.0.0"); err == nil || !strings.Contains(err.Error(), "port") {
			t.Errorf("port %q: %v", p, err)
		}
	}
}

// Parts of a spec that an earlier check already catches are still refused on their own account: if that earlier check were ever
// loosened, a second revision, a slash in a revision or a dot-dot in a path must still not get through.
func TestEachGuardAloneStopsWhatItIsThere(t *testing.T) {
	good := Spec{Host: "gitlab.example.com", Path: "g/r", Rev: "v1.0.0"}
	if good.Module() != "gitlab.example.com/g/r" {
		t.Fatal(good)
	}
	for _, in := range []string{
		"gitlab.example.com/g/r@v1.0.0@v1.0.0",
		"gitlab.example.com/g/r@v1.0.0/..",
		"gitlab.example.com/g/r@" + goodHash + ":x",
		"gitlab.example.com/g/./r@v1.0.0",
		"gitlab.example.com/g/r/.@v1.0.0",
	} {
		if _, err := ParseSpec(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

// The early checks exist to say what is wrong in words a person can act on: a second revision, a slash in a revision and a dot-dot
// in a path would each also fail the later, general checks, but with a message that does not say why.
func TestTheSpecificMistakesAreNamedAsSuch(t *testing.T) {
	for in, want := range map[string]string{
		"gitlab.example.com/g/r@v1.0.0@v2.0.0": "one revision",
		"gitlab.example.com/g/r@v1.0.0/x":      "a / or a :",
		"gitlab.example.com/g/r@v1.0.0:x":      "a / or a :",
		"gitlab.example.com/g/../r@v1.0.0":     "no ..",
		"gitlab.example.com/g/r/..@v1.0.0":     "no ..",
	} {
		_, err := ParseSpec(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want a refusal that says %q, got %v", in, want, err)
		}
	}
}
