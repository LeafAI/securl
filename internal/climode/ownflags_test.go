package climode

import (
	"reflect"
	"strings"
	"testing"
)

// The program's own flags (-config, --no-daemon) may stand anywhere in a command line, but a word that is the VALUE of a tool's
// flag is the tool's: `--sql --no-daemon` is the text "--no-daemon" given to --sql, not the program's flag.
func TestOwnFlagsAreNotTakenFromTheValueOfAToolFlag(t *testing.T) {
	r := newRig(t, false)
	cat, err := catalog(r.envFor())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in       []string
		wantArgs []string
		wantPath string
		wantND   bool
	}{
		{[]string{"db", "query", "--target", "x", "--sql", "--no-daemon"}, []string{"db", "query", "--target", "x", "--sql", "--no-daemon"}, "", false},
		{[]string{"db", "query", "--target", "x", "--sql", "-config"}, []string{"db", "query", "--target", "x", "--sql", "-config"}, "", false},
		{[]string{"db", "query", "--target", "x", "--sql=--no-daemon"}, []string{"db", "query", "--target", "x", "--sql=--no-daemon"}, "", false},
		{[]string{"db", "query", "--target", "x", "--sql", "select 1", "--no-daemon"}, []string{"db", "query", "--target", "x", "--sql", "select 1"}, "", true},
		{[]string{"--no-daemon", "db", "query", "--target", "x"}, []string{"db", "query", "--target", "x"}, "", true},
		{[]string{"db", "--no-daemon", "query", "--target", "x"}, []string{"db", "query", "--target", "x"}, "", true},
		{[]string{"db", "query", "-config", "c.yaml", "--target", "x"}, []string{"db", "query", "--target", "x"}, "c.yaml", false},
		{[]string{"session", "list", "-config", "c.yaml", "--no-daemon"}, []string{"session", "list"}, "c.yaml", true},
		{[]string{"request", "--header", "-config=1", "--url", "u"}, []string{"request", "--header", "-config=1", "--url", "u"}, "", false},
		{[]string{"request", "--force-refresh", "--no-daemon"}, []string{"request", "--force-refresh"}, "", true},
	} {
		gotArgs, path, nd := cat.SplitOwnFlags(tc.in)
		if !reflect.DeepEqual(gotArgs, tc.wantArgs) || path != tc.wantPath || nd != tc.wantND {
			t.Errorf("%s\n  got  %v %q %v\n  want %v %q %v", strings.Join(tc.in, " "), gotArgs, path, nd, tc.wantArgs, tc.wantPath, tc.wantND)
		}
	}
}

func TestOwnFlagsOfAnUnknownCommandAreStillTaken(t *testing.T) {
	r := newRig(t, false)
	cat, _ := catalog(r.envFor())
	args, path, nd := cat.SplitOwnFlags([]string{"frob", "--no-daemon", "-config", "c.yaml"})
	if !reflect.DeepEqual(args, []string{"frob"}) || path != "c.yaml" || !nd {
		t.Errorf("%v %q %v", args, path, nd)
	}
}
