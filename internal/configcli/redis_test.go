package configcli

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The guided questions, in order: name, host, port, environment, username, mode, tls. A read-only target stops there.
const guidedRedis = "cache-dev\nredis.dev.corp.example\n\n1\n\n1\n1\n"

func TestRedisAddGuidedWritesAReadOnlyTarget(t *testing.T) {
	r := run(t, "", guidedRedis, "redis", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	x, ok := c.RedisTarget("cache-dev")
	if !ok || len(c.Redis) != 1 || x.Host != "redis.dev.corp.example" || x.Environment != "dev" || x.Writable() || x.Username != "" || x.PortOrDefault() != 6379 || x.TLSMode() != "verify" {
		t.Fatalf("%+v", c.Redis)
	}
	raw, _ := os.ReadFile(r.path)
	for _, def := range []string{"port:", "tls:", "mode:", "username:", "max_items", "max_reply_bytes", "command_timeout"} {
		if strings.Contains(string(raw), def) {
			t.Errorf("defaults are not written, so the program can change them later (%s):\n%s", def, raw)
		}
	}
	if !strings.Contains(r.out, "session_open") || !strings.Contains(r.out, "redis://cache-dev") {
		t.Errorf("the output says how the password is given:\n%s", r.out)
	}
}

// The password is typed on a page and kept in the vault: nothing here asks for it, takes it as a flag, or writes it. A user name is
// asked for, because it is a name and not a secret.
func TestRedisAddNeverAsksForOrTakesOrWritesAPassword(t *testing.T) {
	r := run(t, "", guidedRedis, "redis", "add")
	for _, prompt := range regexp.MustCompile(`(?m)^[^\n]*?(?:\[[^\]]*\])?: ?$`).FindAllString(r.out, -1) {
		l := strings.ToLower(prompt)
		for _, w := range []string{"password", "passphrase", "secret", "token", "auth"} {
			if strings.Contains(l, w) {
				t.Errorf("a question asks for a credential (%s): %q", w, prompt)
			}
		}
	}
	if !strings.Contains(r.out, "No password is needed here") {
		t.Errorf("it says plainly that no password is asked for:\n%s", r.out)
	}
	for _, flagName := range []string{"--password", "--pass", "--auth", "--requirepass", "--secret", "--token", "--url", "--uri"} {
		x := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev", flagName, "hunter2-VERY-secret")
		if x.code == 0 {
			t.Errorf("%s was accepted", flagName)
		}
		if strings.Contains(x.out+x.err, "hunter2") {
			t.Errorf("%s: the refusal repeats the password:\n%s%s", flagName, x.out, x.err)
		}
		if raw, _ := os.ReadFile(x.path); strings.Contains(string(raw), "redis:") {
			t.Errorf("%s: a target was written although the call was refused:\n%s", flagName, raw)
		}
	}
}

func TestRedisAddByFlagsNeedsNoQuestions(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "test", "--port", "6380", "--username", "app",
		"--tls", "skip-verify", "--max-items", "50", "--max-reply-bytes", "4096", "--command-timeout", "3s")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	x, _ := load(t, r.path).RedisTarget("c")
	if x.PortOrDefault() != 6380 || x.Username != "app" || x.TLSMode() != "skip-verify" || x.ItemLimit() != 50 || x.ReplyLimit() != 4096 || x.CommandTimeoutOrDefault() != 3*time.Second || x.Writable() {
		t.Errorf("%+v", x)
	}
	r2 := run(t, "", "", "redis", "add", "--name", "plain", "--host", "h.example", "--environment", "dev")
	if r2.code != 0 {
		t.Fatalf("name, host and environment are enough: %s", r2.err)
	}
	if x, _ := load(t, r2.path).RedisTarget("plain"); x.Writable() || x.TLSMode() != "verify" {
		t.Errorf("a script that says nothing about the mode or TLS gets the safe ones: %+v", x)
	}
	if raw, _ := os.ReadFile(r2.path); strings.Contains(string(raw), "port:") {
		t.Errorf("the default port is not written:\n%s", raw)
	}
}

// Letting an agent change data is the one answer that is a decision about risk, so a script has to say it is intended.
func TestRedisAddWithWritesNeedsTheWordYesAndTheGuidedWayAsks(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "w", "--host", "h.example", "--environment", "dev", "--mode", "read_write")
	if r.code == 0 {
		t.Fatal("read_write without --yes-allow-writes was accepted")
	}
	if !strings.Contains(r.err, "--yes-allow-writes") {
		t.Errorf("it says what to add: %s", r.err)
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "redis:") {
		t.Errorf("a target was written:\n%s", raw)
	}
	ok := run(t, "", "", "redis", "add", "--name", "w", "--host", "h.example", "--environment", "dev", "--mode", "read_write", "--yes-allow-writes")
	if ok.code != 0 {
		t.Fatalf("%s", ok.err)
	}
	if x, _ := load(t, ok.path).RedisTarget("w"); !x.Writable() {
		t.Errorf("%+v", x)
	}
	if !strings.Contains(ok.out, "rights") && !strings.Contains(ok.out, "ACL") {
		t.Errorf("a writable target says what protects it:\n%s", ok.out)
	}
	// guided: mode 2 (read_write), then the confirmation
	g := run(t, "", "w\nh.example\n\n1\n\n2\ny\n1\n", "redis", "add")
	if g.code != 0 {
		t.Fatalf("%s\n%s", g.err, g.out)
	}
	if x, _ := load(t, g.path).RedisTarget("w"); !x.Writable() {
		t.Errorf("%+v", x)
	}
	d := run(t, "", "w\nh.example\n\n1\n\n2\nn\n", "redis", "add")
	if d.code == 0 {
		t.Error("declining the confirmation is not a success")
	}
	if raw, _ := os.ReadFile(d.path); strings.Contains(string(raw), "redis:") {
		t.Errorf("a declined target reached the file:\n%s", raw)
	}
}

func TestRedisAddFlagsThatBelongToWritesAreRefusedOnAReadOnlyTarget(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev", "--yes-allow-writes")
	if r.code == 0 {
		t.Error("--yes-allow-writes on a read-only target is a mistake to report, not to drop in silence")
	}
}

func TestRedisAddChecksEveryAnswerWithTheConfigurationsOwnCheck(t *testing.T) {
	base := []string{"redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev"}
	for name, extra := range map[string][]string{
		"port 0 text":      {"--port", "x"},
		"port too big":     {"--port", "70000"},
		"bad mode":         {"--mode", "rw"},
		"bad tls":          {"--tls", "maybe"},
		"items too big":    {"--max-items", "100001"},
		"items negative":   {"--max-items", "-1"},
		"reply too big":    {"--max-reply-bytes", "67108865"},
		"timeout too long": {"--command-timeout", "10m"},
		"unknown flag":     {"--database", "1"},
		"extra argument":   {"stray"},
		"username a line":  {"--username", "a\nb"},
	} {
		r := run(t, "", "", append(append([]string{}, base...), extra...)...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "redis:") {
			t.Errorf("%s: a refused target reached the file:\n%s", name, raw)
		}
	}
	for name, args := range map[string][]string{
		"bad name":         {"redis", "add", "--name", "a b", "--host", "h.example", "--environment", "dev"},
		"host with a port": {"redis", "add", "--name", "a", "--host", "h.example:6379", "--environment", "dev"},
		"production":       {"redis", "add", "--name", "a", "--host", "h.example", "--environment", "production"},
		"prod":             {"redis", "add", "--name", "a", "--host", "h.example", "--environment", "prod"},
	} {
		if r := run(t, "", "", args...); r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAWrongGuidedRedisAnswerIsAskedAgainWithTheReason(t *testing.T) {
	// a name with a space, then a good one; a host with a port, then a good one
	r := run(t, "", "a b\ncache\nh.example:6379\nh.example\n\n1\n\n1\n1\n", "redis", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	if !strings.Contains(r.out, "use 1-64 letters, digits") || !strings.Contains(r.out, "no port, scheme or user") {
		t.Errorf("the reasons are said:\n%s", r.out)
	}
	if x, ok := load(t, r.path).RedisTarget("cache"); !ok || x.Host != "h.example" {
		t.Errorf("%+v", x)
	}
}

func TestRedisAddReplacesATargetOfTheSameNameOnlyAfterAsking(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "c", "--host", "old.example", "--environment", "dev")
	r2 := run(t, r.path, "n\n", "redis", "add", "--name", "c", "--host", "new.example", "--environment", "dev")
	if r2.code == 0 {
		t.Error("declining the replacement is not a success")
	}
	if x, _ := load(t, r.path).RedisTarget("c"); x.Host != "old.example" {
		t.Errorf("replaced after the answer was no: %+v", x)
	}
	if r3 := run(t, r.path, "\n", "redis", "add", "--name", "c", "--host", "new.example", "--environment", "dev"); r3.code == 0 {
		t.Error("just pressing Enter must not replace a target")
	}
	r4 := run(t, r.path, "y\n", "redis", "add", "--name", "c", "--host", "new.example", "--environment", "dev")
	if r4.code != 0 {
		t.Fatalf("%s", r4.err)
	}
	c := load(t, r.path)
	if x, _ := c.RedisTarget("c"); x.Host != "new.example" || len(c.Redis) != 1 {
		t.Errorf("%+v", c.Redis)
	}
}

func TestAnInvalidRedisTargetIsRefusedBeforeBeingAskedWhetherToReplaceOne(t *testing.T) {
	first := run(t, "", "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev")
	r := run(t, first.path, "y\n", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev", "--port", "70000")
	if r.code == 0 || strings.Contains(r.out, "already exists") {
		t.Errorf("code %d:\n%s%s", r.code, r.out, r.err)
	}
}

func TestRedisAddLeavesTheRestOfTheFileAsItWas(t *testing.T) {
	first := run(t, "", "", "set", "dingtalk.keyword", "login")
	r := run(t, first.path, "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	if c := load(t, r.path); c.DingTalk.Keyword != "login" || len(c.Redis) != 1 {
		t.Errorf("%+v", c.DingTalk)
	}
	before, _ := os.ReadFile(first.path)
	bad := run(t, first.path, "", "redis", "add", "--name", "x", "--host", "h.example", "--environment", "production")
	after, _ := os.ReadFile(first.path)
	if bad.code == 0 || string(before) != string(after) {
		t.Errorf("a refused call must leave the file exactly as it was")
	}
}

func TestRedisListShowsTargetsWithWhatEachAllowsAndNothingSecret(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev")
	run(t, r.path, "", "redis", "add", "--name", "b", "--host", "g.example", "--environment", "test", "--port", "6380", "--mode", "read_write", "--yes-allow-writes", "--username", "app")
	l := run(t, r.path, "", "redis", "list")
	if l.code != 0 {
		t.Fatal(l.err)
	}
	rows := map[string]string{}
	lines := strings.Split(strings.TrimSpace(l.out), "\n")
	for _, h := range []string{"NAME", "ENV", "MODE", "HOST"} {
		if !strings.Contains(lines[0], h) {
			t.Errorf("%q missing from the header: %s", h, lines[0])
		}
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		rows[f[0]] = strings.Join(f[1:], " ")
	}
	if got := rows["a"]; got != "dev read_only h.example:6379" {
		t.Errorf("a: %q", got)
	}
	if got := rows["b"]; got != "test read_write g.example:6380" {
		t.Errorf("b: %q", got)
	}
	if e := run(t, "", "", "redis", "list"); !strings.Contains(e.out, "redis add") {
		t.Errorf("an empty list says how to add one:\n%s", e.out)
	}
}

func TestRedisRemoveForgetsATargetAndSaysThePasswordStaysUntilItIsClosed(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev")
	if x := run(t, r.path, "", "redis", "remove", "nope"); x.code == 0 {
		t.Error("a target that does not exist")
	}
	if x := run(t, r.path, "", "redis", "remove"); x.code == 0 {
		t.Error("a name is needed")
	}
	x := run(t, r.path, "", "redis", "remove", "c")
	if x.code != 0 {
		t.Fatal(x.err)
	}
	if c := load(t, r.path); len(c.Redis) != 0 {
		t.Errorf("%+v", c.Redis)
	}
	if !strings.Contains(x.out, "session_close") || !strings.Contains(x.out, "redis://c") {
		t.Errorf("a password saved for it stays in the vault until it is closed:\n%s", x.out)
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "redis") {
		t.Errorf("an empty redis list is not left behind:\n%s", raw)
	}
}

func TestTheRedisCommandsHaveTheirOwnUsageAndTheMainUsageListsThem(t *testing.T) {
	for _, args := range [][]string{{"redis"}, {"redis", "bogus"}} {
		r := run(t, "", "", args...)
		if r.code == 0 || !strings.Contains(r.err+r.out, "redis add") {
			t.Errorf("%v: %d\n%s%s", args, r.code, r.err, r.out)
		}
	}
	if u := run(t, "", "", "bogus"); !strings.Contains(u.err+u.out, "redis add") {
		t.Errorf("the usage lists it:\n%s%s", u.err, u.out)
	}
}

// The question that gives an agent the right to change data is answered "no" by default, so that pressing Enter, or input that ends,
// never grants it. And "no" is not a success: nothing is written.
func TestTheWriteConfirmationDefaultsToNoAndNoWritesNothing(t *testing.T) {
	// guided up to the mode, which is 2 (read_write); then Enter on the confirmation, and enough answers after it (Enter for the TLS
	// question) that if the confirmation had said yes the target would be written: only the default is then what decides
	enter := run(t, "", "w\nh.example\n\n1\n\n2\n\n\n\n", "redis", "add")
	if enter.code == 0 {
		t.Fatal("Enter on the confirmation granted the right to write")
	}
	if raw, _ := os.ReadFile(enter.path); strings.Contains(string(raw), "redis:") {
		t.Errorf("a target was written:\n%s", raw)
	}
	no := run(t, "", "w\nh.example\n\n1\n\n2\nn\n", "redis", "add")
	if no.code == 0 || !strings.Contains(no.err+no.out, "cancel") && !strings.Contains(strings.ToLower(no.err), "cancel") {
		t.Errorf("a refusal says it was cancelled (code %d): %s%s", no.code, no.err, no.out)
	}
	if raw, _ := os.ReadFile(no.path); strings.Contains(string(raw), "redis:") {
		t.Errorf("a declined target reached the file:\n%s", raw)
	}
	// the question itself names the commands that are allowed and the ones that never are, so the person knows what they are agreeing to
	if !strings.Contains(no.out, "FLUSHALL") || !strings.Contains(no.out, "never") {
		t.Errorf("the question says what is never allowed:\n%s", no.out)
	}
}

// The environment the questions offer is the one the configuration accepts, and production is neither offered nor accepted: the list
// of choices is the guard here, and the configuration is the second one.
func TestTheEnvironmentsOfferedAreExactlyDevTestAndStaging(t *testing.T) {
	r := run(t, "", guidedRedis, "redis", "add")
	for _, want := range []string{"1) dev", "2) test", "3) staging"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("%q is not offered:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "production") && !strings.Contains(r.out, "not offered") {
		t.Errorf("production is offered:\n%s", r.out)
	}
	// 4 is not a choice
	if x := run(t, "", "c\nh.example\n\n4\n\n1\n1\n", "redis", "add"); x.code == 0 && strings.Contains(x.out, "4)") {
		t.Errorf("a fourth environment was offered:\n%s", x.out)
	}
	if x := run(t, "", "c\nh.example\n\n4\n4\n4\n", "redis", "add"); x.code == 0 {
		t.Error("a choice that is not on the list was accepted")
	}
}

// What the person types in the guided way is checked at the end too, by the configuration's own check.
func TestAGuidedTargetThatTheConfigurationWouldRefuseIsNotWritten(t *testing.T) {
	// a host that the question accepts as a host, with a user name that is too long for the configuration
	long := strings.Repeat("u", 65)
	r := run(t, "", "c\nh.example\n\n1\n"+long+"\n1\n1\n", "redis", "add")
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "redis:") && strings.Contains(string(raw), long) {
		t.Errorf("a user name over the limit reached the file:\n%s", raw)
	}
}

func TestAScriptThatLeavesOutTheNameOrTheHostIsToldWhichFlag(t *testing.T) {
	for flagName, args := range map[string][]string{
		"--name": {"redis", "add", "--host", "h.example", "--environment", "dev"},
		"--host": {"redis", "add", "--name", "a", "--environment", "dev"},
	} {
		r := run(t, "", "", args...)
		if r.code == 0 || !strings.Contains(r.err, flagName) || strings.Contains(r.err, "input ended") {
			t.Errorf("%s: %d %q", flagName, r.code, r.err)
		}
	}
}

func TestAUserNameGivenByFlagIsCheckedLikeAnyOtherAnswer(t *testing.T) {
	for _, u := range []string{"a\nb", strings.Repeat("u", 65), "a\x00b"} {
		r := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev", "--username", u)
		if r.code == 0 {
			t.Errorf("%q was accepted", u)
		}
		if !strings.Contains(r.err, "username") {
			t.Errorf("the refusal names the flag: %q", r.err)
		}
	}
}

func TestTheListOfARedisTargetShowsItsPort(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev", "--port", "6400")
	l := run(t, r.path, "", "redis", "list")
	if !strings.Contains(l.out, "h.example:6400") {
		t.Errorf("%s", l.out)
	}
	r2 := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev")
	if l2 := run(t, r2.path, "", "redis", "list"); !strings.Contains(l2.out, "h.example:6379") {
		t.Errorf("the default port is shown, though it is not in the file:\n%s", l2.out)
	}
}

// The note after a Redis target says what protects it, in the words of the mode: a read-only target says that an agent can only read,
// and a writable one says that Redis's own ACL is what holds.
func TestTheNoteAfterARedisTargetSaysWhatProtectsItInTheWordsOfItsMode(t *testing.T) {
	ro := run(t, "", "", "redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev")
	if !strings.Contains(ro.out, "only read") || !strings.Contains(ro.out, "read rights only") || strings.Contains(ro.out, "takes changes") {
		t.Errorf("read-only:\n%s", ro.out)
	}
	rw := run(t, "", "", "redis", "add", "--name", "b", "--host", "h.example", "--environment", "dev", "--mode", "read_write", "--yes-allow-writes")
	if !strings.Contains(rw.out, "takes changes") || !strings.Contains(rw.out, "ACL") || strings.Contains(rw.out, "only read from") {
		t.Errorf("read-write:\n%s", rw.out)
	}
}

// A target that the configuration refuses is refused by the same check whatever the questions let through: the flags that have no
// question of their own (the limits, the user name) are the ones that reach the file only through it.
func TestEveryLimitThatHasNoQuestionIsHeldByTheConfigurationsCheck(t *testing.T) {
	for _, extra := range [][]string{{"--max-items", "100001"}, {"--max-reply-bytes", "67108865"}, {"--command-timeout", "10m"}, {"--max-items", "-5"}, {"--command-timeout", "-1s"}} {
		r := run(t, "", "", append([]string{"redis", "add", "--name", "a", "--host", "h.example", "--environment", "dev"}, extra...)...)
		if r.code == 0 {
			t.Errorf("%v accepted", extra)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "redis:") {
			t.Errorf("%v: reached the file:\n%s", extra, raw)
		}
	}
}

// The user name given by flag is refused by its own check, which names the flag, and not only by the whole-file check at the end
// that says which entry is wrong: the person is told what to fix in the words of what they typed.
func TestARefusedRedisUserNameNamesTheFlagAndNotJustTheEntry(t *testing.T) {
	r := run(t, "", "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev", "--username", strings.Repeat("u", 65))
	if r.code == 0 || !strings.HasPrefix(strings.TrimPrefix(r.err, "securl config: "), "username: ") {
		t.Errorf("%d %q", r.code, r.err)
	}
	if strings.Contains(r.err, "redis[0]") {
		t.Errorf("it was refused by the file-wide check, which says nothing about the flag: %q", r.err)
	}
}
