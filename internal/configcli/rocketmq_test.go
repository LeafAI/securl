package configcli

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The guided questions, in order: name, NameServers (comma separated), environment, topics (comma separated), TLS. The limits are
// flags only: a person who wants them different says so, and the others have defaults that are safe.
const guidedRMQ = "mq-dev\nrmq-ns.dev.corp.example:9876\n1\norders,payments\n1\n"

func TestRocketMQAddGuidedWritesATarget(t *testing.T) {
	r := run(t, "", guidedRMQ, "rocketmq", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	x, ok := c.RocketMQTarget("mq-dev")
	if !ok || len(c.RocketMQ) != 1 || x.Environment != "dev" || len(x.Topics) != 2 || x.Topics[1] != "payments" || x.NameServers[0] != "rmq-ns.dev.corp.example:9876" || x.TLSMode() != "disable" {
		t.Fatalf("%+v", c.RocketMQ)
	}
	raw, _ := os.ReadFile(r.path)
	for _, def := range []string{"tls:", "max_messages", "max_body_bytes", "timeout"} {
		if strings.Contains(string(raw), def) {
			t.Errorf("defaults are not written, so the program can change them later (%s):\n%s", def, raw)
		}
	}
	if !strings.Contains(r.out, "session_open") || !strings.Contains(r.out, "rocketmq://mq-dev") {
		t.Errorf("the output says how the keys are given:\n%s", r.out)
	}
	if !strings.Contains(r.out, "read") {
		t.Errorf("it says that an agent can only read:\n%s", r.out)
	}
}

// The AccessKey and the SecretKey are typed on a page and kept in the vault: nothing here asks for them, takes them as a flag, or
// writes them.
func TestRocketMQAddNeverAsksForOrTakesOrWritesAKey(t *testing.T) {
	r := run(t, "", guidedRMQ, "rocketmq", "add")
	for _, prompt := range regexp.MustCompile(`(?m)^[^\n]*?(?:\[[^\]]*\])?: ?$`).FindAllString(r.out, -1) {
		l := strings.ToLower(prompt)
		for _, w := range []string{"access key", "accesskey", "secret", "password", "token", "credential"} {
			if strings.Contains(l, w) {
				t.Errorf("a question asks for a credential (%s): %q", w, prompt)
			}
		}
	}
	if !strings.Contains(r.out, "No key is needed here") {
		t.Errorf("it says plainly that no key is asked for:\n%s", r.out)
	}
	for _, flagName := range []string{"--access-key", "--accesskey", "--secret-key", "--secretkey", "--ak", "--sk", "--secret", "--password", "--token", "--credentials"} {
		x := run(t, "", "", "rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev", "--topics", "t", flagName, "hunter2-VERY-secret")
		if x.code == 0 {
			t.Errorf("%s was accepted", flagName)
		}
		if strings.Contains(x.out+x.err, "hunter2") {
			t.Errorf("%s: the refusal repeats the key:\n%s%s", flagName, x.out, x.err)
		}
		if raw, _ := os.ReadFile(x.path); strings.Contains(string(raw), "rocketmq:") {
			t.Errorf("%s: a target was written although the call was refused:\n%s", flagName, raw)
		}
	}
}

func TestRocketMQAddByFlagsNeedsNoQuestions(t *testing.T) {
	r := run(t, "", "", "rocketmq", "add", "--name", "m", "--namesrv", "a.example:9876,b.example", "--environment", "staging", "--topics", "t1, t2",
		"--tls", "skip-verify", "--max-messages", "5", "--max-body-bytes", "0", "--timeout", "3s")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	x, _ := load(t, r.path).RocketMQTarget("m")
	if len(x.NameServers) != 2 || x.NameServers[1] != "b.example" || len(x.Topics) != 2 || x.Topics[1] != "t2" || x.TLSMode() != "skip-verify" ||
		x.MessageLimit() != 5 || x.BodyLimit() != 0 || x.TimeoutOrDefault() != 3*time.Second {
		t.Errorf("%+v", x)
	}
	r2 := run(t, "", "", "rocketmq", "add", "--name", "plain", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	if r2.code != 0 {
		t.Fatalf("a name, a NameServer, an environment and a topic are enough: %s", r2.err)
	}
	if x, _ := load(t, r2.path).RocketMQTarget("plain"); x.BodyLimit() != 4096 || x.TLSMode() != "disable" {
		t.Errorf("a script that says nothing about the limits gets the safe ones: %+v", x)
	}
}

// A body limit of 0 written out means "no body". Leaving the flag out means the default. The two must reach the file differently.
func TestRocketMQAddTellsAZeroBodyLimitFromNoLimitGiven(t *testing.T) {
	a := run(t, "", "", "rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev", "--topics", "t", "--max-body-bytes", "0")
	b := run(t, "", "", "rocketmq", "add", "--name", "b", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	ra, _ := os.ReadFile(a.path)
	rb, _ := os.ReadFile(b.path)
	if !strings.Contains(string(ra), "max_body_bytes: 0") {
		t.Errorf("a zero that was asked for must be written, or the target would show bodies after all:\n%s", ra)
	}
	if strings.Contains(string(rb), "max_body_bytes") {
		t.Errorf("a limit that was not given must not be written:\n%s", rb)
	}
	xa, _ := load(t, a.path).RocketMQTarget("a")
	xb, _ := load(t, b.path).RocketMQTarget("b")
	if xa.BodyLimit() != 0 || xb.BodyLimit() != 4096 {
		t.Errorf("%d %d", xa.BodyLimit(), xb.BodyLimit())
	}
}

// There is no "all topics": a target without a list of topics is the one thing an agent must not be given.
func TestRocketMQAddNeedsTopicsAndHasNoAll(t *testing.T) {
	base := []string{"rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev"}
	r := run(t, "", "", base...)
	if r.code == 0 {
		t.Fatal("a target without topics was accepted")
	}
	if !strings.Contains(r.err, "--topics") {
		t.Errorf("a script that leaves the topics out is told so, and not that its input ended: %s", r.err)
	}
	// "all" is not special: it is a topic named all, and nothing here treats it as every topic
	if ok := run(t, "", "", append(append([]string{}, base...), "--topics", "all")...); ok.code != 0 {
		t.Errorf("a topic that happens to be called all is a topic: %s", ok.err)
	} else if x, _ := load(t, ok.path).RocketMQTarget("a"); !x.AllowsTopic("all") || x.AllowsTopic("orders") {
		t.Errorf("it allows the one topic and no other: %+v", x)
	}
	for _, bad := range []string{"*", "", " , ", "a b", "%RETRY%g", "%DLQ%g", "RMQ_SYS_TRANS_HALF_TOPIC", "a/b"} {
		x := run(t, "", "", append(append([]string{}, base...), "--topics", bad)...)
		if x.code == 0 {
			t.Errorf("--topics %q was accepted", bad)
		}
		if raw, _ := os.ReadFile(x.path); strings.Contains(string(raw), "rocketmq:") {
			t.Errorf("--topics %q: a refused target reached the file:\n%s", bad, raw)
		}
	}
	// guided: a blank answer to the topics question is asked again and not accepted
	g := run(t, "", "mq\nh.example\n1\n\n\norders\n1\n", "rocketmq", "add")
	if g.code != 0 || !strings.Contains(g.out, "a value is required") {
		t.Errorf("a blank list of topics is asked again: %d\n%s%s", g.code, g.out, g.err)
	}
	if x, _ := load(t, g.path).RocketMQTarget("mq"); len(x.Topics) != 1 || x.Topics[0] != "orders" {
		t.Errorf("%+v", x)
	}
}

func TestRocketMQAddChecksEveryAnswerWithTheConfigurationsOwnCheck(t *testing.T) {
	base := []string{"rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev", "--topics", "t"}
	for name, extra := range map[string][]string{
		"bad tls":           {"--tls", "maybe"},
		"messages too many": {"--max-messages", "33"},
		"messages negative": {"--max-messages", "-1"},
		"body too big":      {"--max-body-bytes", "1048577"},
		"body negative":     {"--max-body-bytes", "-1"},
		"timeout too long":  {"--timeout", "10m"},
		"unknown flag":      {"--group", "g"},
		"extra argument":    {"stray"},
	} {
		r := run(t, "", "", append(append([]string{}, base...), extra...)...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "rocketmq:") {
			t.Errorf("%s: a refused target reached the file:\n%s", name, raw)
		}
	}
	for name, args := range map[string][]string{
		"bad name":         {"rocketmq", "add", "--name", "a b", "--namesrv", "h.example", "--environment", "dev", "--topics", "t"},
		"namesrv scheme":   {"rocketmq", "add", "--name", "a", "--namesrv", "http://h.example:9876", "--environment", "dev", "--topics", "t"},
		"namesrv bad port": {"rocketmq", "add", "--name", "a", "--namesrv", "h.example:x", "--environment", "dev", "--topics", "t"},
		"namesrv empty":    {"rocketmq", "add", "--name", "a", "--namesrv", " , ", "--environment", "dev", "--topics", "t"},
		"too many namesrv": {"rocketmq", "add", "--name", "a", "--namesrv", "a1,a2,a3,a4,a5,a6,a7,a8,a9", "--environment", "dev", "--topics", "t"},
		"production":       {"rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "production", "--topics", "t"},
		"duplicate topics": {"rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev", "--topics", "t,t"},
	} {
		if r := run(t, "", "", args...); r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAWrongGuidedRocketMQAnswerIsAskedAgainWithTheReason(t *testing.T) {
	r := run(t, "", "a b\nmq\nhttp://h.example\nh.example\n1\nbad topic\norders\n1\n", "rocketmq", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	for _, want := range []string{"use 1-64 letters, digits", "no scheme, user or path", "plain topic names"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the reason %q is said:\n%s", want, r.out)
		}
	}
	if x, ok := load(t, r.path).RocketMQTarget("mq"); !ok || x.NameServers[0] != "h.example" || x.Topics[0] != "orders" {
		t.Errorf("%+v", x)
	}
}

func TestRocketMQAddReplacesATargetOfTheSameNameOnlyAfterAsking(t *testing.T) {
	args := func(ns string) []string {
		return []string{"rocketmq", "add", "--name", "m", "--namesrv", ns, "--environment", "dev", "--topics", "t"}
	}
	r := run(t, "", "", args("old.example")...)
	if r2 := run(t, r.path, "n\n", args("new.example")...); r2.code == 0 {
		t.Error("declining the replacement is not a success")
	}
	if x, _ := load(t, r.path).RocketMQTarget("m"); x.NameServers[0] != "old.example" {
		t.Errorf("replaced after the answer was no: %+v", x)
	}
	if r3 := run(t, r.path, "\n", args("new.example")...); r3.code == 0 {
		t.Error("just pressing Enter must not replace a target")
	}
	if r4 := run(t, r.path, "y\n", args("new.example")...); r4.code != 0 {
		t.Fatalf("%s", r4.err)
	}
	c := load(t, r.path)
	if x, _ := c.RocketMQTarget("m"); x.NameServers[0] != "new.example" || len(c.RocketMQ) != 1 {
		t.Errorf("%+v", c.RocketMQ)
	}
}

func TestAnInvalidRocketMQTargetIsRefusedBeforeBeingAskedWhetherToReplaceOne(t *testing.T) {
	first := run(t, "", "", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	r := run(t, first.path, "y\n", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "*")
	if r.code == 0 || strings.Contains(r.out, "already exists") {
		t.Errorf("code %d:\n%s%s", r.code, r.out, r.err)
	}
}

func TestRocketMQAddLeavesTheRestOfTheFileAsItWasAndIsIndependentOfRedis(t *testing.T) {
	first := run(t, "", "", "redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev")
	r := run(t, first.path, "", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	if c := load(t, r.path); len(c.Redis) != 1 || len(c.RocketMQ) != 1 {
		t.Errorf("%+v %+v", c.Redis, c.RocketMQ)
	}
	before, _ := os.ReadFile(first.path)
	bad := run(t, first.path, "", "rocketmq", "add", "--name", "x", "--namesrv", "h.example", "--environment", "production", "--topics", "t")
	after, _ := os.ReadFile(first.path)
	if bad.code == 0 || string(before) != string(after) {
		t.Errorf("a refused call must leave the file exactly as it was")
	}
	if x := run(t, first.path, "", "rocketmq", "remove", "m"); x.code != 0 {
		t.Fatal(x.err)
	}
	if c := load(t, first.path); len(c.Redis) != 1 || len(c.RocketMQ) != 0 {
		t.Errorf("removing one kind must not touch the other: %+v %+v", c.Redis, c.RocketMQ)
	}
}

func TestRocketMQListShowsTargetsWithTheirTopicsAndNothingSecret(t *testing.T) {
	r := run(t, "", "", "rocketmq", "add", "--name", "a", "--namesrv", "h.example", "--environment", "dev", "--topics", "orders")
	run(t, r.path, "", "rocketmq", "add", "--name", "b", "--namesrv", "x.example:9877,y.example", "--environment", "test", "--topics", "t1,t2")
	l := run(t, r.path, "", "rocketmq", "list")
	if l.code != 0 {
		t.Fatal(l.err)
	}
	lines := strings.Split(strings.TrimSpace(l.out), "\n")
	for _, h := range []string{"NAME", "ENV", "NAMESRV", "TOPICS"} {
		if !strings.Contains(lines[0], h) {
			t.Errorf("%q missing from the header: %s", h, lines[0])
		}
	}
	rows := map[string]string{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		rows[f[0]] = strings.Join(f[1:], " ")
	}
	if got := rows["a"]; got != "dev h.example:9876 orders" {
		t.Errorf("a: %q", got)
	}
	if got := rows["b"]; got != "test x.example:9877,y.example:9876 t1,t2" {
		t.Errorf("b: %q", got)
	}
	if e := run(t, "", "", "rocketmq", "list"); !strings.Contains(e.out, "rocketmq add") {
		t.Errorf("an empty list says how to add one:\n%s", e.out)
	}
}

func TestRocketMQRemoveForgetsATargetAndSaysTheKeysStayUntilItIsClosed(t *testing.T) {
	r := run(t, "", "", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	if x := run(t, r.path, "", "rocketmq", "remove", "nope"); x.code == 0 {
		t.Error("a target that does not exist")
	}
	if x := run(t, r.path, "", "rocketmq", "remove"); x.code == 0 {
		t.Error("a name is needed")
	}
	x := run(t, r.path, "", "rocketmq", "remove", "m")
	if x.code != 0 {
		t.Fatal(x.err)
	}
	if !strings.Contains(x.out, "session_close") || !strings.Contains(x.out, "rocketmq://m") {
		t.Errorf("the keys saved for it stay in the vault until it is closed:\n%s", x.out)
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "rocketmq") {
		t.Errorf("an empty rocketmq list is not left behind:\n%s", raw)
	}
}

func TestTheRocketMQCommandsHaveTheirOwnUsageAndTheMainUsageListsThem(t *testing.T) {
	for _, args := range [][]string{{"rocketmq"}, {"rocketmq", "bogus"}} {
		r := run(t, "", "", args...)
		if r.code == 0 || !strings.Contains(r.err+r.out, "rocketmq add") {
			t.Errorf("%v: %d\n%s%s", args, r.code, r.err, r.out)
		}
	}
	if u := run(t, "", "", "bogus"); !strings.Contains(u.err+u.out, "rocketmq add") {
		t.Errorf("the usage lists it:\n%s%s", u.err, u.out)
	}
}

// The note that follows a RocketMQ target says what protects it, since the real boundary is the key's own permission.
func TestRocketMQAddSaysThatAnAgentOnlyReadsAndWhatToGiveTheKey(t *testing.T) {
	r := run(t, "", guidedRMQ, "rocketmq", "add")
	for _, want := range []string{"only read messages", "topics listed here", "subscribe permission"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the note does not say %q:\n%s", want, r.out)
		}
	}
}

func TestTheEnvironmentsOfferedForRocketMQAreExactlyDevTestAndStaging(t *testing.T) {
	r := run(t, "", guidedRMQ, "rocketmq", "add")
	for _, want := range []string{"1) dev", "2) test", "3) staging"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("%q is not offered:\n%s", want, r.out)
		}
	}
	if x := run(t, "", "m\nh.example\n4\n4\n4\n", "rocketmq", "add"); x.code == 0 {
		t.Error("a choice that is not on the list was accepted")
	}
}

// A target that the configuration would refuse is not written, whatever the questions let through.
func TestAGuidedRocketMQTargetThatTheConfigurationWouldRefuseIsNotWritten(t *testing.T) {
	r := run(t, "", "m\nh.example\n1\nt\n1\n", "rocketmq", "add", "--max-messages", "99")
	if r.code == 0 {
		t.Error("accepted")
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "rocketmq:") {
		t.Errorf("a refused target reached the file:\n%s", raw)
	}
}

// A target the configuration would refuse is refused before the person is asked whether to replace the one of that name: they must
// not be made to confirm replacing something with a thing that is then refused anyway.
func TestAnInvalidRocketMQLimitIsRefusedBeforeBeingAskedWhetherToReplaceOne(t *testing.T) {
	first := run(t, "", "", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t")
	r := run(t, first.path, "y\n", "rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t", "--max-messages", "99")
	if r.code == 0 || strings.Contains(r.out, "already exists") {
		t.Errorf("code %d:\n%s%s", r.code, r.out, r.err)
	}
	if x, _ := load(t, first.path).RocketMQTarget("m"); x.MessageLimit() != 20 {
		t.Errorf("the existing target changed: %+v", x)
	}
}

// A line that contains a percent sign is not a format: the topics the broker keeps for itself are named in a note, and the note must
// come out as written. (It once came out as "%!R(MISSING)ETRY%!(BADWIDTH)", which no test noticed because none read the sentence.)
func TestNoNoteOfTheRocketMQCommandHoldsAFormatMistake(t *testing.T) {
	r := run(t, "", guidedRMQ, "rocketmq", "add")
	for _, bad := range []string{"%!", "(MISSING)", "(BADWIDTH)", "(EXTRA", "(BADPREC)", "(NOVERB)"} {
		if strings.Contains(r.out, bad) {
			t.Errorf("a format mistake in the output (%s):\n%s", bad, r.out)
		}
	}
	for _, want := range []string{"RMQ_SYS_*", "%RETRY%*", "%DLQ%*"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the note names %q as it is written:\n%s", want, r.out)
		}
	}
}

func TestNoOutputOfAnyConfigCommandHoldsAFormatMistake(t *testing.T) {
	for _, args := range [][]string{
		{"rocketmq", "add", "--name", "m", "--namesrv", "h.example", "--environment", "dev", "--topics", "t"},
		{"redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev"},
		{"redis", "add", "--name", "c", "--host", "h.example", "--environment", "dev", "--mode", "read_write", "--yes-allow-writes"},
		{"dingtalk", "group", "add", "--name", "g"},
		{"telegram", "add", "--name", "b", "--chat", "c=1"},
	} {
		r := run(t, "", "", args...)
		for _, bad := range []string{"%!", "(MISSING)", "(BADWIDTH)", "(EXTRA"} {
			if strings.Contains(r.out+r.err, bad) {
				t.Errorf("%v: a format mistake (%s):\n%s%s", args, bad, r.out, r.err)
			}
		}
	}
}
