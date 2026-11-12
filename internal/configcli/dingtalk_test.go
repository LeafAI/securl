package configcli

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	dtHook   = "https://oapi.dingtalk.com/robot/send?access_token=c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	dtSecret = "SECabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
)

// The guided questions, in order: the group's name, whether its robot signs its messages, its keyword (blank: none).
const guidedGroup = "ops\n\n\n"

func TestDingTalkGroupAddGuidedWritesAGroup(t *testing.T) {
	r := run(t, "", guidedGroup, "dingtalk", "group", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	g, ok := c.DingTalkGroup("ops")
	if !ok || g.Sign || g.Keyword != "" || len(c.DingTalk.Groups) != 1 {
		t.Fatalf("%+v", c.DingTalk)
	}
	raw, _ := os.ReadFile(r.path)
	for _, def := range []string{"send_limit", "send_window", "sign: false", "keyword"} {
		if strings.Contains(string(raw), def) {
			t.Errorf("defaults are not written (%s):\n%s", def, raw)
		}
	}
	if !strings.Contains(r.out, "session_open") || !strings.Contains(r.out, "dingtalk://ops") {
		t.Errorf("the output says how the webhook is given:\n%s", r.out)
	}
}

func TestDingTalkGroupAddGuidedWithSigningAndAKeyword(t *testing.T) {
	r := run(t, "", "alerts\ny\ndeploy\n", "dingtalk", "group", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	g, _ := load(t, r.path).DingTalkGroup("alerts")
	if !g.Sign || g.Keyword != "deploy" {
		t.Errorf("%+v", g)
	}
}

// A webhook and a signing secret are pasted by a person on a page and kept in the vault: nothing here asks for one, takes one as a
// flag, or writes one.
func TestDingTalkGroupAddNeverAsksForOrTakesOrWritesAWebhookOrASecret(t *testing.T) {
	r := run(t, "", guidedGroup, "dingtalk", "group", "add")
	for _, prompt := range regexp.MustCompile(`(?m)^[^\n]*?(?:\[[^\]]*\])?: ?$`).FindAllString(r.out, -1) {
		l := strings.ToLower(prompt)
		for _, w := range []string{"webhook", "token", "password", "secret value", "address"} {
			if strings.Contains(l, w) {
				t.Errorf("a question asks for a credential (%s): %q", w, prompt)
			}
		}
	}
	if !strings.Contains(r.out, "No webhook is needed here") {
		t.Errorf("it says plainly that no webhook is asked for:\n%s", r.out)
	}
	for _, flagName := range []string{"--webhook", "--url", "--token", "--access-token", "--secret", "--sign-secret", "--password"} {
		r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops", flagName, dtHook)
		if r.code == 0 {
			t.Errorf("%s was accepted", flagName)
		}
		for _, leak := range []string{"SECRETTOKEN", dtHook, "access_token"} {
			if strings.Contains(r.out+r.err, leak) {
				t.Errorf("%s: the refusal repeats %q:\n%s%s", flagName, leak, r.out, r.err)
			}
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "groups") {
			t.Errorf("%s: a group was written although the call was refused:\n%s", flagName, raw)
		}
	}
	raw, _ := os.ReadFile(r.path)
	for _, key := range []string{"webhook", "access_token", "token", "secret:"} {
		if strings.Contains(string(raw), key) {
			t.Errorf("the file holds a credential (%s):\n%s", key, raw)
		}
	}
}

func TestDingTalkGroupAddByFlagsNeedsNoQuestions(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops", "--sign", "--keyword", "deploy", "--send-limit", "5", "--send-window", "2m")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	g, _ := load(t, r.path).DingTalkGroup("ops")
	if !g.Sign || g.Keyword != "deploy" || g.SendLimit() != 5 || g.SendWindow() != 2*time.Minute {
		t.Errorf("%+v", g)
	}
	r2 := run(t, "", "", "dingtalk", "group", "add", "--name", "plain")
	if r2.code != 0 {
		t.Fatalf("a name alone is enough: %s", r2.err)
	}
	if g, _ := load(t, r2.path).DingTalkGroup("plain"); g.Sign || g.Keyword != "" {
		t.Errorf("%+v", g)
	}
}

// Every answer is checked with the check the configuration applies when it loads, so that the questions and the file cannot disagree.
func TestDingTalkGroupAddChecksEveryAnswerWithTheConfigurationsOwnCheck(t *testing.T) {
	for name, args := range map[string][]string{
		"name with a space":   {"--name", "a b"},
		"name too long":       {"--name", strings.Repeat("a", 65)},
		"rate over 20 a min":  {"--name", "a", "--send-limit", "30"},
		"rate by window":      {"--name", "a", "--send-limit", "20", "--send-window", "30s"},
		"negative limit":      {"--name", "a", "--send-limit", "-1"},
		"window over a day":   {"--name", "a", "--send-window", "48h"},
		"keyword with a line": {"--name", "a", "--keyword", "x\ny"},
		"keyword too long":    {"--name", "a", "--keyword", strings.Repeat("k", 65)},
		"unknown flag":        {"--name", "a", "--parse-mode", "markdown"},
		"extra argument":      {"--name", "a", "stray"},
	} {
		r := run(t, "", "", append([]string{"dingtalk", "group", "add"}, args...)...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "groups") {
			t.Errorf("%s: a refused group reached the file:\n%s", name, raw)
		}
	}
}

func TestDingTalkGroupAddReplacesAGroupOfTheSameNameOnlyAfterAsking(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops")
	r2 := run(t, r.path, "n\n", "dingtalk", "group", "add", "--name", "ops", "--keyword", "new")
	if r2.code == 0 {
		t.Error("declining the replacement is not a success")
	}
	if g, _ := load(t, r.path).DingTalkGroup("ops"); g.Keyword != "" {
		t.Errorf("the group was replaced after the answer was no: %+v", g)
	}
	r3 := run(t, r.path, "y\n", "dingtalk", "group", "add", "--name", "ops", "--keyword", "new")
	if r3.code != 0 {
		t.Fatalf("%s", r3.err)
	}
	c := load(t, r.path)
	if g, _ := c.DingTalkGroup("ops"); g.Keyword != "new" || len(c.DingTalk.Groups) != 1 {
		t.Errorf("replaced: %+v", c.DingTalk.Groups)
	}
}

// The login robot is in the same section of the file and is not the group's: adding a group leaves it as it was.
func TestDingTalkGroupAddLeavesTheLoginRobotAlone(t *testing.T) {
	first := run(t, "", "", "set", "dingtalk.keyword", "login")
	if first.code != 0 {
		t.Fatal(first.err)
	}
	r := run(t, first.path, "", "dingtalk", "group", "add", "--name", "ops")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	c := load(t, r.path)
	if c.DingTalk.Keyword != "login" || len(c.DingTalk.Groups) != 1 {
		t.Errorf("%+v", c.DingTalk)
	}
	if g, _ := c.DingTalkGroup("ops"); g.Keyword != "" {
		t.Errorf("a group does not take the login robot's keyword: %+v", g)
	}
}

func TestDingTalkGroupListShowsGroupsByNameWithWhatEachNeedsAndNothingSecret(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops")
	run(t, r.path, "", "dingtalk", "group", "add", "--name", "alerts", "--sign", "--keyword", "deploy", "--send-limit", "5")
	l := run(t, r.path, "", "dingtalk", "group", "list")
	if l.code != 0 {
		t.Fatal(l.err)
	}
	for _, want := range []string{"GROUP", "SIGN", "KEYWORD", "LIMIT", "ops", "alerts", "deploy"} {
		if !strings.Contains(l.out, want) {
			t.Errorf("%q missing:\n%s", want, l.out)
		}
	}
	empty := run(t, "", "", "dingtalk", "group", "list")
	if !strings.Contains(empty.out, "dingtalk group add") {
		t.Errorf("an empty list says how to add one:\n%s", empty.out)
	}
}

func TestDingTalkGroupRemoveForgetsAGroupAndSaysTheWebhookStaysUntilItIsClosed(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops")
	if x := run(t, r.path, "", "dingtalk", "group", "remove", "nope"); x.code == 0 {
		t.Error("a group that does not exist")
	}
	if x := run(t, r.path, "", "dingtalk", "group", "remove"); x.code == 0 {
		t.Error("a name is needed")
	}
	x := run(t, r.path, "", "dingtalk", "group", "remove", "ops")
	if x.code != 0 {
		t.Fatal(x.err)
	}
	if c := load(t, r.path); len(c.DingTalk.Groups) != 0 {
		t.Errorf("%+v", c.DingTalk)
	}
	if !strings.Contains(x.out, "session_close") || !strings.Contains(x.out, "dingtalk://ops") {
		t.Errorf("a webhook saved for it stays in the vault until it is closed:\n%s", x.out)
	}
}

func TestDingTalkCommandsHaveTheirOwnUsageAndRefuseWhatTheyDoNotKnow(t *testing.T) {
	for _, args := range [][]string{{"dingtalk"}, {"dingtalk", "group"}, {"dingtalk", "bogus"}, {"dingtalk", "group", "bogus"}} {
		r := run(t, "", "", args...)
		if r.code == 0 {
			t.Errorf("%v: accepted", args)
		}
		if !strings.Contains(r.err+r.out, "dingtalk group add") {
			t.Errorf("%v: the usage names the command:\n%s%s", args, r.err, r.out)
		}
	}
	u := run(t, "", "", "bogus")
	if !strings.Contains(u.err+u.out, "dingtalk group add") {
		t.Errorf("the usage lists it:\n%s%s", u.err, u.out)
	}
}

// A wrong answer to a guided question is said and asked again, so a person is never sent away with a file the server would refuse.
func TestAWrongGuidedAnswerIsAskedAgainWithTheReason(t *testing.T) {
	r := run(t, "", "a b\nops\n\n\n", "dingtalk", "group", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	if !strings.Contains(r.out, "use 1-64 letters, digits") {
		t.Errorf("the reason is said:\n%s", r.out)
	}
	if c := load(t, r.path); len(c.DingTalk.Groups) != 1 || c.DingTalk.Groups[0].Name != "ops" {
		t.Errorf("%+v", c.DingTalk.Groups)
	}
	k := run(t, "", "ops\n\nbad\x07word\nfine\n", "dingtalk", "group", "add")
	if k.code != 0 || !strings.Contains(k.out, "one line of at most 64 characters") {
		t.Errorf("a keyword with a control character is asked again: %d\n%s%s", k.code, k.out, k.err)
	}
	if g, _ := load(t, k.path).DingTalkGroup("ops"); g.Keyword != "fine" {
		t.Errorf("%+v", g)
	}
}

// What the flags give is checked before anything is written, and a refused call leaves the file as it was.
func TestARefusedGroupLeavesTheFileExactlyAsItWas(t *testing.T) {
	first := run(t, "", "", "set", "dingtalk.keyword", "login")
	before, _ := os.ReadFile(first.path)
	r := run(t, first.path, "", "dingtalk", "group", "add", "--name", "a", "--send-limit", "30")
	if r.code == 0 {
		t.Fatal("a rate over what DingTalk allows was accepted")
	}
	if after, _ := os.ReadFile(first.path); string(after) != string(before) {
		t.Errorf("the file changed:\n%s\n---\n%s", before, after)
	}
	if _, err := os.Stat(first.path + ".bak"); err == nil {
		t.Error("a backup was made for a change that was not made")
	}
}

func TestTheListSaysWhichGroupsSignAndWhatTheirLimitIs(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "plain")
	run(t, r.path, "", "dingtalk", "group", "add", "--name", "signed", "--sign", "--send-limit", "7", "--send-window", "2m")
	l := run(t, r.path, "", "dingtalk", "group", "list")
	rows := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(l.out), "\n")[1:] {
		f := strings.Fields(line)
		rows[f[0]] = strings.Join(f[1:], " ")
	}
	if got := rows["plain"]; got != "no - 10 per 1m0s" {
		t.Errorf("plain: %q", got)
	}
	if got := rows["signed"]; got != "yes - 7 per 2m0s" {
		t.Errorf("signed: %q", got)
	}
}

func TestOnlyTheGroupWordLeadsToTheGroupCommands(t *testing.T) {
	// the second word is a real subcommand in some of these, so that it is the first word alone that decides
	for _, args := range [][]string{
		{"dingtalk", "add", "--name", "x"}, {"dingtalk", "list"}, {"dingtalk", "remove", "x"},
		{"dingtalk", "x", "add", "--name", "x"}, {"dingtalk", "add", "add", "--name", "x"}, {"dingtalk", "groups", "add", "--name", "x"},
		{"dingtalk", "list", "list"}, {"dingtalk", "Group", "add", "--name", "x"},
	} {
		r := run(t, "", "", args...)
		if r.code == 0 {
			t.Errorf("%v: accepted", args)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "groups") {
			t.Errorf("%v: wrote a group:\n%s", args, raw)
		}
	}
}

func TestReplacingIsDeclinedByDefaultSoAnAbsentAnswerKeepsTheGroup(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "ops", "--keyword", "old")
	r2 := run(t, r.path, "\n", "dingtalk", "group", "add", "--name", "ops", "--keyword", "new")
	if r2.code == 0 {
		t.Error("just pressing Enter must not replace a group")
	}
	if g, _ := load(t, r.path).DingTalkGroup("ops"); g.Keyword != "old" {
		t.Errorf("%+v", g)
	}
}

func TestASigningGroupSaysItsSecretIsAskedForOnThePage(t *testing.T) {
	r := run(t, "", "", "dingtalk", "group", "add", "--name", "a", "--sign")
	if !strings.Contains(r.out, "signing secret") {
		t.Errorf("%s", r.out)
	}
	p := run(t, "", "", "dingtalk", "group", "add", "--name", "b")
	if strings.Contains(p.out, "signing secret") {
		t.Errorf("a group that does not sign does not mention a secret:\n%s", p.out)
	}
}

// A group that cannot be saved is refused before anything else is asked: a person must not be made to confirm replacing a group with
// something that is then refused anyway.
func TestAnInvalidGroupIsRefusedBeforeBeingAskedWhetherToReplaceOne(t *testing.T) {
	first := run(t, "", "", "dingtalk", "group", "add", "--name", "ops")
	r := run(t, first.path, "y\n", "dingtalk", "group", "add", "--name", "ops", "--send-limit", "30")
	if r.code == 0 {
		t.Fatal("accepted")
	}
	if strings.Contains(r.out, "already exists") {
		t.Errorf("asked whether to replace a group with something that is invalid:\n%s", r.out)
	}
	if !strings.Contains(r.err, "20 a minute") {
		t.Errorf("the refusal says why: %q", r.err)
	}
}
