package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// capture runs fn and returns what it printed to stdout.
func capture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := fn()
	w.Close()
	os.Stdout = old
	return <-done, code
}

func TestDoctorSiteInspectsAJenkins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jenkins/login":
			w.Write([]byte(`<form name="login" action="j_acegi_security_check" method="post"></form>`))
		case "/jenkins/whoAmI/api/json":
			w.Write([]byte(`{"anonymous":true,"authenticated":true,"name":"anonymous"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	cfg := "keys: {dir: " + dir + "/keys}\nsecurity: {allow_local_addresses: true}\naliases: {\"" + host + "\": jenkins}\nroots: {\"" + host + "\": " + srv.URL + "/jenkins}\n"
	if err := os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := capture(t, func() int {
		return runDoctor([]string{"-config", filepath.Join(dir, "c.yaml"), "-site", srv.URL + "/jenkins/job/x"})
	})
	for _, want := range []string{`driver "jenkins"`, "/jenkins", "posts to j_acegi_security_check", "anonymous=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// the DingTalk webhook is not configured in this test, so the overall exit code is 1, but the site part is ok
	if strings.Contains(out, "FAIL] site") || strings.Contains(out, "FAIL] inspect") {
		t.Errorf("site inspection failed:\n%s", out)
	}
	_ = code

	// a host outside allowed_hosts is refused with the same rule the tools use
	cfg2 := strings.Replace(cfg, "security: {allow_local_addresses: true}", "security: {allow_local_addresses: true, allowed_hosts: [\"*.corp.example\"]}", 1)
	os.WriteFile(filepath.Join(dir, "d.yaml"), []byte(cfg2), 0o600)
	out, _ = capture(t, func() int {
		return runDoctor([]string{"-config", filepath.Join(dir, "d.yaml"), "-site", srv.URL})
	})
	if !strings.Contains(out, "host_not_allowed") {
		t.Errorf("allowed_hosts not enforced:\n%s", out)
	}
}

func TestDoctorReportsAuditAndLimits(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if !strings.Contains(out, "[ok  ] audit log: "+filepath.Join(dir, "audit.jsonl")) {
		t.Errorf("doctor should check the audit log:\n%s", out)
	}
	if !strings.Contains(out, "at most 3 times per site") || !strings.Contains(out, "securl config init") {
		t.Errorf("doctor should show the limits and point at `securl config init`:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Errorf("the audit file should be creatable: %v", err)
	}
}

func TestDoctorReportsTheTwoFactors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("security:\n  link_totp: {enabled: true}\n  seal_totp: {enabled: true}\n"), 0o600)
	// no vault yet: the factors can never start, which is a failure and says how to fix it
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if code == 0 || !strings.Contains(out, "[FAIL] unlock factor") || !strings.Contains(out, "[FAIL] sealing factor") {
		t.Errorf("a factor that is on with nowhere to keep its secret must fail the check (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "vault init") || !strings.Contains(out, "totp init") {
		t.Errorf("the failure should say how to fix it:\n%s", out)
	}
	// vault locked: the secrets cannot be checked, so the settings are shown and no verdict is given
	writeVaultSecrets(t, cfgPath, nil)
	out, _ = capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	for _, want := range []string{"unlock factor: on", "sealing factor: on", "10m0s", "30s", "not checked"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	// never a secret or a code
	if strings.Contains(strings.ToLower(out), "secret:") {
		t.Errorf("doctor must not print secrets:\n%s", out)
	}
}

func TestDoctorSaysNothingAboutFactorsThatAreOff(t *testing.T) {
	dir := t.TempDir()
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", filepath.Join(dir, "c.yaml")}) })
	if strings.Contains(out, "[FAIL] unlock") || strings.Contains(out, "[FAIL] sealing") {
		t.Errorf("a factor that is off must not fail:\n%s", out)
	}
	if !strings.Contains(out, "unlock factor: off") || !strings.Contains(out, "sealing factor: off") {
		t.Errorf("doctor should say that the factors are off:\n%s", out)
	}
}

func TestDoctorFailsOnAnUnknownConfigKey(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(cfgPath, []byte("security:\n  allowed_host: [\"*.corp.example\"]\n"), 0o600)
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if code != 1 || !strings.Contains(out, "[FAIL] config") || !strings.Contains(out, "allowed_hosts") {
		t.Errorf("a typo in a security key must fail the check and name the right key (exit %d):\n%s", code, out)
	}
}

func TestDoctorSiteAppliesTheLocalAddressRuleLikeTheTools(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("keys: {dir: "+dir+"/keys}\naliases: {\""+strings.TrimPrefix(srv.URL, "http://")+"\": jenkins}\n"), 0o600)
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-site", srv.URL}) })
	if !strings.Contains(out, "allow_local_addresses") || code == 0 {
		t.Errorf("doctor -site must refuse a local address and say how to allow it (exit %d):\n%s", code, out)
	}
	if hits != 0 {
		t.Errorf("the local server was contacted %d times", hits)
	}
}

func writeVaultSecrets(t *testing.T, cfgPath string, entries map[string]string) {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	if err := v.Init(doctorPass); err != nil {
		t.Fatal(err)
	}
	for k, val := range entries {
		if err := v.Put(k, []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	v.Lock()
}

const doctorPass = "correct horse battery staple"

// doctor reports the vault, and says what a running server needs: a shut vault is normal and must not be a failure.
func TestDoctorReportsTheVaultState(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if !strings.Contains(out, "vault") || !strings.Contains(out, "securl vault init") {
		t.Errorf("a missing vault is the first thing to fix, and doctor must say how:\n%s", out)
	}
	writeVaultSecrets(t, cfgPath, nil)
	out, _ = capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if !strings.Contains(out, "[ok  ] vault") || !strings.Contains(out, "locked") {
		t.Errorf("a locked vault is the normal state of a server that has not been opened:\n%s", out)
	}
	if strings.Contains(out, "[FAIL] vault") {
		t.Errorf("a locked vault is not a failure:\n%s", out)
	}
}

func TestDoctorNeverAsksForTheVaultPassphrase(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("security:\n  link_totp: {enabled: true}\n"), 0o600)
	writeVaultSecrets(t, cfgPath, nil)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if strings.Contains(strings.ToLower(out), "passphrase:") {
		t.Errorf("doctor only reports; it must not prompt:\n%s", out)
	}
	if !strings.Contains(out, "unlock factor") {
		t.Errorf("the factor is still reported:\n%s", out)
	}
	if strings.Contains(out, "[FAIL] unlock factor") {
		t.Errorf("with the vault locked the secret cannot be checked, and that is not a failure of the setup:\n%s", out)
	}
	if !strings.Contains(out, "locked") {
		t.Errorf("it should say why it could not check:\n%s", out)
	}
}

func TestDoctorFailsAFactorThatIsOnWithNoVault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("security:\n  link_totp: {enabled: true}\n"), 0o600)
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if code == 0 || !strings.Contains(out, "[FAIL] unlock factor") {
		t.Errorf("a factor that is on while no vault exists can never start:\n%s", out)
	}
}

func TestDoctorFlagsLegacySecretFiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	s, _ := totp.NewSecret()
	if err := totp.SaveSecret(filepath.Join(dir, "totp", "link.secret"), s); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	os.WriteFile(filepath.Join(dir, "keys", "aaaa.asc"), []byte("x"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if !strings.Contains(out, "plaintext") || !strings.Contains(out, "securl vault init") {
		t.Errorf("secrets left in plain files are the thing this whole change exists to remove, and doctor must say so:\n%s", out)
	}
	if strings.Contains(out, totp.FormatSecret(s)) {
		t.Error("doctor printed a secret")
	}
}

// A missing vault is a failure: the exit code is how scripts and CI notice it.
func TestDoctorFailsWithoutAVault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if code == 0 || !strings.Contains(out, "[FAIL] vault") {
		t.Errorf("no vault must be a failed check with a non-zero exit (exit %d):\n%s", code, out)
	}
	writeVaultSecrets(t, cfgPath, nil)
	out, _ = capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if strings.Contains(out, "[FAIL] vault") {
		t.Errorf("with the vault made the check passes:\n%s", out)
	}
}

// Each kind of file that an earlier version left must be noticed on its own, and the check fails.
func TestDoctorNoticesEachKindOfLegacyFile(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"link TOTP secret": func(t *testing.T, dir string) {
			s, _ := totp.NewSecret()
			totp.SaveSecret(filepath.Join(dir, "totp", "link.secret"), s)
		},
		"seal TOTP secret": func(t *testing.T, dir string) {
			s, _ := totp.NewSecret()
			totp.SaveSecret(filepath.Join(dir, "totp", "seal.secret"), s)
		},
		"session data": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "sessions"), 0o700)
			os.WriteFile(filepath.Join(dir, "sessions", "sessions.enc"), []byte("x"), 0o600)
		},
		"session key": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "sessions"), 0o700)
			os.WriteFile(filepath.Join(dir, "sessions", "sessions.key"), []byte("x"), 0o600)
		},
		"transport key": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
			os.WriteFile(filepath.Join(dir, "keys", "aaaa.asc"), []byte("x"), 0o600)
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "c.yaml")
			os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
			writeVaultSecrets(t, cfgPath, nil) // a vault exists, so this is the only thing that can fail
			plant(t, dir)
			out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
			if code == 0 || !strings.Contains(out, "[FAIL] plaintext secrets") {
				t.Errorf("a leftover %s must fail the check (exit %d):\n%s", name, code, out)
			}
		})
	}
	// and with nothing left behind, the check is silent
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	writeVaultSecrets(t, cfgPath, nil)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if strings.Contains(out, "plaintext secrets") {
		t.Errorf("nothing was left behind:\n%s", out)
	}
}

func TestDoctorIgnoresFilesInTheKeyDirectoryThatAreNotKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	writeVaultSecrets(t, cfgPath, nil)
	os.MkdirAll(filepath.Join(dir, "keys", "x.asc"), 0o700) // a directory named like a key
	os.WriteFile(filepath.Join(dir, "keys", "notes.txt"), []byte("mine"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if strings.Contains(out, "plaintext secrets") {
		t.Errorf("only login's own key files count:\n%s", out)
	}
}

func TestDoctorSaysHowTheLinkReachesThePerson(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg      string
		wantCode bool // a non-zero exit
		want     string
	}{
		"no robot, no switch": {"limits: {per_site: 3}\n", true, "[FAIL] dingtalk webhook"},
		"no robot, switch on": {"security: {link_via_agent: true}\n", false, "link_via_agent is on"},
		"a robot":             {"dingtalk: {webhook: \"https://oapi.dingtalk.com/robot/send?access_token=abc\"}\n", false, "[ok  ] dingtalk webhook: configured"},
	} {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.yaml")
		os.WriteFile(p, []byte(tc.cfg), 0o600)
		out, _ := capture(t, func() int { return runDoctor([]string{"-config", p}) })
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: output lacks %q:\n%s", name, tc.want, out)
		}
		if tc.wantCode && !strings.Contains(out, "securl config init") {
			t.Errorf("%s: the failure must say how to fix it:\n%s", name, out)
		}
		if !tc.wantCode && strings.Contains(out, "FAIL] dingtalk webhook") {
			t.Errorf("%s: this setup is fine:\n%s", name, out)
		}
	}
}

func TestDoctorSaysNothingAboutTelegramWhenNoneIsConfigured(t *testing.T) {
	// t.TempDir() is named after the test, which has the word in it, so the paths are taken out before the output is searched
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	out = strings.ReplaceAll(out, dir, "<dir>")
	if strings.Contains(strings.ToLower(out), "telegram") {
		t.Errorf("a setup with no bot has nothing to say about Telegram:\n%s", out)
	}
}

func TestDoctorReportsEachTelegramBotByNameAndNeverAChatIdOrAToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("telegram:\n  proxy: http://user:pa55word@127.0.0.1:1080\n  bots:\n    - name: ops\n      chats:\n        - {name: alerts, chat_id: -1001234567890}\n        - {name: me, chat_id: 123456789, send: false}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	for _, want := range []string{"telegram bot ops", "2 chats", "1 can be sent to", "127.0.0.1:1080"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"pa55word", "-1001234567890", "123456789", "AAH"} {
		if strings.Contains(out, secret) {
			t.Errorf("doctor prints %q:\n%s", secret, out)
		}
	}
}

// -telegram checks that api.telegram.org can be reached the way securl will reach it (through the proxy, if one is set). It needs
// no token: doctor never asks for the vault passphrase, so it cannot check one, and says so.
func TestDoctorTelegramChecksReachabilityThroughTheProxyAndSaysItCannotCheckTheToken(t *testing.T) {
	var viaProxy int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy++
		w.WriteHeader(404) // Telegram answers 404 to a path it does not know, and that is an answer: the host is reachable
		w.Write([]byte(`{"ok":false,"error_code":404,"description":"Not Found"}`))
	}))
	defer proxy.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("security: {allow_local_addresses: true}\ntelegram:\n  proxy: "+proxy.URL+"\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-telegram"}) })
	if viaProxy == 0 {
		t.Errorf("the check did not go through the proxy:\n%s", out)
	}
	if !strings.Contains(out, "[ok  ] telegram api") {
		t.Errorf("an answer from Telegram's side is reachability:\n%s", out)
	}
	// the line about reachability itself (not the bot's line, which also mentions the token) says what is and is not checked
	var reach string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "telegram api") {
			reach = l
		}
	}
	if !strings.Contains(reach, "token") || !strings.Contains(reach, "unlock") || !strings.Contains(reach, "session_open telegram://") {
		t.Errorf("the reachability line says that the token is checked when a person logs in, not here, and how:\n%s", reach)
	}
}

func TestDoctorTelegramFailsAndSaysWhatToDoWhenTheProxyIsDown(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	addr := dead.URL
	dead.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("security: {allow_local_addresses: true}\ntelegram:\n  proxy: http://user:pa55word@"+strings.TrimPrefix(addr, "http://")+"\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n"), 0o600)
	out, code := capture(t, func() int { return runDoctor([]string{"-config", cfgPath, "-telegram"}) })
	if code == 0 || !strings.Contains(out, "[FAIL] telegram api") {
		t.Errorf("a proxy that is down is a failure (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "telegram.proxy") {
		t.Errorf("it names the setting:\n%s", out)
	}
	if strings.Contains(out, "pa55word") {
		t.Errorf("the proxy's credential is printed:\n%s", out)
	}
}

func TestDoctorWithoutTheTelegramFlagMakesNoRequestToTelegram(t *testing.T) {
	var hits int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer proxy.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("telegram:\n  proxy: "+proxy.URL+"\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n"), 0o600)
	capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if hits != 0 {
		t.Errorf("doctor without -telegram reached out %d times", hits)
	}
}
