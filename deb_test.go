package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebRejectsInvalidInputsBeforeBuilding(t *testing.T) {
	for _, tc := range []struct{ version, arch string }{
		{"../escape", "amd64"}, {"nightly-20261012-abc1234", "amd64"},
		{"1.0\nInjected: yes", "amd64"}, {"1.0", "../../escape"}, {"1.0", "386"},
	} {
		t.Run(tc.version+"_"+tc.arch, func(t *testing.T) {
			cmd := exec.Command("bash", "scripts/deb.sh", t.TempDir(), tc.version, tc.arch)
			out, err := cmd.CombinedOutput()
			if err == nil || !(strings.Contains(string(out), "deb.sh: version must") || strings.Contains(string(out), "deb.sh: architecture must")) {
				t.Fatalf("invalid input must be rejected explicitly: %v\n%s", err, out)
			}
		})
	}
}

func TestMakeDebBuildsWithoutInstalling(t *testing.T) {
	out, err := exec.Command("make", "-n", "deb", "VERSION=1.2.3", "DEB_ARCH=arm64", "DIST=custom-output").CombinedOutput()
	if err != nil {
		t.Fatalf("make deb: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `bash scripts/deb.sh "custom-output" "1.2.3" "arm64"`) {
		t.Fatalf("make must forward the output directory, version and architecture: %s", out)
	}
	for _, forbidden := range []string{"sudo", "apt install", "dpkg -i", "systemctl"} {
		if strings.Contains(string(out), forbidden) {
			t.Errorf("make deb must only build, not run %q", forbidden)
		}
	}
}

func debTool(t *testing.T, path string, args ...string) []byte {
	t.Helper()
	var cmd *exec.Cmd
	if _, err := exec.LookPath("dpkg-deb"); err == nil {
		cmd = exec.Command("dpkg-deb", append(args, path)...)
	} else {
		cmd = exec.Command("docker", append([]string{"run", "--rm", "--network=none", "-v", filepath.Dir(path) + ":/packages:ro", "debian:bookworm-slim", "dpkg-deb"}, append(args, "/packages/"+filepath.Base(path))...)...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dpkg-deb %v: %v\n%s", args, err, out)
	}
	return out
}

func TestDebPackageContainsBinaryAndPerUserService(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		if _, err := exec.LookPath("docker"); err != nil {
			t.Skip("dpkg-deb or Docker is required")
		}
		if err := exec.Command("docker", "info").Run(); err != nil {
			t.Skip("Docker is not running")
		}
	}
	dir := t.TempDir()
	cmd := exec.Command("make", "deb", "DIST="+dir, "VERSION=1.2.3", "DEB_ARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make deb: %v\n%s", err, out)
	}
	pkg := filepath.Join(dir, "securl_1.2.3_amd64.deb")
	if st, err := os.Stat(pkg); err != nil || st.Size() == 0 {
		t.Fatalf("missing package: %v", err)
	}
	fields := string(debTool(t, pkg, "-f"))
	for _, want := range []string{"Package: securl", "Version: 1.2.3", "Architecture: amd64", "openssh-client", "dbus-user-session", "systemd"} {
		if !strings.Contains(fields, want) {
			t.Errorf("control file missing %q: %s", want, fields)
		}
	}
	files := string(debTool(t, pkg, "-c"))
	for _, want := range []string{"./usr/bin/securl", "./usr/lib/systemd/user/securl.service", "./usr/lib/systemd/user/default.target.wants/securl.service", "./usr/share/doc/securl/THIRD_PARTY_NOTICES.md"} {
		if !strings.Contains(files, want) {
			t.Errorf("package missing %s: %s", want, files)
		}
	}
	for _, forbidden := range []string{"./etc/securl", "config.yaml", "./root/", "./home/", "./usr/lib/systemd/system/"} {
		if strings.Contains(files, forbidden) {
			t.Errorf("package must not contain %s", forbidden)
		}
	}
}

func TestDebServiceNeverRunsAsRootOrUnlocksTheVault(t *testing.T) {
	b, err := os.ReadFile("packaging/securl.service")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"ConditionUser=!root", "ExecStart=/usr/bin/securl daemon", "Restart=on-failure", "UMask=0077", "WantedBy=default.target"} {
		if !strings.Contains(s, want) {
			t.Errorf("user unit missing %q", want)
		}
	}
	b, err = os.ReadFile("packaging/user-service.sh")
	if err != nil {
		t.Fatal(err)
	}
	s = string(b)
	for _, want := range []string{`[ "$uid" -eq 0 ]`, "runuser", "--user", "daemon-reload", "restart", "stop", "configure", "remove", "deconfigure"} {
		if !strings.Contains(s, want) {
			t.Errorf("maintainer script missing %q", want)
		}
	}
	for _, forbidden := range []string{"vault init", "vault_unlock", "securl unlock", "session close", "rm -rf", "loginctl enable-linger"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("maintainer script must not run %q", forbidden)
		}
	}
}

func debMaintainerFixture(t *testing.T, scriptName, failAction string) (string, string, []string) {
	t.Helper()
	dir := t.TempDir()
	runtime := filepath.Join(dir, "users", "1000")
	for _, path := range []string{runtime, filepath.Join(dir, "systemd"), filepath.Join(dir, "bin")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, uid := range []string{"0", "1000"} {
		path := filepath.Join(dir, "users", uid)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("unix", filepath.Join(path, "bus"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
	}
	b, err := os.ReadFile("packaging/user-service.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("/run/systemd/system", filepath.Join(dir, "systemd"), "/run/user/", filepath.Join(dir, "users")+"/").Replace(string(b))
	log := filepath.Join(dir, "calls")
	files := map[string]string{
		scriptName:    script,
		"bin/getent":  "#!/bin/sh\nprintf 'testuser:x:1000:1000::/home/testuser:/bin/sh\\n'\n",
		"bin/runuser": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALL_LOG\"\ncase \"$*\" in *\"$FAIL_ACTION securl.service\"*) [ -z \"$FAIL_ACTION\" ] || exit 1;; esac\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"), "CALL_LOG="+log, "FAIL_ACTION="+failAction)
	return filepath.Join(dir, scriptName), log, env
}

func TestDebMaintainerLifecycle(t *testing.T) {
	for _, tc := range []struct {
		script, arg, action, fail string
		wantError                 bool
	}{
		{"postinst", "configure", "restart", "", false},
		{"prerm", "remove", "stop", "", false},
		{"prerm", "deconfigure", "stop", "", false},
		{"prerm", "upgrade", "", "", false},
		{"postinst", "abort-upgrade", "", "", false},
		{"postinst", "configure", "restart", "restart", false},
		{"prerm", "remove", "stop", "stop", true},
		{"user-service", "restart", "restart", "", false},
		{"user-service", "stop", "stop", "", false},
		{"user-service", "restart", "restart", "restart", false},
		{"user-service", "stop", "stop", "stop", true},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			script, log, env := debMaintainerFixture(t, tc.script, tc.fail)
			cmd := exec.Command("sh", script, tc.arg)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected result: %v\n%s", err, out)
			}
			calls, readErr := os.ReadFile(log)
			if tc.action == "" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("no service changes expected: %s (%v)", calls, readErr)
				}
				return
			}
			if len(strings.Split(strings.TrimSpace(string(calls)), "\n")) != 2 {
				t.Fatalf("only the non-root user should be refreshed and acted on: %s", calls)
			}
			for _, want := range []string{"-u testuser -- env XDG_RUNTIME_DIR=", "systemctl --user daemon-reload", "systemctl --user " + tc.action + " securl.service"} {
				if !strings.Contains(string(calls), want) {
					t.Errorf("missing %q: %s", want, calls)
				}
			}
			if tc.fail != "" && !strings.Contains(string(out), "could not "+tc.fail) {
				t.Fatalf("failure must be reported: %s", out)
			}
		})
	}
}
