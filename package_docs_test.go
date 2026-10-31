package main

import (
	"os"
	"strings"
	"testing"
)

func packageDocs(t *testing.T, check func(*testing.T, string)) {
	t.Helper()
	for _, path := range []string{"README.md", skillFile} {
		t.Run(path, func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			check(t, strings.Join(strings.Fields(string(b)), " "))
		})
	}
}

func requireDocTerms(t *testing.T, text string, terms ...string) {
	t.Helper()
	for _, term := range terms {
		if !strings.Contains(text, term) {
			t.Errorf("documentation missing %q", term)
		}
	}
}

func TestLinuxPackageDocsTeachBuildInstallAndArchitectures(t *testing.T) {
	packageDocs(t, func(t *testing.T, s string) {
		requireDocTerms(t, s,
			"make deb VERSION=0.1.0 DEB_ARCH=amd64", "sudo apt install ./dist/securl_0.1.0_amd64.deb",
			"make rpm VERSION=0.1.0 RPM_ARCH=x86_64", "sudo dnf install ./dist/securl-0.1.0-1.x86_64.rpm",
			"DEB_ARCH=arm64", "RPM_ARCH=aarch64", "RPM_RELEASE", "DIST", "dpkg-deb", "rpm-build",
			"Amazon Linux 2023", "not published", "build", "install")
	})
}

func TestLinuxPackageDocsExplainUserServiceAndLifecycle(t *testing.T) {
	packageDocs(t, func(t *testing.T, s string) {
		requireDocTerms(t, s,
			"systemctl --user status securl --no-pager", "journalctl --user -u securl -n 50 --no-pager",
			"systemctl --user restart securl", "systemctl --user stop securl", "sudo systemctl --user",
			"No medium found", "without sudo", "not_initialized", "securl vault init", "securl config init",
			"securl unlock", "user data", "uninstall", "locked", "systemd is not running", "vault.idle_lock")
	})
}

func TestDocsDistinguishMcpLifetimeFromCliDaemon(t *testing.T) {
	packageDocs(t, func(t *testing.T, s string) {
		requireDocTerms(t, s,
			`"mcpServers"`, `"command": "/usr/bin/securl"`, "contexts server add securl -- /usr/bin/securl",
			"contexts exec", "fresh", "persistent", "does not", "CLI daemon",
			"securl archery instances --url https://archery.corp.example",
			"--instance '<instance>'", "isError", "never", "password")
	})
}
