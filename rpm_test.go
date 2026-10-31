package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeRpmOnlyBuilds(t *testing.T) {
	out, err := exec.Command("make", "-n", "rpm", "VERSION=1.2.3", "RPM_ARCH=aarch64", "RPM_RELEASE=2", "DIST=custom-output").CombinedOutput()
	if err != nil {
		t.Fatalf("make rpm: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `bash scripts/rpm.sh "custom-output" "1.2.3" "aarch64" "2"`) {
		t.Fatalf("make must forward all package options: %s", out)
	}
	for _, forbidden := range []string{"sudo", "dnf install", "rpm -i", "systemctl"} {
		if strings.Contains(string(out), forbidden) {
			t.Errorf("make rpm must not run %q", forbidden)
		}
	}
}

func TestRpmRejectsInvalidInputs(t *testing.T) {
	for _, args := range [][]string{
		{"../escape", "amd64", "1"}, {"1.0\nName: bad", "amd64", "1"},
		{"1.0", "../../escape", "1"}, {"1.0", "386", "1"},
		{"1.0", "amd64", "%{lua:bad}"}, {"1.0", "amd64", "0"},
	} {
		cmd := exec.Command("bash", append([]string{"scripts/rpm.sh", t.TempDir()}, args...)...)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "rpm.sh: invalid") {
			t.Fatalf("must explicitly reject %v: %v\n%s", args, err, out)
		}
	}
}

func rpmQuery(t *testing.T, pkg string, args ...string) string {
	t.Helper()
	out, err := exec.Command("rpm", append(args, pkg)...).CombinedOutput()
	if err != nil {
		t.Fatalf("rpm %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func buildTestRpm(t *testing.T, arch, release, rpmarch string) string {
	t.Helper()
	for _, tool := range []string{"rpm", "rpmbuild"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	dir := t.TempDir()
	cmd := exec.Command("make", "rpm", "DIST="+dir, "VERSION=1.2.3", "RPM_RELEASE="+release, "RPM_ARCH="+arch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make rpm: %v\n%s", err, out)
	}
	pkg := filepath.Join(dir, "securl-1.2.3-"+release+"."+rpmarch+".rpm")
	if _, err := os.Stat(pkg); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestRpmPackageContentsAndUpgradeLifecycle(t *testing.T) {
	pkg := buildTestRpm(t, "amd64", "2", "x86_64")
	if got := rpmQuery(t, pkg, "-qp", "--queryformat", "%{NAME} %{VERSION} %{RELEASE} %{ARCH}"); got != "securl 1.2.3 2 x86_64" {
		t.Fatalf("unexpected package identity: %s", got)
	}
	files := rpmQuery(t, pkg, "-qpl")
	for _, want := range []string{"/usr/bin/securl", "/usr/lib/systemd/user/securl.service", "/usr/lib/systemd/user/default.target.wants/securl.service", "/usr/libexec/securl/user-service", "/usr/share/doc/securl/THIRD_PARTY_NOTICES.md"} {
		if !strings.Contains(files, want+"\n") {
			t.Errorf("missing %s: %s", want, files)
		}
	}
	for _, forbidden := range []string{"/etc/securl", "/home/", "/root/", "/usr/lib/systemd/system/"} {
		if strings.Contains(files, forbidden) {
			t.Errorf("must not package %s", forbidden)
		}
	}
	deps := rpmQuery(t, pkg, "-qpR")
	for _, want := range []string{"openssh-clients", "ca-certificates", "systemd", "dbus", "util-linux", "glibc-common"} {
		if !strings.Contains(deps, want) {
			t.Errorf("missing runtime dependency %s: %s", want, deps)
		}
	}
	scripts := rpmQuery(t, pkg, "-qp", "--scripts")
	for _, want := range []string{"posttrans", "/usr/libexec/securl/user-service restart", "preuninstall", `[ "$1" -eq 0 ]`, "/usr/libexec/securl/user-service stop"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("missing lifecycle guard %q: %s", want, scripts)
		}
	}
}

func TestRpmCrossBuildsArm64WithoutCrossBinutils(t *testing.T) {
	pkg := buildTestRpm(t, "arm64", "1", "aarch64")
	if got := rpmQuery(t, pkg, "-qp", "--queryformat", "%{ARCH}"); got != "aarch64" {
		t.Fatalf("wrong architecture: %s", got)
	}
}
