package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The release is signed: SHA256SUMS carries a signature that a user checks with the public key in the repository, so that
// what they downloaded is shown to come from the people who publish it. The checksum files alone cannot do that, because
// whoever can replace an archive can replace the checksum file next to it.

const (
	signScript     = "scripts/sign-release.sh"
	publicKeyFile  = "keys/securl-release.pub"
	allowedSigners = "keys/allowed_signers"
	signNamespace  = "securl-release"
	signIdentity   = "securl-release"
)

func signSkip(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	for _, tool := range []string{"bash", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// testKey makes a throwaway key pair in dir (never the release key) and returns the private and the public file.
func testKey(t *testing.T, dir, name string) (priv, pub string) {
	t.Helper()
	priv = filepath.Join(dir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test-"+name, "-f", priv).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return priv, priv + ".pub"
}

// signedDir is a directory that holds a SHA256SUMS over one file and its signature made with the key pair of a fresh test key.
func signedDir(t *testing.T) (dir, pub, priv string) {
	t.Helper()
	dir = t.TempDir()
	keys := t.TempDir()
	priv, pub = testKey(t, keys, "release")
	os.WriteFile(filepath.Join(dir, "securl_linux_amd64.tar.gz"), []byte("an archive"), 0o644)
	c := exec.Command("sha256sum", "securl_linux_amd64.tar.gz")
	c.Dir = dir
	sums, err := c.Output()
	if err != nil {
		c = exec.Command("shasum", "-a", "256", "securl_linux_amd64.tar.gz")
		c.Dir = dir
		if sums, err = c.Output(); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
	return dir, pub, priv
}

// sign runs the script the way CI does: with the private key in a file.
func sign(t *testing.T, dir, pub, priv string, extraEnv ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("bash", signScript, dir, pub)
	cmd.Env = append(os.Environ(), append([]string{"SIGNING_KEY_FILE=" + priv, "SSH_AUTH_SOCK="}, extraEnv...)...)
	return cmd.CombinedOutput()
}

func signersFor(t *testing.T, pub string) string {
	t.Helper()
	b, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	p := filepath.Join(t.TempDir(), "allowed_signers")
	os.WriteFile(p, []byte(signIdentity+` namespaces="`+signNamespace+`" `+f[0]+" "+f[1]+"\n"), 0o644)
	return p
}

func userVerify(t *testing.T, dir, signers, sumsPath string) error {
	t.Helper()
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", signers, "-I", signIdentity, "-n", signNamespace, "-s", filepath.Join(dir, "SHA256SUMS.sig"))
	cmd.Stdin = strings.NewReader(string(sums))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("verify: %s", out)
		return err
	}
	return nil
}

func TestSigningMakesASignatureThatTheUserCommandAccepts(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	if out, err := sign(t, dir, pub, priv); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); err != nil {
		t.Fatal("no SHA256SUMS.sig")
	}
	if err := userVerify(t, dir, signersFor(t, pub), filepath.Join(dir, "SHA256SUMS")); err != nil {
		t.Errorf("the command from the README does not accept the signature: %v", err)
	}
}

// mustBeSigned fails the test unless the signature exists. A check that "fails" because there is no signature at all would
// pass for the wrong reason, so every test of a refusal first shows that there was something to refuse.
func mustBeSigned(t *testing.T, dir string) {
	t.Helper()
	if st, err := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); err != nil || st.Size() == 0 {
		t.Fatalf("there is no signature to check: the test would pass for the wrong reason (%v)", err)
	}
}

func TestAChangedChecksumFileFailsTheUsersCheck(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	if out, err := sign(t, dir, pub, priv); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustBeSigned(t, dir)
	b, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	forged := filepath.Join(t.TempDir(), "SHA256SUMS")
	// one character of one hash is different: what an attacker who replaced the archive would have to do
	os.WriteFile(forged, []byte(strings.Replace(string(b), string(b[0]), map[bool]string{true: "1", false: "0"}[b[0] == '0'], 1)), 0o644)
	if err := userVerify(t, dir, signersFor(t, pub), forged); err == nil {
		t.Error("a changed SHA256SUMS passed the check")
	}
}

func TestASignatureMadeWithAnotherKeyFailsTheUsersCheck(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	otherPriv, otherPub := testKey(t, t.TempDir(), "other")
	_ = otherPub
	// signed by the other key, but checked against the release key
	if out, err := sign(t, dir, otherPub, otherPriv); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustBeSigned(t, dir)
	_ = priv
	if err := userVerify(t, dir, signersFor(t, pub), filepath.Join(dir, "SHA256SUMS")); err == nil {
		t.Error("a signature by another key passed the check")
	}
}

func TestASignatureForAnotherPurposeFailsTheUsersCheck(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	// a signature of the same file under another namespace (a git commit signature has the namespace "git"): it must not do
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", priv, "-n", "git", filepath.Join(dir, "SHA256SUMS"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustBeSigned(t, dir)
	if err := userVerify(t, dir, signersFor(t, pub), filepath.Join(dir, "SHA256SUMS")); err == nil {
		t.Error("a signature made for another purpose passed as a release signature")
	}
}

func TestSigningNeverLeavesASignatureThatDoesNotVerify(t *testing.T) {
	signSkip(t)
	dir, pub, _ := signedDir(t)
	// the key given to sign is not the one whose public half is named: what a mismatch between the secret and the committed
	// public key looks like in CI
	wrongPriv, _ := testKey(t, t.TempDir(), "wrong")
	out, err := sign(t, dir, pub, wrongPriv)
	if err == nil {
		t.Fatalf("a signature that does not verify against the public key was accepted\n%s", out)
	}
	if _, serr := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); serr == nil {
		t.Error("an unverified SHA256SUMS.sig was left where it would be published")
	}
	if !strings.Contains(string(out), "does not verify") {
		t.Errorf("the failure says why:\n%s", out)
	}
}

func TestSigningRefusesChecksumsThatDoNotMatchTheFiles(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	os.WriteFile(filepath.Join(dir, "securl_linux_amd64.tar.gz"), []byte("changed after the sums were made"), 0o644)
	out, err := sign(t, dir, pub, priv)
	if err == nil {
		t.Fatalf("SHA256SUMS that does not match the archive was signed\n%s", out)
	}
	if _, serr := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); serr == nil {
		t.Error("a signature was left for sums that do not match")
	}
}

func TestSigningNeedsAKeyAndSaysSo(t *testing.T) {
	signSkip(t)
	dir, pub, _ := signedDir(t)
	cmd := exec.Command("bash", signScript, dir, pub)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=", "SIGNING_KEY_FILE=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("signed with no key\n%s", out)
	}
	if !strings.Contains(string(out), "no signing key") {
		t.Errorf("%s", out)
	}
}

func TestTheKeyFileIsNotLeftBehindOrLogged(t *testing.T) {
	signSkip(t)
	dir, pub, priv := signedDir(t)
	secret, _ := os.ReadFile(priv)
	// the script gets a temporary directory of its own, so that what is found in it is what this run left, and nothing else
	tmp := t.TempDir()
	out, err := sign(t, dir, pub, priv, "TMPDIR="+tmp, "SIGNING_KEY="+string(secret), "SIGNING_KEY_FILE=")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	body := strings.Split(strings.TrimSpace(string(secret)), "\n")
	if len(body) > 2 && strings.Contains(string(out), body[1]) {
		t.Errorf("the private key is in the output:\n%s", out)
	}
	left, _ := os.ReadDir(tmp)
	for _, f := range left {
		t.Errorf("the script left %s in its temporary directory", f.Name())
	}
}

// The key is written to a file only when it came as text, and the file is private by the time anything reads it. A wrapper
// stands in for ssh-keygen on the PATH, records the mode of the key file it is given, and then runs the real one.
func TestTheTemporaryKeyFileIsPrivateAndOnlyMadeWhenTheKeyCameAsText(t *testing.T) {
	signSkip(t)
	real, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen")
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "modes")
	wrapper := "#!/bin/sh\n" +
		"prev=\"\"; for a in \"$@\"; do if [ \"$prev\" = -f ]; then f=\"$a\"; fi; prev=\"$a\"; done\n" +
		"if [ -n \"$f\" ] && [ -f \"$f\" ]; then echo \"$(ls -l \"$f\" | cut -c1-10) $f\" >> " + log + "; fi\n" +
		"exec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh-keygen"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	path := "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")

	dir, pub, priv := signedDir(t)
	secret, _ := os.ReadFile(priv)
	tmp := t.TempDir()
	if out, err := sign(t, dir, pub, priv, path, "TMPDIR="+tmp); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	given, _ := os.ReadFile(log)
	for _, l := range strings.Split(strings.TrimSpace(string(given)), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.Contains(f[1], "securl-sign-key") {
			t.Errorf("a key given as a file was copied to %s before it was used", f[1])
		}
	}
	if !strings.Contains(string(given), priv) {
		t.Errorf("ssh-keygen was not given the key file itself (%s); it saw: %q", priv, string(given))
	}
	os.Remove(log)

	dir2, pub2, priv2 := signedDir(t)
	secret, _ = os.ReadFile(priv2)
	os.Remove(log)
	if out, err := sign(t, dir2, pub2, priv2, path, "TMPDIR="+tmp, "SIGNING_KEY="+string(secret), "SIGNING_KEY_FILE="); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	modes, _ := os.ReadFile(log)
	sawTemp := false
	for _, l := range strings.Split(strings.TrimSpace(string(modes)), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || !strings.Contains(f[1], "securl-sign-key") {
			continue
		}
		sawTemp = true
		if f[0] != "-rw-------" {
			t.Errorf("the temporary key file has mode %s when ssh-keygen reads it", f[0])
		}
	}
	if !sawTemp {
		t.Errorf("ssh-keygen was never given the temporary key file; it saw: %q", string(modes))
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("the temporary key file was left behind: %v", left)
	}
	_ = pub
}

func TestSigningThroughTheAgentUsesOnlyTheKeyNamedByTheFile(t *testing.T) {
	signSkip(t)
	if os.Getenv("SSH_AUTH_SOCK") == "" && os.Getenv("SECURL_TEST_AGENT") == "" {
		t.Skip("no ssh-agent")
	}
	dir, pub, _ := signedDir(t)
	cmd := exec.Command("bash", signScript, dir, pub)
	cmd.Env = append(os.Environ(), "SIGNING_KEY_FILE=", "SIGNING_KEY=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the agent has no key for this public key, yet it signed\n%s", out)
	}
	if _, serr := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); serr == nil {
		t.Error("a signature was left")
	}
}

// ---- the committed public key ----

func TestThePublicKeyInTheRepositoryIsAPublicEd25519KeyAndNothingElse(t *testing.T) {
	b, err := os.ReadFile(publicKeyFile)
	if err != nil {
		t.Fatalf("%s must exist: %v", publicKeyFile, err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "ssh-ed25519 AAAA") {
		t.Fatalf("one ssh-ed25519 public key line, got %q", string(b))
	}
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("a private key in the repository")
	}
	signSkip(t)
	out, err := exec.Command("ssh-keygen", "-l", "-f", publicKeyFile).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ED25519") {
		t.Errorf("not a readable ed25519 key: %v %s", err, out)
	}
}

func TestAllowedSignersNamesTheReleaseKeyForTheReleaseNamespaceOnly(t *testing.T) {
	pub, _ := os.ReadFile(publicKeyFile)
	f := strings.Fields(string(pub))
	b, err := os.ReadFile(allowedSigners)
	if err != nil {
		t.Fatalf("%s must exist: %v", allowedSigners, err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("one signer, got %d lines", len(lines))
	}
	want := signIdentity + ` namespaces="` + signNamespace + `" ` + f[0] + " " + f[1]
	if lines[0] != want {
		t.Errorf("allowed_signers is not exactly the release key for the release namespace:\n got  %s\n want %s", lines[0], want)
	}
}

// ---- what the documents tell a person to type ----

// The commands in the README and the skill are run here as written, against a release made with a throwaway key whose public
// half stands in for keys/allowed_signers. A command in a document that does not work is a user who cannot install.
var verifyLine = regexp.MustCompile(`ssh-keygen -Y verify -f allowed_signers -I (\S+) -n (\S+) -s SHA256SUMS\.sig < SHA256SUMS`)

func TestTheVerifyCommandInTheDocumentsIsTheOneThatAcceptsTheSignatureAndTheOneThatRefusesAForgery(t *testing.T) {
	signSkip(t)
	for _, doc := range []string{"README.md", "skills/securl/SKILL.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		m := verifyLine.FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("%s has no `ssh-keygen -Y verify -f allowed_signers ... -s SHA256SUMS.sig < SHA256SUMS` line", doc)
		}
		if m[1] != signIdentity || m[2] != signNamespace {
			t.Errorf("%s verifies identity %q namespace %q; the release is signed for %q and %q", doc, m[1], m[2], signIdentity, signNamespace)
		}
		dir, pub, priv := signedDir(t)
		if out, err := sign(t, dir, pub, priv); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		mustBeSigned(t, dir)
		copyFile(t, signersFor(t, pub), filepath.Join(dir, "allowed_signers"))
		run := func() error {
			c := exec.Command("bash", "-c", m[0])
			c.Dir = dir
			out, err := c.CombinedOutput()
			if err == nil && !strings.Contains(string(out), "Good") {
				t.Errorf("%s: the command succeeded without saying Good: %s", doc, out)
			}
			return err
		}
		if err := run(); err != nil {
			t.Errorf("%s: the documented command does not accept a good signature: %v", doc, err)
		}
		sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), append(sums, []byte("0000  forged\n")...), 0o644)
		if err := run(); err == nil {
			t.Errorf("%s: the documented command accepts a forged SHA256SUMS", doc)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A person is told where the key comes from, and the fingerprint they can compare is the real one.
func TestTheDocumentsNameTheRealKeyAndSayWhereToGetItFrom(t *testing.T) {
	out, err := exec.Command("ssh-keygen", "-lf", publicKeyFile).CombinedOutput()
	if err != nil {
		t.Skipf("ssh-keygen: %v", err)
	}
	fpr := strings.Fields(string(out))[1]
	for _, doc := range []string{"README.md", "skills/securl/SKILL.md"} {
		b, _ := os.ReadFile(doc)
		s := string(b)
		if !strings.Contains(s, fpr) {
			t.Errorf("%s does not give the fingerprint of the release key (%s)", doc, fpr)
		}
		if !strings.Contains(s, "https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers") {
			t.Errorf("%s does not say to take allowed_signers from the repository", doc)
		}
		if strings.Contains(s, "releases/download/nightly/allowed_signers") || strings.Contains(s, "releases/download/nightly/securl-release.pub") {
			t.Errorf("%s fetches the key from the release: a key that comes with the files can be replaced with them", doc)
		}
		if !strings.Contains(s, "SHA256SUMS.sig") {
			t.Errorf("%s does not mention the signature file", doc)
		}
	}
}
