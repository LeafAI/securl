package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A workflow that does not say what its token may do gets the repository's default, which can be read and write. CodeQL
// reports that as actions/missing-workflow-permissions (alerts 1 and 7 were the two jobs of ci.yml). Every workflow here
// declares a least-privilege token, and a job that needs more says so on that job only.

type anyWorkflow struct {
	Permissions any `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions any `yaml:"permissions"`
	} `yaml:"jobs"`
}

func allWorkflows(t *testing.T) map[string]anyWorkflow {
	t.Helper()
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	out := map[string]anyWorkflow{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var w anyWorkflow
		if err := yaml.Unmarshal(b, &w); err != nil {
			t.Fatalf("%s is not valid YAML: %v", f, err)
		}
		out[f] = w
	}
	return out
}

// permissionsOf reads a permissions block as scope -> level. A bare "read-all" / "write-all" string is returned under
// the scope "*".
func permissionsOf(p any) map[string]string {
	switch v := p.(type) {
	case map[string]any:
		m := map[string]string{}
		for k, x := range v {
			m[k], _ = x.(string)
		}
		return m
	case string:
		return map[string]string{"*": v}
	}
	return nil
}

func TestEveryWorkflowDeclaresItsTokenPermissions(t *testing.T) {
	for f, w := range allWorkflows(t) {
		top := permissionsOf(w.Permissions)
		if top != nil {
			continue
		}
		// Without a workflow-level block, every job must carry its own.
		for name, j := range w.Jobs {
			if permissionsOf(j.Permissions) == nil {
				t.Errorf("%s: job %q has no permissions and the workflow has none: it gets the repository default", f, name)
			}
		}
	}
}

func TestNoWorkflowGrantsMoreThanItNeeds(t *testing.T) {
	// What each workflow is allowed to write, and where. Anything else is read-only.
	allowed := map[string]map[string][]string{
		".github/workflows/pages.yml":   {"": {"pages", "id-token"}},
		".github/workflows/nightly.yml": {"publish": {"contents"}},
		// CodeQL uploads its results as code scanning alerts, which needs security-events: write on the analyze job.
		".github/workflows/codeql.yml": {"analyze": {"security-events"}},
	}
	for f, w := range allWorkflows(t) {
		check := func(where string, p map[string]string) {
			var writes []string
			for scope, level := range p {
				if level == "write" || level == "write-all" || level == "admin" {
					writes = append(writes, scope)
				}
			}
			sort.Strings(writes)
			ok := map[string]bool{}
			for _, s := range allowed[f][where] {
				ok[s] = true
			}
			for _, s := range writes {
				if !ok[s] {
					t.Errorf("%s (%s): %s: write is not expected for this workflow", f, strings.TrimSpace(where+" "), s)
				}
			}
		}
		check("", permissionsOf(w.Permissions))
		for name, j := range w.Jobs {
			check(name, permissionsOf(j.Permissions))
		}
		if top := permissionsOf(w.Permissions); top != nil {
			if top["*"] == "write-all" || top["*"] == "read-all" {
				t.Errorf("%s: name the scopes instead of %s", f, top["*"])
			}
		}
	}
}

// The ones that only read the repository say so in the one place that counts, the top of the file, so that a job added
// later is covered without anyone having to remember.
func TestReadOnlyWorkflowsSayContentsReadAtTheTop(t *testing.T) {
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/nightly.yml", ".github/workflows/pages.yml"} {
		w := allWorkflows(t)[f]
		if got := permissionsOf(w.Permissions)["contents"]; got != "read" {
			t.Errorf("%s: workflow-level contents permission = %q, want read", f, got)
		}
	}
}

// ---- the signing key ----
//
// The private key of the release is a secret of the environment `release-signing`, which only `master` may read. These tests hold
// the workflows to that: the key is named in one place, in the job that signs, which names the environment, and nothing that a
// pull request runs can reach it.

type keyedWorkflow struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]struct {
		If          string `yaml:"if"`
		Environment any    `yaml:"environment"`
		Steps       []struct {
			Name string            `yaml:"name"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
			With map[string]any    `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadKeyed(t *testing.T, file string) (keyedWorkflow, string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var w keyedWorkflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return w, string(b)
}

const signingSecret = "RELEASE_SIGNING_KEY"

func TestTheSigningKeyIsNamedOnlyInTheNightlyWorkflow(t *testing.T) {
	files, _ := filepath.Glob(".github/workflows/*.yml")
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), signingSecret) && f != ".github/workflows/nightly.yml" {
			t.Errorf("%s names the signing key: only the nightly workflow may", f)
		}
	}
}

func TestOnlyTheSigningJobReadsTheKeyAndItNamesTheProtectedEnvironment(t *testing.T) {
	w, _ := loadKeyed(t, ".github/workflows/nightly.yml")
	var holders []string
	for name, j := range w.Jobs {
		uses := false
		for _, s := range j.Steps {
			for _, v := range s.Env {
				if strings.Contains(v, "secrets."+signingSecret) {
					uses = true
				}
			}
			for _, v := range s.With {
				if str, ok := v.(string); ok && strings.Contains(str, signingSecret) {
					uses = true
				}
			}
			if strings.Contains(s.Run, signingSecret) {
				t.Errorf("job %s step %q puts the key into a script: pass it through env", name, s.Name)
			}
		}
		if uses {
			holders = append(holders, name)
			if env, _ := j.Environment.(string); env != "release-signing" {
				t.Errorf("job %s reads the signing key without naming the environment that protects it (environment: %v)", name, j.Environment)
			}
		}
	}
	if len(holders) != 1 || holders[0] != "sign" {
		t.Errorf("exactly one job, sign, reads the key; got %v", holders)
	}
}

func TestTheSigningJobRunsOnlyForABuildThatMayBePublished(t *testing.T) {
	w, _ := loadKeyed(t, ".github/workflows/nightly.yml")
	if got := w.Jobs["sign"].If; got != "needs.build.outputs.publish == 'true'" {
		t.Errorf("sign runs when build approved a publication, which is a master schedule or manual run and nothing else; if: %q", got)
	}
}

func TestNoJobThatRunsForAPullRequestCanReachTheKey(t *testing.T) {
	w, raw := loadKeyed(t, ".github/workflows/nightly.yml")
	if _, ok := w.On["pull_request"]; !ok {
		t.Skip("the workflow does not run for pull requests")
	}
	for name, j := range w.Jobs {
		if j.Environment == nil && name != "sign" {
			continue
		}
		// `sign` is gated: a pull request makes build say publish=false, and `sign` needs publish=true
		if name == "sign" && j.If == "needs.build.outputs.publish == 'true'" {
			continue
		}
		t.Errorf("job %s names an environment and is not gated by the decision of build", name)
	}
	// pull_request_target would run this workflow with secrets for a fork's code
	if strings.Contains(raw, "pull_request_target") {
		t.Error("pull_request_target gives a pull request's code access to secrets")
	}
	// the key is never written where a later step, or a pull request's artifact, could read it
	for _, s := range w.Jobs["sign"].Steps {
		if p, ok := s.With["path"].(string); ok && !strings.HasPrefix(p, "dist/SHA256SUMS.sig") && strings.Contains(s.Name, "") && s.Run == "" && strings.Contains(p, "key") {
			t.Errorf("step %q uploads %q, which could carry the key", s.Name, p)
		}
	}
}

func TestTheSignatureIsCheckedAgainstThePublicKeyBeforeAndAfterTheHandOver(t *testing.T) {
	w, raw := loadKeyed(t, ".github/workflows/nightly.yml")
	signs := false
	for _, s := range w.Jobs["sign"].Steps {
		signs = signs || strings.Contains(s.Run, "scripts/sign-release.sh dist keys/securl-release.pub")
	}
	if !signs {
		t.Error("the sign job must run scripts/sign-release.sh with the committed public key: it checks its own signature against it")
	}
	checked := false
	for _, s := range w.Jobs["publish"].Steps {
		checked = checked || (strings.Contains(s.Run, "ssh-keygen -Y verify") && strings.Contains(s.Run, "keys/allowed_signers"))
	}
	if !checked {
		t.Error("publish must check the signature with the committed allowed_signers before it replaces the release")
	}
	if strings.Contains(raw, "SIGNING_KEY") && strings.Contains(w.Jobs["publish"].Steps[0].Name, "SIGNING") {
		t.Error("publish must not have the key")
	}
}

func TestThePublishJobHasNoAccessToTheKey(t *testing.T) {
	w, _ := loadKeyed(t, ".github/workflows/nightly.yml")
	if w.Jobs["publish"].Environment != nil {
		t.Errorf("publish names an environment (%v): the job that can write the release must not be the job that can sign", w.Jobs["publish"].Environment)
	}
	for _, s := range w.Jobs["publish"].Steps {
		for _, v := range s.Env {
			if strings.Contains(v, "secrets.") && !strings.Contains(v, "github.token") {
				t.Errorf("publish step %q reads a secret: %s", s.Name, v)
			}
		}
	}
}

// The signature that the sign job made reaches the publish job, in the directory the scripts read it from, and it is
// checked before the release is replaced: once the old release is gone there is no taking the new one back.
func TestThePublishJobFetchesTheSignatureIntoDistAndChecksItBeforeReplacingTheRelease(t *testing.T) {
	w, _ := loadKeyed(t, ".github/workflows/nightly.yml")
	fetched, checkAt, replaceAt := false, -1, -1
	for i, s := range w.Jobs["publish"].Steps {
		if n, _ := s.With["name"].(string); n == "securl-nightly-signature" {
			fetched = true
			if p, _ := s.With["path"].(string); p != "dist" {
				t.Errorf("the signature is downloaded to %q, but the scripts read it from dist", p)
			}
		}
		if strings.Contains(s.Run, "ssh-keygen -Y verify") {
			checkAt = i
		}
		if strings.Contains(s.Run, "scripts/publish-nightly.sh") {
			replaceAt = i
		}
	}
	if !fetched {
		t.Error("publish does not download the signature that sign made")
	}
	if checkAt < 0 || replaceAt < 0 || checkAt > replaceAt {
		t.Errorf("the signature must be checked (step %d) before the release is replaced (step %d)", checkAt, replaceAt)
	}
	uploaded := ""
	for _, s := range w.Jobs["sign"].Steps {
		if n, _ := s.With["name"].(string); n == "securl-nightly-signature" {
			uploaded, _ = s.With["path"].(string)
		}
	}
	if uploaded != "dist/SHA256SUMS.sig" {
		t.Errorf("sign uploads %q under the name publish downloads; it must be the signature file", uploaded)
	}
}
