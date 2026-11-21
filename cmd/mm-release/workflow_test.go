package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type workflowDoc struct {
	Name        string                 `yaml:"name"`
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Concurrency struct {
		Group  string `yaml:"group"`
		Cancel bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Name        string            `yaml:"name"`
	Uses        string            `yaml:"uses"`
	Needs       any               `yaml:"needs"`
	If          string            `yaml:"if"`
	RunsOn      string            `yaml:"runs-on"`
	Environment string            `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	If   string            `yaml:"if"`
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

// Count references in parsed YAML, including expressions outside job steps.
// Counting the context name covers both dot access and bracket notation.
var secretContext = regexp.MustCompile(`(?i)\bsecrets\b`)

func workflowSecretReferences(node *yaml.Node) int {
	if node.Kind == yaml.ScalarNode {
		return len(secretContext.FindAllStringIndex(node.Value, -1))
	}
	n := 0
	for _, child := range node.Content {
		n += workflowSecretReferences(child)
	}
	return n
}

func TestWorkflowsContractAndPermissions(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	wfDir := filepath.Join(repoRoot, ".github", "workflows")
	ents, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("read workflows dir: %v", err)
	}

	// Signing credentials belong to Sign. Only the two release-PR workflows
	// can pass the chores App credentials to its pinned token action.
	for _, e := range ents {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		p := filepath.Join(wfDir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		text := string(raw)
		if strings.Contains(text, "pull_request_target") {
			t.Errorf("%s contains forbidden pull_request_target trigger", e.Name())
		}
		var tree yaml.Node
		if err := yaml.Unmarshal(raw, &tree); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		var allowed int
		switch e.Name() {
		case "sign.yml":
			allowed = 5 // TestSignWorkflowContract checks each reference and its location.
		case "version-cut.yml", "prepare-release.yml":
			var doc workflowDoc
			if err := tree.Decode(&doc); err != nil {
				t.Fatal(err)
			}
			for _, job := range doc.Jobs {
				for _, step := range job.Steps {
					if step.Uses != "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510" {
						continue
					}
					if step.With["client-id"] != "${{ secrets.CHORES_DUMB_CLIENT_ID }}" ||
						step.With["private-key"] != "${{ secrets.CHORES_DUMB_PRIVATE_KEY }}" {
						t.Errorf("%s must use the chores App credentials only as token action inputs", e.Name())
					} else {
						allowed += 2
					}
				}
			}
			if allowed == 0 {
				t.Errorf("%s does not use the pinned chores App token action", e.Name())
			}
		}
		if n := workflowSecretReferences(&tree); n != allowed {
			t.Errorf("%s has %d secret references, want %d at their approved inputs", e.Name(), n, allowed)
		}
	}

	// Parse and check go-core.yml.
	goCoreRaw, err := os.ReadFile(filepath.Join(wfDir, "go-core.yml"))
	if err != nil {
		t.Fatalf("read go-core.yml: %v", err)
	}
	var goCore workflowDoc
	if err := yaml.Unmarshal(goCoreRaw, &goCore); err != nil {
		t.Fatalf("unmarshal go-core.yml: %v", err)
	}
	if _, ok := goCore.On["workflow_call"]; !ok {
		t.Errorf("go-core.yml missing on.workflow_call trigger")
	}
	if len(goCore.Permissions) != 1 || goCore.Permissions["contents"] != "read" {
		t.Errorf("go-core.yml top-level permissions = %v, want {contents: read}", goCore.Permissions)
	}
	for jobID, job := range goCore.Jobs {
		if len(job.Permissions) != 0 {
			t.Errorf("go-core.yml job %s has unexpected permissions %v", jobID, job.Permissions)
		}
		for i, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				if v, ok := step.With["persist-credentials"]; !ok || v != false {
					t.Errorf("go-core.yml job %s step %d checkout persist-credentials = %v, want false", jobID, i+1, v)
				}
			}
		}
	}
	rgJob, ok := goCore.Jobs["release-gate"]
	if !ok {
		t.Fatalf("go-core.yml missing release-gate job")
	}
	if rgJob.Name != "release-gate (${{ matrix.target }})" {
		t.Errorf("release-gate.name = %q, want %q", rgJob.Name, "release-gate (${{ matrix.target }})")
	}
	if rgJob.Needs != "build" {
		t.Errorf("release-gate.needs = %v, want build", rgJob.Needs)
	}
	var sawDistDL, sawRGUpload bool
	for _, step := range rgJob.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") && step.With["name"] == "dist" {
			sawDistDL = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "release-gate-${{ matrix.os }}-${{ matrix.arch }}" {
			sawRGUpload = true
		}
	}
	if !sawDistDL || !sawRGUpload {
		t.Errorf("release-gate artifacts: dist download=%v, release-gate upload=%v", sawDistDL, sawRGUpload)
	}
	s6Job, ok := goCore.Jobs["s6-gate"]
	if !ok {
		t.Fatalf("go-core.yml missing s6-gate job")
	}
	if s6Job.Name != "release gate (R09, P03)" {
		t.Errorf("s6-gate.name = %q, want %q", s6Job.Name, "release gate (R09, P03)")
	}
	var sawSMUpload, sawAggregateRun bool
	for _, step := range s6Job.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "support-matrix" {
			sawSMUpload = true
		}
		if strings.Contains(step.Run, "release-aggregate") && strings.Contains(step.Run, "-checksums dist/SHA256SUMS") && strings.Contains(step.Run, "-out support-matrix.md") {
			sawAggregateRun = true
		}
	}
	if !sawSMUpload || !sawAggregateRun {
		t.Errorf("s6-gate steps: support-matrix upload=%v, release-aggregate run=%v", sawSMUpload, sawAggregateRun)
	}

	// Parse and check release.yml.
	relRaw, err := os.ReadFile(filepath.Join(wfDir, "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	var rel workflowDoc
	if err := yaml.Unmarshal(relRaw, &rel); err != nil {
		t.Fatalf("unmarshal release.yml: %v", err)
	}

	// Top-level permissions: contents: read.
	if len(rel.Permissions) != 1 || rel.Permissions["contents"] != "read" {
		t.Errorf("release.yml top-level permissions = %v, want {contents: read}", rel.Permissions)
	}

	// Triggers: push.tags: ['v*'] and workflow_dispatch with inputs tag (required) and publish (boolean, default false).
	pushCfg, ok := rel.On["push"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing on.push map: %T", rel.On["push"])
	}
	tagsList, ok := pushCfg["tags"].([]any)
	if !ok || len(tagsList) != 1 || tagsList[0] != "v*" {
		t.Errorf("release.yml on.push.tags = %v, want [v*]", pushCfg["tags"])
	}

	wdCfg, ok := rel.On["workflow_dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing on.workflow_dispatch map")
	}
	inputsCfg, ok := wdCfg["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing on.workflow_dispatch.inputs map")
	}
	tagInput, ok := inputsCfg["tag"].(map[string]any)
	if !ok || tagInput["required"] != true {
		t.Errorf("release.yml workflow_dispatch.inputs.tag = %v, want required: true", inputsCfg["tag"])
	}
	pubInput, ok := inputsCfg["publish"].(map[string]any)
	if !ok || pubInput["type"] != "boolean" || pubInput["default"] != false {
		t.Errorf("release.yml workflow_dispatch.inputs.publish = %v, want type: boolean, default: false", inputsCfg["publish"])
	}

	// Job gates calls ./.github/workflows/go-core.yml with no elevated permissions.
	gatesJob, ok := rel.Jobs["gates"]
	if !ok {
		t.Fatalf("release.yml missing gates job")
	}
	if gatesJob.Uses != "./.github/workflows/go-core.yml" {
		t.Errorf("gates.uses = %q, want ./.github/workflows/go-core.yml", gatesJob.Uses)
	}
	if gatesJob.If != "" {
		t.Errorf("gates.if = %q, want empty so gates always run on workflow_dispatch", gatesJob.If)
	}
	if len(gatesJob.Permissions) != 0 {
		t.Errorf("gates.permissions = %v, want empty (inherits contents: read)", gatesJob.Permissions)
	}

	// Job publish is the only job with permissions: contents: write.
	pubJob, ok := rel.Jobs["publish"]
	if !ok {
		t.Fatalf("release.yml missing publish job")
	}
	if pubJob.Needs != "gates" {
		t.Errorf("publish.needs = %v, want gates", pubJob.Needs)
	}
	if pubJob.RunsOn != "macos-15" {
		t.Errorf("publish.runs-on = %q, want macos-15", pubJob.RunsOn)
	}
	if len(pubJob.Permissions) != 1 || pubJob.Permissions["contents"] != "write" {
		t.Errorf("publish.permissions = %v, want {contents: write}", pubJob.Permissions)
	}
	if len(rel.Jobs) != 2 {
		t.Errorf("release.yml has %d jobs, want 2 (gates, publish)", len(rel.Jobs))
	}

	var (
		sawCheckout        bool
		sawDistDownload    bool
		sawGateDownload    bool
		sawMatrix          bool
		sawTagVerifyStep   bool
		sawSignedVerify    bool
		sawDraftSnapshot   bool
		sawPublicPublisher bool
		sawPublishedDraft  bool
	)
	const wantSignedVerify = `go run ./cmd/mm-release verify-signed -unsigned dist -signed signed -team Z5DM34QS5U -require-keyd -formula Formula/managed-machine.rb -require-pin`
	const wantPublish = `gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID" -F draft=false`
	for i, step := range pubJob.Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			sawCheckout = true
			if v, ok := step.With["persist-credentials"]; !ok || v != false {
				t.Errorf("publish step %d checkout persist-credentials = %v, want false", i+1, v)
			}
		}
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			switch {
			case step.With["name"] == "dist":
				sawDistDownload = true
			case step.With["pattern"] == "release-gate-*":
				sawGateDownload = true
			case step.With["name"] == "support-matrix":
				sawMatrix = true
			}
		}
		if strings.Contains(step.Run, "git tag --points-at HEAD") &&
			strings.Contains(step.Run, "v$(cat VERSION)") &&
			strings.Contains(step.Run, "mm-release verify -dist dist") {
			sawTagVerifyStep = true
		}
		if strings.Contains(step.Run, "verify-public-draft.py downloaded") {
			sawDraftSnapshot = true
		}
		if strings.Contains(step.Run, "verify-public-darwin-publisher --archive") {
			if !sawSignedVerify || !sawDraftSnapshot {
				t.Fatal("public publisher check must use the downloaded, verified release")
			}
			sawPublicPublisher = true
		}
		if strings.Contains(step.Run, wantSignedVerify) {
			sawSignedVerify = true
			if !strings.Contains(step.Run, `-darwin-gate release-gate-darwin-arm64.json -source-revision "$GITHUB_SHA" >> support-matrix.md`) {
				t.Errorf("signed distribution verification must link the native gate to the published download in the support matrix")
			}
		}
		if strings.Contains(step.Run, "generate-notes") {
			t.Fatal("public release notes must come from validated release data")
		}
		if strings.Contains(step.Run, wantPublish) {
			check := strings.Index(step.Run, `verify-public-draft.py publish "${TAG#v}" "$RUNNER_TEMP/public-assets.json" > "$RUNNER_TEMP/public-release-notes.md"`)
			if !strings.Contains(step.Run, wantPublish+` -f name="$TAG" -F "body=@$RUNNER_TEMP/public-release-notes.md"`) {
				t.Fatal("publish must attach the release notes from the final asset verification")
			}
			if !sawPublicPublisher || check < 0 || check >= strings.Index(step.Run, wantPublish) {
				t.Fatal("publishing requires the embedded public publishers and current draft inventory")
			}
			sawPublishedDraft = true
			if step.Env["GH_TOKEN"] != "${{ github.token }}" {
				t.Errorf("publish step GH_TOKEN = %q, want ${{ github.token }}", step.Env["GH_TOKEN"])
			}
		}
		if strings.Contains(step.Run, "gh release create") {
			t.Errorf("publish step %d creates a release; it must publish the signed draft", i+1)
		}
	}
	if !sawCheckout {
		t.Errorf("publish job missing actions/checkout step")
	}
	if !sawDistDownload || !sawGateDownload || !sawMatrix {
		t.Errorf("publish job artifact downloads: dist=%v release-gate=%v support-matrix=%v",
			sawDistDownload, sawGateDownload, sawMatrix)
	}
	if !sawTagVerifyStep {
		t.Errorf("publish job missing tag + mm-release verify -dist dist step")
	}
	if !sawSignedVerify {
		t.Errorf("publish job missing exact %q invocation", wantSignedVerify)
	}
	if !sawPublishedDraft {
		t.Errorf("publish job missing exact %q invocation", wantPublish)
	}
}

// Exercise the real draft checks with disposable CLI responses. GitHub's
// pending-tag lookup can succeed when the REST published-tag route returns 404.
func TestPendingReleaseDraftLookup(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable", tool)
		}
	}
	root, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc workflowDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	job := doc.Jobs["publish"]
	if job.Concurrency.Group != "release-publish-${{ inputs.tag || github.ref_name }}" || job.Concurrency.Cancel {
		t.Fatal("manual and pushed publishes must serialize by release tag")
	}
	steps := map[string]string{}
	for _, item := range job.Steps {
		steps[item.Name] = item.Run
	}
	const lookup = "Identify the signed draft"
	const publish = "Publish the signed draft"
	for _, name := range []string{lookup, publish} {
		if steps[name] == "" {
			t.Fatalf("missing step %s", name)
		}
	}
	const gh = `#!/bin/bash
set -eu
case "$*" in
	'release view v1.2.3 --repo org/project --json databaseId --jq .databaseId')
		test "$LOOKUP" != missing || exit 1
		echo "$LOOKUP" ;;
	'api repos/org/project/commits/v1.2.3 --jq .sha') echo "$TAG_SHA" ;;
	'api repos/org/project/releases/37')
		if [[ -e uploaded ]]; then touch rechecked; echo '{"draft":false}'
		else echo "$RECORD"; fi ;;
	'release upload v1.2.3 '*) touch uploaded ;;
	*) exit 1 ;;
esac
`
	const draft = `{"id":37,"draft":true,"tag_name":"v1.2.3","target_commitish":"reviewed-source","author":{"id":41898282,"type":"Bot"}}`
	for _, tc := range []struct {
		name, step, lookup, record, tagSHA string
		valid, upload                      bool
	}{
		{"pending draft", lookup, "37", draft, "reviewed-source", true, false},
		{"no draft found", lookup, "missing", draft, "reviewed-source", false, false},
		{"invalid release ID", lookup, "0", draft, "reviewed-source", false, false},
		{"different release", lookup, "37", strings.Replace(draft, "37", "38", 1), "reviewed-source", false, false},
		{"already published", lookup, "37", strings.Replace(draft, "true", "false", 1), "reviewed-source", false, false},
		{"human draft author", lookup, "37", strings.Replace(draft, `"Bot"`, `"User"`, 1), "reviewed-source", false, false},
		{"other bot author", lookup, "37", strings.Replace(draft, "41898282", "1000", 1), "reviewed-source", false, false},
		{"absent author on retry", publish, "37", strings.Replace(draft, `"author"`, `"other"`, 1), "reviewed-source", false, false},
		{"different tag", lookup, "37", strings.Replace(draft, "1.2.3", "1.2.4", 1), "reviewed-source", false, false},
		{"different source", lookup, "37", strings.Replace(draft, "reviewed-source", "other-source", 1), "reviewed-source", false, false},
		{"published before upload", publish, "37", strings.Replace(draft, "true", "false", 1), "reviewed-source", false, false},
		{"replaced before upload", publish, "38", draft, "reviewed-source", false, false},
		{"tag moved before upload", publish, "37", draft, "other-source", false, false},
		{"published after upload", publish, "37", draft, "reviewed-source", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "scripts"), 0700); err != nil {
				t.Fatal(err)
			}
			guard, err := os.ReadFile(filepath.Join(root, "scripts", "verify-release-draft"))
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"scripts/verify-release-draft": string(guard), "VERSION": "1.2.3\n", "gh": gh, "git": "#!/bin/bash\ntest \"$*\" = 'rev-parse HEAD' && echo reviewed-source\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			envFile := filepath.Join(dir, "github-env")
			cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", steps[tc.step])
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GITHUB_ENV="+envFile, "GITHUB_REPOSITORY=org/project", "RELEASE_ID=37", "RUNNER_TEMP="+dir,
				"LOOKUP="+tc.lookup, "RECORD="+tc.record, "TAG_SHA="+tc.tagSHA)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.valid {
				t.Fatalf("success = %t, want %t: %s", err == nil, tc.valid, output)
			}
			_, err = os.Stat(filepath.Join(dir, "uploaded"))
			if (err == nil) != tc.upload {
				t.Fatalf("metadata upload = %t, want %t", err == nil, tc.upload)
			}
			if tc.upload {
				if _, err := os.Stat(filepath.Join(dir, "rechecked")); err != nil {
					t.Fatal("published draft was not rechecked after upload")
				}
			}
			body, err := os.ReadFile(envFile)
			if tc.valid {
				if err != nil || string(body) != "RELEASE_ID=37\n" {
					t.Fatalf("unexpected workflow output %q: %v", body, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("refused step exported %q (%v)", body, err)
			}
		})
	}
}

// TestSignWorkflowContract pins the main-only jobs and both signing paths.
// Only the signer in release reads the five distribution secrets.
func TestSignWorkflowContract(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "sign.yml"))
	if err != nil {
		t.Fatalf("read sign.yml: %v", err)
	}
	var doc workflowDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal sign.yml: %v", err)
	}
	push := map[string]any{
		"branches": []any{"main"},
		"paths":    []any{"VERSION"},
	}
	if len(doc.On) != 2 || doc.On["workflow_dispatch"] == nil || !reflect.DeepEqual(doc.On["push"], push) {
		t.Errorf("sign.yml triggers = %v, want dispatch or a release request on main", doc.On)
	}
	dispatch, _ := doc.On["workflow_dispatch"].(map[string]any)
	inputs, _ := dispatch["inputs"].(map[string]any)
	if len(inputs) != 1 || inputs["version"] == nil {
		t.Fatalf("manual Machine signing takes only a release version, got %v", inputs)
	}
	if len(doc.Permissions) != 1 || doc.Permissions["contents"] != "read" {
		t.Errorf("sign.yml top-level permissions = %v, want {contents: read}", doc.Permissions)
	}
	request, exists := doc.Jobs["request"]
	readOnly := map[string]string{"actions": "read", "contents": "read", "pull-requests": "read"}
	if len(doc.Jobs) != 3 || !exists || request.Environment != "" || !reflect.DeepEqual(request.Permissions, readOnly) || request.If != "github.ref == 'refs/heads/main'" {
		t.Fatal("version and provenance must be validated read-only on main before any deployment")
	}
	manual := doc.Jobs["manual-approval"]
	if manual.Needs != "request" || manual.Environment != "release-manual" ||
		manual.If != "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'" ||
		!reflect.DeepEqual(manual.Permissions, map[string]string{"actions": "read"}) {
		t.Fatalf("unexpected manual deployment gate: %+v", manual)
	}
	if len(manual.Steps) != 1 || !strings.Contains(manual.Steps[0].Run, "actions/runs/$GITHUB_RUN_ID/approvals") ||
		!strings.Contains(manual.Steps[0].Run, `.state == "approved"`) || !strings.Contains(manual.Steps[0].Run, `.name == "release-manual"`) {
		t.Fatal("manual gate must confirm an approval for this workflow run and environment")
	}
	job, ok := doc.Jobs["sign"]
	if !ok || !reflect.DeepEqual(job.Needs, []any{"request", "manual-approval"}) || job.Environment != "release" {
		t.Fatal("the release signer must depend on version resolution and the manual gate")
	}
	const signIf = "${{ !cancelled() && github.ref == 'refs/heads/main' && needs.request.result == 'success' && " +
		"((github.event_name == 'push' && needs.manual-approval.result == 'skipped') || " +
		"(github.event_name == 'workflow_dispatch' && needs.manual-approval.result == 'success')) }}"
	if job.If != signIf {
		t.Errorf("sign.if = %q, want %q", job.If, signIf)
	}
	if len(job.Permissions) != 1 || job.Permissions["contents"] != "write" {
		t.Errorf("sign.permissions = %v, want {contents: write}", job.Permissions)
	}
	allowed := map[string]bool{
		"MACOS_DEVID_P12": true, "MACOS_DEVID_P12_PASSWORD": true,
		"NOTARY_KEY_P8": true, "NOTARY_KEY_ID": true, "NOTARY_ISSUER_ID": true,
	}
	configured, publicSigned := false, false
	seen := map[string]bool{}
	for i, step := range job.Steps {
		if strings.Contains(step.Run, "verify-public-darwin-publisher --configured") {
			configured = true
		}
		if strings.Contains(step.Run, "scripts/sign-darwin --public-release") {
			if !configured {
				t.Fatal("release signing must check publisher configuration first")
			}
			publicSigned = true
		}
		if strings.Contains(step.Run, "gh release upload") && !publicSigned {
			t.Fatal("draft asset upload requires public publisher validation")
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			if v, ok := step.With["persist-credentials"]; !ok || v != false {
				t.Errorf("sign step %d checkout persist-credentials = %v, want false", i+1, v)
			}
		}
		if strings.Contains(step.Run, "secrets.") {
			t.Errorf("sign step %d interpolates a secret into its script; pass it through env", i+1)
		}
		for _, v := range step.Env {
			if !strings.Contains(v, "secrets.") {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(v, "${{ secrets."), " }}")
			if !allowed[name] {
				t.Errorf("sign step %d reads unexpected secret %q", i+1, v)
			}
			seen[name] = true
		}
	}
	for name := range allowed {
		if !seen[name] {
			t.Errorf("sign.yml never reads %s", name)
		}
	}
	text := string(raw)
	if n := strings.Count(text, "secrets."); n != len(allowed) {
		t.Errorf("sign.yml references secrets.* %d times, want %d (one env entry each)", n, len(allowed))
	}
	for _, forbidden := range []string{
		"security create-keychain -p",
		"security unlock-keychain -p",
		"security import ",
		"security set-key-partition-list ",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("sign.yml contains forbidden command-line pattern %q", forbidden)
		}
	}
	const wantImportLine = `import "$RUNNER_TEMP/identity.p12" -k "$keychain" -P "$esc_p12" -f pkcs12 -T /usr/bin/codesign`
	var importLines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") {
			importLines = append(importLines, trimmed)
		}
	}
	if len(importLines) != 1 || importLines[0] != wantImportLine {
		t.Errorf("sign.yml security -i import lines = %q, want [%q]", importLines, wantImportLine)
	}
}

// Exercise manual signing approval against its two expected API endpoints.
// tests/version-cut.test.sh checks automatic signing against real Git history.
func TestSignPreflight(t *testing.T) {
	for _, dependency := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(dependency); err != nil {
			t.Skipf("%s unavailable", dependency)
		}
	}
	root, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "sign.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc workflowDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	steps := map[string]string{}
	for _, step := range doc.Jobs["request"].Steps {
		steps[step.If] = step.Run
	}
	const dispatch = "github.event_name == 'workflow_dispatch'"
	const receipt = "approved deployment"
	steps[receipt] = doc.Jobs["manual-approval"].Steps[0].Run
	const fixture = `api_fixture() {
	case "${!#}" in
		'repos/org/project/environments/release-manual') echo "$ENVIRONMENT" ;;
		'repos/org/project/actions/runs/15/approvals') echo "$APPROVALS" ;;
		*) return 22 ;;
	esac
}
`
	defaults := []string{
		"GITHUB_REPOSITORY=org/project", "GITHUB_RUN_ID=15",
		`ENVIRONMENT={"protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User","reviewer":{"id":42}}]}]}`,
		`APPROVALS=[{"state":"approved","environments":[{"name":"release-manual"}]}]`,
	}
	for _, tc := range []struct {
		name, step, override string
		pass                 bool
	}{
		{"configured manual gate", dispatch, "", true},
		{"unconfigured environment", dispatch, "ENVIRONMENT={}", false},
		{"empty reviewer list", dispatch, `ENVIRONMENT={"protection_rules":[{"type":"required_reviewers","reviewers":[]}]}`, false},
		{"approved manual gate", receipt, "", true},
		{"missing approval", receipt, "APPROVALS=[]", false},
		{"other environment approved", receipt, `APPROVALS=[{"state":"approved","environments":[{"name":"other"}]}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := steps[tc.step]
			if !strings.Contains(script, "gh api ") {
				t.Fatalf("missing API check for %s", tc.step)
			}
			cmd := exec.Command("bash", "-c", fixture+strings.ReplaceAll(script, "gh api ", "api_fixture "))
			cmd.Env = append(os.Environ(), defaults...)
			if tc.override != "" {
				cmd.Env = append(cmd.Env, tc.override)
			}
			if out, err := cmd.CombinedOutput(); (err == nil) != tc.pass {
				t.Fatalf("pass = %t, want %t: %s", err == nil, tc.pass, out)
			}
		})
	}
}

type workflowContext struct {
	EventName     string
	Ref           string
	InputsPublish bool
}

func TestReleasePublishJobIfExpression(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	relRaw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rel workflowDoc
	if err := yaml.Unmarshal(relRaw, &rel); err != nil {
		t.Fatal(err)
	}
	ifExpr := strings.TrimSpace(rel.Jobs["publish"].If)
	const wantExpr = "(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || (github.event_name == 'workflow_dispatch' && inputs.publish)"
	if ifExpr != wantExpr {
		t.Fatalf("publish.if = %q, want %q", ifExpr, wantExpr)
	}

	cases := []struct {
		name string
		ctx  workflowContext
		want bool
	}{
		{
			name: "workflow_dispatch with publish=false on a branch runs gates and skips publish",
			ctx:  workflowContext{EventName: "workflow_dispatch", Ref: "refs/heads/main", InputsPublish: false},
			want: false,
		},
		{
			name: "workflow_dispatch with publish=false on release branch skips publish",
			ctx:  workflowContext{EventName: "workflow_dispatch", Ref: "refs/heads/release/v0.9.0", InputsPublish: false},
			want: false,
		},
		{
			name: "workflow_dispatch with publish=false on a tag ref still skips publish (dry run)",
			ctx:  workflowContext{EventName: "workflow_dispatch", Ref: "refs/tags/v0.9.0", InputsPublish: false},
			want: false,
		},
		{
			name: "workflow_dispatch with publish=true runs publish",
			ctx:  workflowContext{EventName: "workflow_dispatch", Ref: "refs/tags/v0.9.0", InputsPublish: true},
			want: true,
		},
		{
			name: "push of v* tag runs publish",
			ctx:  workflowContext{EventName: "push", Ref: "refs/tags/v0.9.0", InputsPublish: false},
			want: true,
		},
		{
			name: "push of branch skips publish",
			ctx:  workflowContext{EventName: "push", Ref: "refs/heads/main", InputsPublish: false},
			want: false,
		},
		{
			name: "push of non-v tag skips publish",
			ctx:  workflowContext{EventName: "push", Ref: "refs/tags/test-1", InputsPublish: false},
			want: false,
		},
	}
	for _, tc := range cases {
		got := evalPublishIf(ifExpr, tc.ctx)
		if got != tc.want {
			t.Errorf("%s: eval(%q, %+v) = %v, want %v", tc.name, ifExpr, tc.ctx, got, tc.want)
		}
	}
}

// evalPublishIf evaluates the boolean workflow `if:` expression grammar used by
// jobs.publish (`||`, `&&`, parenthesized groups, `==` string comparisons,
// `startsWith(a, b)`, and boolean context `inputs.publish`).
func evalPublishIf(expr string, ctx workflowContext) bool {
	expr = strings.TrimSpace(expr)
	if parts := splitTopLevel(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalPublishIf(p, ctx) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevel(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalPublishIf(p, ctx) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && matchingOuterParens(expr) {
		return evalPublishIf(expr[1:len(expr)-1], ctx)
	}
	if strings.HasPrefix(expr, "startsWith(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("startsWith/") : len(expr)-1]
		args := splitTopLevel(inner, ",")
		if len(args) == 2 {
			return strings.HasPrefix(evalStringAtom(args[0], ctx), evalStringAtom(args[1], ctx))
		}
	}
	if lhs, rhs, ok := strings.Cut(expr, "=="); ok {
		return evalStringAtom(lhs, ctx) == evalStringAtom(rhs, ctx)
	}
	if expr == "inputs.publish" {
		return ctx.InputsPublish
	}
	return false
}

func evalStringAtom(atom string, ctx workflowContext) string {
	atom = strings.TrimSpace(atom)
	if len(atom) >= 2 && atom[0] == '\'' && atom[len(atom)-1] == '\'' {
		return atom[1 : len(atom)-1]
	}
	switch atom {
	case "github.event_name":
		return ctx.EventName
	case "github.ref":
		return ctx.Ref
	}
	return atom
}

func matchingOuterParens(s string) bool {
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				depth++
			}
		case ')':
			if !inQuote {
				depth--
				if depth == 0 && i < len(s)-1 {
					return false
				}
			}
		}
	}
	return depth == 0
}

func splitTopLevel(s, sep string) []string {
	var parts []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				depth++
			}
		case ')':
			if !inQuote {
				depth--
			}
		default:
			if !inQuote && depth == 0 && strings.HasPrefix(s[i:], sep) {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				i += len(sep) - 1
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}
