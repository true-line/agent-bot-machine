package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestVersionCutUsesTrustedWorkflowRevision(t *testing.T) {
	root, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "version-cut.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc workflowDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{
		"github.ref == 'refs/heads/main'", "github.ref_protected",
		"github.event.workflow_run.event == 'push'", "github.event.workflow_run.conclusion == 'success'",
		"github.event.workflow_run.head_branch == 'main'",
		"github.event.workflow_run.head_repository.full_name == github.repository",
	} {
		if !strings.Contains(doc.Jobs["identify"].If, condition) {
			t.Errorf("identify is missing %q", condition)
		}
	}
	for job, guard := range map[string]string{"identify": "candidate", "verify": "trusted", "tag": "trusted"} {
		steps := doc.Jobs[job].Steps
		if len(steps) < 2 || !strings.HasPrefix(steps[0].Uses, "actions/checkout@") {
			t.Fatalf("%s must start with the trusted main checkout", job)
		}
		opts := steps[0].With
		if opts["ref"] != "${{ github.sha }}" || opts["persist-credentials"] != false || opts["fetch-depth"] != 0 {
			t.Errorf("%s must check out the workflow SHA and main history without credentials", job)
		}
		if !strings.Contains(steps[1].Run, "python3 scripts/version-cut.py "+guard+" \"$CUT\"") {
			t.Errorf("%s must verify the proposed cut before consuming artifacts or minting a token", job)
		}
		for _, step := range steps[1:] {
			if strings.HasPrefix(step.Uses, "actions/checkout@") || strings.HasPrefix(step.Uses, "actions/cache@") ||
				(strings.HasPrefix(step.Uses, "actions/setup-go@") && step.With["cache"] != false) {
				t.Errorf("%s reintroduces a second checkout or shared cache: %s", job, step.Uses)
			}
		}
	}
}
