//go:build darwin

package members

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aLocalTestQSourceFixedPrivatePlan(t *testing.T) {
	q, approval, _, _, digest, _ := stage2aLocalTestQApprovalFixture(t)
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := stage2aLocalTestQPlanPath(state, approval.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalStage2aReservationJCS(q)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("cannot stage Q source fixture")
	}
	read := func() error {
		got, body, gotDigest, err := stage2aLocalTestQReadPlan(state, approval.PlanID,
			uint32(os.Getuid()), uint32(os.Getgid()))
		if err != nil {
			return err
		}
		if got != q || string(body) != string(raw) || gotDigest != digest {
			t.Fatal("Q source changed during protected read")
		}
		return nil
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func() error{
		"noncanonical contents": func() error {
			return os.WriteFile(path, append(append([]byte(nil), raw...), ' '), 0600)
		},
		"symlinked source": func() error {
			if err := os.Rename(path, path+".original"); err != nil {
				return err
			}
			return os.Symlink(path+".original", path)
		},
		"world readable": func() error { return os.Chmod(path, 0644) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := change(); err != nil {
				t.Fatal(err)
			}
			if err := read(); err == nil {
				t.Fatal("modified Q source accepted")
			}
		})
	}
	if _, err := stage2aLocalTestQPlanPath(state, "../other"); err == nil {
		t.Fatal("caller-selected Q path accepted")
	}
}
