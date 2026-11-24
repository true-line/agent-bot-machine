package members

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/target"
)

func planSaveTestOps() savedPlanIO {
	return savedPlanIO{
		createTemp: os.CreateTemp,
		write:      func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		syncFile:   syncSavedPlanFile,
		close:      func(f *os.File) error { return f.Close() },
		rename:     os.Rename,
		syncDir:    syncSavedPlanDirectory,
	}
}

func TestSavedPlanFlushesNewDirectoriesAndRenamedFile(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "members", "plans")
	s := Saved{PlanID: "plan-20261124T010000Z-abcd"}
	ops := planSaveTestOps()
	var stages []string
	realSyncDir := ops.syncDir
	ops.syncDir = func(path string) error {
		stages = append(stages, "dir:"+path)
		return realSyncDir(path)
	}
	realSyncFile := ops.syncFile
	ops.syncFile = func(f *os.File) error {
		stages = append(stages, "file")
		return realSyncFile(f)
	}
	realClose := ops.close
	ops.close = func(f *os.File) error {
		stages = append(stages, "close")
		return realClose(f)
	}
	realRename := ops.rename
	ops.rename = func(old, new string) error {
		stages = append(stages, "rename")
		return realRename(old, new)
	}
	if err := saveWith(dir, s, ops); err != nil {
		t.Fatal(err)
	}
	var want []string
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		want = append(want, "dir:"+parent)
		if filepath.Dir(parent) == parent {
			break
		}
	}
	want = append(want, "file", "close", "rename", "dir:"+dir)
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("durability stages = %q, want %q", stages, want)
	}
	file := filepath.Join(dir, s.PlanID+".json")
	raw, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(raw), `"plan_id": "`+s.PlanID+`"`) {
		t.Fatalf("saved plan readback: %q, %v", raw, err)
	}
	if info, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("saved plan private mode: %v, %v", info, err)
	}
}

func TestSavedPlanRefusesFailedWriteBarriers(t *testing.T) {
	refused := errors.New("injected plan save failure")
	for _, stage := range []string{"create", "write", "short write", "file sync", "close", "rename", "directory sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			s := Saved{PlanID: "plan-20261124T010000Z-abcd"}
			ops := planSaveTestOps()
			switch stage {
			case "create":
				ops.createTemp = func(string, string) (*os.File, error) { return nil, refused }
			case "write":
				ops.write = func(*os.File, []byte) (int, error) { return 0, refused }
			case "short write":
				ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
			case "file sync":
				ops.syncFile = func(*os.File) error { return refused }
			case "close":
				ops.close = func(f *os.File) error { _ = f.Close(); return refused }
			case "rename":
				ops.rename = func(string, string) error { return refused }
			case "directory sync":
				ops.syncDir = func(string) error { return refused }
			}
			err := saveWith(dir, s, ops)
			if stage == "short write" {
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatalf("short write = %v", err)
				}
			} else if !errors.Is(err, refused) {
				t.Fatalf("%s = %v", stage, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".plan-") {
					t.Fatalf("temporary plan remains after %s", stage)
				}
			}
			if stage != "directory sync" {
				if _, err := os.Stat(filepath.Join(dir, s.PlanID+".json")); !os.IsNotExist(err) {
					t.Fatalf("failed %s exposed final plan: %v", stage, err)
				}
			}
		})
	}
}

func TestSavedPlanRefusesUnflushedNewDirectory(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "members", "plans")
	ops := planSaveTestOps()
	refused := errors.New("injected parent directory sync failure")
	ops.syncDir = func(string) error { return refused }
	s := Saved{PlanID: "plan-20261124T010000Z-abcd"}
	if err := saveWith(dir, s, ops); !errors.Is(err, refused) {
		t.Fatalf("new directory barrier = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, s.PlanID+".json")); !os.IsNotExist(err) {
		t.Fatalf("unflushed directory exposed a saved plan: %v", err)
	}
}

func TestSavedPlanRetryRepeatsFailedParentBarrier(t *testing.T) {
	refused := errors.New("injected parent directory sync failure")
	for _, name := range []string{"state", "members"} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			dir := filepath.Join(state, "members", "plans")
			failedAt := state
			if name == "members" {
				failedAt = filepath.Join(state, "members")
			}
			s := Saved{PlanID: "plan-20261124T010000Z-abcd"}
			ops := planSaveTestOps()
			realSyncDir := ops.syncDir
			failed := false
			ops.syncDir = func(path string) error {
				if path == failedAt && !failed {
					failed = true
					return refused
				}
				return realSyncDir(path)
			}
			if err := saveWith(dir, s, ops); !errors.Is(err, refused) {
				t.Fatalf("first save = %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, s.PlanID+".json")); !os.IsNotExist(err) {
				t.Fatalf("failed parent barrier exposed final plan: %v", err)
			}
			var retried []string
			ops.syncDir = func(path string) error {
				retried = append(retried, path)
				return realSyncDir(path)
			}
			if err := saveWith(dir, s, ops); err != nil {
				t.Fatalf("retry = %v", err)
			}
			if !containsPlanDir(retried, failedAt) {
				t.Fatalf("retry skipped failed parent %q: %q", failedAt, retried)
			}
		})
	}
}

func containsPlanDir(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}

func TestMembersPlanDoesNotReportAnUnsavedID(t *testing.T) {
	d, state := deps(t, bare())
	blocked := filepath.Join(state, "blocked")
	if err := os.WriteFile(blocked, []byte("file, not directory"), 0600); err != nil {
		t.Fatal(err)
	}
	d.StateDir = func() (string, error) { return blocked, nil }
	res := Command(d).Run(on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-lead"})
	if res.Diagnostic == nil || len(res.Records) != 0 {
		t.Fatalf("unsaved plan was reported: %+v", res)
	}
}
