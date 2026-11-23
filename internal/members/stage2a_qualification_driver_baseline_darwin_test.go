package members

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage2aQualificationDriverBaselineRunsPinnedProviderAndPolicy(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("baseline driver runs only in a nonroot account")
	}
	begin := driverCaseBegin("managed-protected")
	dir := t.TempDir()
	makePin := func(name string) qualificationFile {
		t.Helper()
		path := filepath.Join(dir, name)
		data := []byte(name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return qualificationFile{Path: path, SHA256: strings.TrimPrefix(stage2aQualificationSHA256(data), "sha256:")}
	}
	review := stage2aDriverReview{testPlanSHA256: begin.TestPlanSHA256, Policy: makePin("policy")}
	provider := makePin("provider")
	a, driver := net.Pipe()
	defer a.Close()
	defer driver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := func() error { return nil }
	done := make(chan error, 1)
	go func() {
		done <- serveStage2aDriverBaseline(ctx, driver, review, provider, uid, ok)
	}()
	trace, err := exchangeStage2aDriverCases(ctx, a, begin, stage2aDriverBeforeLaunch, ok,
		func(ctx context.Context, command stage2aDriverCommand, _ string) (stage2aDriverCorroboration, error) {
			return verifyStage2aDriverBaseline(ctx, command, review, provider, uid)
		},
		func(probe stage2aQualificationObserveV1) ([]byte, error) {
			if len(probe.Paths) != 1 {
				return nil, errors.New("baseline missing reviewed path")
			}
			switch probe.Gate {
			case "T02":
				if probe.Paths[0].Path != provider.Path {
					return nil, errors.New("T02 provider pin was replaced")
				}
			case "T03":
				if probe.Paths[0].Path != review.Policy.Path {
					return nil, errors.New("T03 policy pin was replaced")
				}
			default:
				return nil, errors.New("wrong gate")
			}
			return nil, nil
		})
	if err != nil || len(trace) != 2 {
		t.Fatalf("baseline failed: %d witness pairs, %v", len(trace), err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(provider.Path, 0622); err != nil {
		t.Fatal(err)
	}
	if _, err := sampleStage2aDriverBaselineFile(provider, uid); err == nil {
		t.Fatal("writable provider pin accepted")
	}
}

func TestStage2aQualificationDriverBaselineRefusesLivePhase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, driver := net.Pipe()
	defer a.Close()
	defer driver.Close()
	begin := driverCaseBegin("managed-cooperative")
	done := make(chan error, 1)
	go func() {
		done <- serveStage2aDriverBaseline(ctx, driver, stage2aDriverReview{testPlanSHA256: begin.TestPlanSHA256},
			qualificationFile{}, 501, func() error { return nil })
	}()
	_, err := writeStage2aQualificationFrame(a, stage2aDriverCommand{
		Schema: stage2aDriverCaseSchema, Kind: "capture", Profile: begin.Profile,
		SessionID: begin.SessionID, StartID: begin.StartID, InstallationID: begin.InstallationID,
		TestPlanSHA256: begin.TestPlanSHA256, ReservationSHA256: begin.ReservationSHA256,
		Phase: stage2aDriverLiveStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, errStage2aDriverLiveUnsupported) {
		t.Fatalf("live phase wasn't explicitly refused: %v", err)
	}
}
