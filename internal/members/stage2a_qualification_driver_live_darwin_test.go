//go:build darwin

package members

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage2aProtectedT03OwnerDriverCapture(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("owner driver runs only in a nonroot account")
	}
	dir := t.TempDir()
	pin := func(name string) qualificationFile {
		path := filepath.Join(dir, name)
		data := []byte(name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return qualificationFile{Path: path, SHA256: strings.TrimPrefix(stage2aQualificationSHA256(data), "sha256:")}
	}
	policy, provider := pin("policy"), pin("provider")
	for _, enabled := range []bool{false, true} {
		name := "baseline-review"
		if enabled {
			name = "live-review"
		}
		t.Run(name, func(t *testing.T) {
			a, driver := net.Pipe()
			defer driver.Close()
			defer a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			begin := driverCaseBegin("managed-protected")
			review := stage2aDriverReview{testPlanSHA256: begin.TestPlanSHA256, Policy: policy}
			done := make(chan error, 1)
			checkA := func() error { return nil }
			go func() {
				err := serveStage2aDriverReviewed(ctx, driver, review,
					stage2aQualificationQReview{Provider: provider, DriverBaselineOnly: !enabled, DriverLiveT03: enabled},
					uid, checkA)
				_ = driver.Close()
				done <- err
			}()
			baseline, err := exchangeStage2aDriverCases(ctx, a, begin, stage2aDriverBeforeLaunch, checkA,
				func(ctx context.Context, command stage2aDriverCommand, _ string) (stage2aDriverCorroboration, error) {
					return verifyStage2aDriverBaseline(ctx, command, review, provider, uid)
				}, func(stage2aQualificationObserveV1) ([]byte, error) { return nil, nil })
			if err != nil || len(baseline) != 2 {
				t.Fatalf("baseline capture failed: %v", err)
			}
			if !enabled {
				_ = a.Close()
				if err := <-done; err != nil {
					t.Fatalf("baseline-only driver did not complete: %v", err)
				}
				return
			}
			var captured stage2aDriverCommand
			probes := 0
			trace, err := exchangeStage2aDriverCasesWithCapture(ctx, a, begin, stage2aDriverLiveT03,
				checkA, nil, func(probe stage2aQualificationObserveV1) ([]byte, error) {
					probes++
					if probe.Gate != "T03" || probe.Phase != string(stage2aDriverLiveT03) ||
						probe.EventID != "direct-route-refused" || probe.StimulusRef == nil ||
						probe.StimulusRef.SHA256 != stage2aQualificationSHA256([]byte(`{"case":"test"}`)) {
						t.Errorf("unexpected Q probe: %+v", probe)
					}
					return nil, nil
				}, func(_ context.Context, command stage2aDriverCommand) (stage2aDriverCorroboration, error) {
					captured = command
					return stage2aDriverCorroboration{
						artifact:  []byte(`{"case":"test"}`),
						osWitness: []byte(`{"witness":"test"}`),
						probe: stage2aQualificationObserveV1{Processes: []stage2aQualificationProcessRequestV1{
							{Role: "runner", PID: 42},
						}},
					}, nil
				})
			_ = a.Close()
			workerErr := <-done
			if err != nil || workerErr != nil || len(trace) != 1 || probes != 1 ||
				captured.Challenge == "" || captured.SessionID != begin.SessionID ||
				captured.ReservationSHA256 != begin.ReservationSHA256 {
				t.Fatalf("capture did not join: A=%v driver=%v trace=%d probes=%d", err, workerErr, len(trace), probes)
			}
		})
	}
}

func TestStage2aProtectedT03OwnerDriverRequiresBaseline(t *testing.T) {
	a, driver := net.Pipe()
	defer a.Close()
	defer driver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	begin := driverCaseBegin("managed-protected")
	done := make(chan error, 1)
	checkA := func() error { return nil }
	go func() {
		err := serveStage2aDriverReviewed(ctx, driver,
			stage2aDriverReview{testPlanSHA256: begin.TestPlanSHA256},
			stage2aQualificationQReview{DriverLiveT03: true}, 501, checkA)
		_ = driver.Close()
		done <- err
	}()
	_, err := exchangeStage2aDriverCasesWithCapture(ctx, a, begin, stage2aDriverLiveT03,
		checkA, nil, func(stage2aQualificationObserveV1) ([]byte, error) {
			t.Error("Q observation started ahead of the baseline")
			return nil, nil
		}, func(context.Context, stage2aDriverCommand) (stage2aDriverCorroboration, error) {
			t.Error("live T03 armed ahead of the baseline")
			return stage2aDriverCorroboration{}, nil
		})
	if workerErr := <-done; err == nil || workerErr != errStage2aDriverLiveUnsupported {
		t.Fatalf("accepted live phase without baseline: A=%v driver=%v", err, workerErr)
	}
}
