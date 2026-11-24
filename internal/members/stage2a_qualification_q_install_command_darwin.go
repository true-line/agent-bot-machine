package members

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/qwts/managed-machine/internal/statedir"
)

type stage2aQualificationQOwnerPlan struct {
	PlanID          string                       `json:"plan_id"`
	LauncherSHA256  string                       `json:"launcher_sha256"`
	Install         stage2aQualificationQInstall `json:"installed_observer"`
	Source          []byte                       `json:"observer_source_base64"`
	ProcessObserver []byte                       `json:"process_observer_base64"`
}

// RunStage2aQualificationQInstall is the explicit local owner ceremony.
// The expected digest covers the entire reviewed role and launcher grant.
func RunStage2aQualificationQInstall(deps ApplyDeps, args []string) error {
	if len(args) != 1 || !stage2aQualificationDigest(args[0]) || deps.DaemonState == nil {
		return errStage2aReservationAuthority
	}
	owner, home, diagnostic := membersSudoOwner(Deps{ApplyDeps: deps}, "stage2a-qualification-install")
	if diagnostic != nil {
		return fmt.Errorf("qualification observer installation requires an interactive owner sudo session")
	}
	_, account, err := deps.DaemonState(owner, home)
	if err != nil || account == owner {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (512<<10)+1))
	if err != nil || len(raw) > 512<<10 || stage2aQualificationSHA256(raw) != args[0] {
		return errStage2aReservationAuthority
	}
	if stage2aStrictJSON(raw) != nil {
		return errStage2aReservationAuthority
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var plan stage2aQualificationQOwnerPlan
	if dec.Decode(&plan) != nil || !ValidApproval(plan.PlanID, plan.LauncherSHA256) || plan.Install.Review.Owner != owner || plan.Install.Review.PlanID != plan.PlanID {
		return errStage2aReservationAuthority
	}
	if plan.Install.LauncherSHA256 != plan.LauncherSHA256 {
		return errStage2aReservationAuthority
	}
	hq, found, err := (OSHost{}).Account(DarwinHQAccount)
	if err != nil || !found || hq.UID != plan.Install.HQUID || hq.GID != plan.Install.HQGID {
		return errStage2aReservationAuthority
	}
	install, err := json.Marshal(plan.Install)
	if err != nil {
		return err
	}
	state, err := statedir.Path("darwin", func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return err
	}
	savedRaw, err := readQualificationInput(filepath.Join(state, "members", "plans", plan.PlanID+".json"))
	if err != nil {
		return errStage2aReservationAuthority
	}
	request, err := decodeStage2aQualificationQPlan(savedRaw, plan.Install)
	if err != nil {
		return err
	}
	review := plan.Install.Review
	if request.Runner.BinaryPath != plan.Install.Source.Path ||
		request.Runner.SourcePath == "" || verifyQualificationRunnerReviewFile(request) != nil {
		return errStage2aReservationAuthority
	}
	if review.DriverBaselineOnly {
		driver, err := loadStage2aQualificationDriverReview(review.TestPlan)
		if err != nil || !stage2aQualificationPrintable(driver.CohortID, 128) ||
			driver.SuiteRevision != request.SuiteRevision || driver.Policy.SHA256 != request.Host.EnforcementPolicySHA ||
			verifyQualificationFile(driver.Policy) != nil {
			return errStage2aReservationAuthority
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := observeStage2aQualificationHost(ctx, review.HostUUID); err != nil {
		return err
	}
	return provisionStage2aQualificationQ(account, plan.LauncherSHA256, plan.PlanID, install, plan.Source, plan.ProcessObserver, savedRaw, plan.Install)
}
