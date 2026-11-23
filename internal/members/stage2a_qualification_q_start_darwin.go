package members

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

func spawnStage2aQualificationQ(ctx context.Context, install stage2aQualificationQInstall,
	listener *stage2aQualificationListenerV1, begin stage2aQualificationBeginV1) (*stage2aQualificationSessionV1, func() error, error) {
	return spawnStage2aQualificationQWithArgvProof(ctx, install, listener, begin, true)
}

// The cross-UID proof is required for an installed, owner-reviewed Q start.
func spawnStage2aQualificationQWithArgvProof(ctx context.Context, install stage2aQualificationQInstall,
	listener *stage2aQualificationListenerV1, begin stage2aQualificationBeginV1, reviewedArgvProof bool) (*stage2aQualificationSessionV1, func() error, error) {
	argv := stage2aQualificationQArguments(install)
	if reviewedArgvProof {
		current, err := loadStage2aQualificationQInstall()
		if err != nil || !reflect.DeepEqual(current, install) ||
			trustedPath(OSHost{}, stage2aQualificationQPlist, false) != nil ||
			checkDarwinACLs(pathAncestry(stage2aQualificationQPlist)) != nil {
			return nil, nil, errQualificationAdmissionUnavailable
		}
		raw, err := os.ReadFile(stage2aQualificationQPlist)
		if err != nil || !bytes.Equal(raw, renderStage2aQualificationQLaunchd(install)) {
			return nil, nil, errQualificationAdmissionUnavailable
		}
		for _, executable := range []string{SoulLauncher, install.Node.Path, install.PS.Path} {
			if runProgram("/usr/bin/codesign", "--verify", "--strict", executable) != nil {
				return nil, nil, errQualificationAdmissionUnavailable
			}
		}
		if loaded, err := stage2aQualificationQLaunchdLoaded(); err != nil || !loaded {
			return nil, nil, errQualificationAdmissionUnavailable
		}
	}
	after := time.Now().Truncate(time.Microsecond)
	pid, err := triggerStage2aQualificationQ(ctx, install, filepath.Base(listener.path))
	if err != nil {
		return nil, nil, err
	}
	kernel, err := observeSoulKernelProcess(pid)
	if err != nil || !stage2aQualificationKernelMatches(kernel, pid, install.UID, install.GID) ||
		kernel.ParentPID != 1 || time.Unix(kernel.StartSeconds, int64(kernel.StartMicros)*1000).Before(after) ||
		!stage2aQualificationKernelGroupsMatch(kernel, install) {
		return nil, nil, fmt.Errorf("qualification launchd observer identity refused")
	}
	conn, peer, err := listener.accept(ctx, pid, install.UID, install.GID, install.Node.Path, argv, reviewedArgvProof)
	if err != nil {
		return nil, nil, err
	}
	if !sameSoulKernelProcess(kernel, peer.kernel) || !stage2aQualificationKernelGroupsMatch(peer.kernel, install) {
		_ = conn.Close()
		return nil, nil, errQualificationAdmissionUnavailable
	}
	session, err := beginStage2aQualificationSessionV1(conn, peer, begin, "sha256:"+install.Source.SHA256, time.Now())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return session, func() error { return stage2aQualificationQExit(peer.kernel) }, nil
}
