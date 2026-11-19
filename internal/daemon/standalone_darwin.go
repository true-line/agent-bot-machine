//go:build darwin

package daemon

import (
	"errors"
	"os"
	"path/filepath"
)

const standaloneNamespace = "Application Support/ai.true-line.agent-bot-hq/standalone"

func checkStandaloneAdmission(library string) error {
	for _, name := range []string{"declaration-pending-v1", "declaration-v1"} {
		if _, err := os.Lstat(filepath.Join(library, standaloneNamespace, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("the administrator must finish or retire the standalone HQ signing declaration before starting Machine")
		}
	}
	return nil
}

// The issuer publishes a pending record before its final inventory of local
// registered homes. Publishing the normal Machine state before checking again
// means either the issuer observes Machine or Machine observes the declaration.
func prepareMachineLifecycle(home string) error {
	return prepareMachineLifecycleAt("/Library", home)
}

func prepareMachineLifecycleAt(library, home string) error {
	if err := checkStandaloneAdmission(library); err != nil {
		return err
	}
	config := filepath.Join(home, ".config")
	for _, path := range []string{config, filepath.Join(config, "agent-machine")} {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() {
			return errors.New("unable to verify Machine's registered state directory")
		}
	}
	return checkStandaloneAdmission(library)
}
