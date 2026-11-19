package daemon

import (
	"errors"
	"os"
	"path/filepath"
)

// Publish the existing deny marker before doing any other work. Both the
// live Machine gate and keyd check it. Never wait for a signing operation.
func revokeHQ(dir string) error {
	peers := filepath.Join(dir, "peers")
	for _, path := range []string{dir, peers} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("expected private Machine pairing directory")
		}
		if err := verifyPrivateDir(path); err != nil {
			return err
		}
	}
	path := filepath.Join(peers, "agent-daemon.revoked")
	flag, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("HQ revocation marker requires administrator recovery")
		}
		if err = verifyDirOwner(path, info); err != nil {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		if err := errors.Join(flag.Sync(), flag.Close()); err != nil {
			return err
		}
	}
	parent, err := os.Open(peers)
	if err != nil {
		return err
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return err
	}
	// The marker is already live. Retire pending challenges and the old
	// owner-approved principal as well, so clearing a file alone cannot
	// reactivate a previously enrolled HQ.
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		return err
	}
	defer unlock()
	s, err := readOwnerPairState(dir)
	if err != nil {
		return err
	}
	if s != nil && (s.HQ != "" || s.Pending != nil || s.Recovery != nil || s.FirstHQ != nil) {
		return (&ownerPairState{Owner: s.Owner}).save(dir)
	}
	return nil
}
