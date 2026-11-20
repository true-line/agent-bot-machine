package daemon

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// CheckHQUpgradePair reads only published pairing evidence under the resolved
// prefix owner's directory. Root apply must retain the same owner, Machine,
// dedicated role, peer key and enrollment epoch through service replacement.
func CheckHQUpgradePair(dir, account, want string, run func() error) error {
	operator, err := user.Lookup(account)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(operator.Uid)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "owner-pair.lock"), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer lock.Close()
	ls, err := lock.Stat()
	if err != nil || !ls.Mode().IsRegular() || ls.Mode().Perm() != 0600 || ls.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		return errors.New("unexpected owner pairing lock")
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ownerPairFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(uid) || st.Size() > 4096 {
		return errors.New("unexpected owner pairing evidence")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return errors.New("could not read bounded owner pairing evidence")
	}
	p, err := decodeOwnerPairState(b)
	if err != nil || p == nil || p.UID < 300 || p.UID > 399 || !dedicatedMembersPlanPeer(p.UID) || pairCommitment(p) != want || (p.Pending != nil && p.Pending.Expires > time.Now().Unix()) {
		return errors.New("approved dedicated HQ pairing changed")
	}
	key, err := p.liveKey(filepath.Join(dir, "peers"))
	if err != nil || len(key) == 0 || hex.EncodeToString(key) != p.HQ {
		return errors.New("approved HQ pairing is unavailable")
	}
	if run != nil {
		return run()
	}
	return nil
}
