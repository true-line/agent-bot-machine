package daemon

import (
	"crypto/ed25519"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// ReadStage2aHQWorkerKey is called only inside the fixed offline A worker.
// It opens the already enrolled key, without starting the daemon, repairing
// custody, creating a key, or contacting HQ.
func ReadStage2aHQWorkerKey(account, fingerprint string, authorize func(string) error) (ed25519.PrivateKey, string, error) {
	if os.Getuid() < 400 || os.Getuid() != os.Geteuid() || authorize == nil {
		return nil, "", errChannelIdentity
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || u.Username != account || !filepath.IsAbs(u.HomeDir) {
		return nil, "", errChannelIdentity
	}
	dir := stateDir(u.HomeDir)
	if err := authorize(dir); err != nil {
		return nil, "", err
	}
	key, err := pairedChannelKey(dir, ChannelDir(), defaultLegacySharedDir(u.HomeDir), defaultKeyStore(filepath.Join(dir, "daemon.key")))
	if err != nil || len(key) != ed25519.PrivateKeySize || publicFingerprint(key.Public().(ed25519.PublicKey)) != fingerprint {
		zeroBytes(key)
		return nil, "", errChannelIdentity
	}
	return key, dir, nil
}

// Hold the live pairing across local private-key access and the entire
// offline reservation operation, independently of the caller's lock.
func ReadStage2aReservationWorkerKey(hqUID int, epoch, fingerprint string) (ed25519.PrivateKey, func() error, error) {
	if os.Getuid() < 400 || os.Getuid() != os.Geteuid() || !dedicatedMembersPlanPeer(hqUID) || epoch == "" {
		return nil, nil, errChannelIdentity
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return nil, nil, errChannelIdentity
	}
	var unlock func() error
	key, _, err := ReadStage2aHQWorkerKey(u.Username, fingerprint, func(dir string) error {
		var lockErr error
		unlock, lockErr = lockDevicePairing(dir)
		if lockErr != nil {
			return lockErr
		}
		pair, err := currentDevicePairing(dir)
		if err != nil || !pair.OwnerPresenceRequired || !pair.AgentDaemonBound || pair.AgentDaemonUID != hqUID || pair.HQEpoch != epoch {
			return errChannelIdentity
		}
		return nil
	})
	if err != nil || unlock == nil {
		if unlock != nil {
			_ = unlock()
		}
		zeroBytes(key)
		return nil, nil, errChannelIdentity
	}
	return key, unlock, nil
}
