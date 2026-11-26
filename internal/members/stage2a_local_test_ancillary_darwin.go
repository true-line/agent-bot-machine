//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"time"
)

const (
	stage2aLocalTestAncillarySubkeyPurpose = "agent-bot-stage2a-observed-body-local-test-ancillary-subkey-v1\x00"
	stage2aLocalTestAncillaryOriginPurpose = "agent-bot-stage2a-observed-body-local-test-ancillary-origin-v1\x00"
)

type stage2aLocalTestAncillaryObservation struct {
	Sequence              int    `json:"sequence"`
	ReceivedAt            string `json:"received_at"`
	HTTPStatus            int    `json:"http_status"`
	HeaderShapeSHA256     string `json:"header_shape_sha256"`
	ObservedHeadersSHA256 string `json:"observed_headers_sha256"`
	NormalizedBodySHA256  string `json:"normalized_body_sha256"`
	ProviderCountBefore   uint64 `json:"provider_count_before"`
	ProviderCountAfter    uint64 `json:"provider_count_after"`
}

type stage2aLocalTestAncillaryFinalWitness struct {
	Schema             string                               `json:"schema"`
	Kind               string                               `json:"kind"`
	SchemaVersion      int                                  `json:"schema_version"`
	Selectors          stage2aLocalTestSelectors            `json:"selectors"`
	CompletedRunSHA256 string                               `json:"completed_run_sha256"`
	Peer               Stage2aT03RelayPeer                  `json:"peer"`
	PeerSHA256         string                               `json:"peer_sha256"`
	First              stage2aLocalTestAncillaryObservation `json:"first"`
	Second             stage2aLocalTestAncillaryObservation `json:"second"`
	IssuedAt           string                               `json:"issued_at"`
	ExpiresAt          string                               `json:"expires_at"`
}

type stage2aLocalTestAncillarySubmission struct {
	Core      stage2aLocalTestAncillaryFinalWitness `json:"core"`
	OriginMAC string                                `json:"origin_mac"`
}

func stage2aLocalTestAncillaryMAC(secret []byte, reservationDigest string, core []byte) []byte {
	subkey := hmac.New(sha256.New, secret)
	subkey.Write([]byte(stage2aLocalTestAncillarySubkeyPurpose))
	subkey.Write([]byte(reservationDigest))
	key := subkey.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stage2aLocalTestAncillaryOriginPurpose))
	mac.Write(core)
	return mac.Sum(nil)
}

// A checks the separate B MAC and the two observations against the installed
// owner profile. Target completion stays immutable; its digest is only joined.
// The caller also rechecks that this peer is the current kernel-observed stock
// child before committing the witness.
func verifyStage2aLocalTestAncillarySubmission(sub stage2aLocalTestAncillarySubmission,
	secret []byte, expectedSelectors stage2aLocalTestSelectors, completedRunSHA256 string,
	expectedPeer Stage2aT03RelayPeer, profile stage2aLocalTestAncillaryProfile,
	targetCompletedAt, deadline, now time.Time) ([]byte, error) {
	c := sub.Core
	if len(secret) != 32 || !expectedSelectors.valid() ||
		!stage2aPrefixedDigest.MatchString(completedRunSHA256) ||
		c.Schema != "agent-bot-machine/stage2a-observed-body-local-test-ancillary-final-witness/v1" ||
		c.Kind != "observed-body-local-test-ancillary-final-witness" || c.SchemaVersion != 1 ||
		c.Selectors != expectedSelectors || c.CompletedRunSHA256 != completedRunSHA256 ||
		c.Peer != expectedPeer || !c.Peer.valid() ||
		!profile.valid(profile.FirstHeaderShape.Host) ||
		!targetCompletedAt.Before(deadline) || now.Before(targetCompletedAt) || !now.Before(deadline) {
		return nil, errStage2aReservationAuthority
	}
	peerRaw, err := stage2aT03PeerCanonical(c.Peer)
	if err != nil || c.PeerSHA256 != stage2aReservationSHA256(peerRaw) {
		return nil, errStage2aReservationAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if e1 != nil || e2 != nil || issued.Before(targetCompletedAt) || now.Before(issued) ||
		!now.Before(expires) || expires.After(deadline) || !issued.Before(expires) {
		return nil, errStage2aReservationAuthority
	}
	for index, observation := range []stage2aLocalTestAncillaryObservation{c.First, c.Second} {
		shape := profile.FirstHeaderShape
		headers := profile.FirstHeadersSHA256
		if index == 1 {
			shape = profile.SecondHeaderShape
			headers = profile.SecondHeadersSHA256
		}
		shapeRaw, err := marshalStage2aReservationJCS(shape)
		received, timeErr := time.Parse(time.RFC3339Nano, observation.ReceivedAt)
		if err != nil || timeErr != nil || observation.Sequence != index+1 ||
			observation.HTTPStatus != 422 || observation.HeaderShapeSHA256 != stage2aReservationSHA256(shapeRaw) ||
			observation.ObservedHeadersSHA256 != headers ||
			observation.NormalizedBodySHA256 != profile.NormalizedBodySHA256 ||
			observation.ProviderCountBefore != observation.ProviderCountAfter ||
			received.After(issued) || received.After(deadline) {
			return nil, errStage2aReservationAuthority
		}
		if index == 0 {
			if !received.Before(targetCompletedAt) {
				return nil, errStage2aReservationAuthority
			}
			firstAt := received
			secondAt, e := time.Parse(time.RFC3339Nano, c.Second.ReceivedAt)
			if e != nil || secondAt.Before(firstAt) {
				return nil, errStage2aReservationAuthority
			}
		}
	}
	canonical, err := marshalStage2aReservationJCS(c)
	if err != nil || stage2aLocalTestCanonicalPayload(canonical, stage2aLocalTestAncillaryPurpose) != nil ||
		!stage2aLowerHex64(sub.OriginMAC) {
		return nil, errStage2aReservationAuthority
	}
	got, err := hex.DecodeString(sub.OriginMAC)
	if err != nil || subtle.ConstantTimeCompare(got,
		stage2aLocalTestAncillaryMAC(secret, c.Selectors.ReservationDigest, canonical)) != 1 {
		return nil, errStage2aReservationAuthority
	}
	return canonical, nil
}

// This record is one-use across daemon restarts. A signs only after its
// exclusive durable file exists; a signature failure leaves the claim spent.
func commitAndSignStage2aLocalTestAncillary(store stage2aAdminClaimStore, dir *os.File,
	sub stage2aLocalTestAncillarySubmission, secret []byte,
	expectedSelectors stage2aLocalTestSelectors, completedRunSHA256 string,
	expectedPeer Stage2aT03RelayPeer, profile stage2aLocalTestAncillaryProfile,
	targetCompletedAt, deadline, now time.Time, enrolledKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	if dir == nil || store.checkDirectory(dir) != nil || store.uid < 400 || store.gid == 0 ||
		store.uid != uint32(os.Getuid()) || store.uid != uint32(os.Geteuid()) ||
		store.gid != uint32(os.Getgid()) || store.gid != uint32(os.Getegid()) || sign == nil {
		return nil, errStage2aReservationAuthority
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, expectedSelectors.InstallationID)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil {
		return nil, errStage2aReservationAuthority
	}
	canonical, err := verifyStage2aLocalTestAncillarySubmission(sub, secret,
		expectedSelectors, completedRunSHA256, expectedPeer, profile, targetCompletedAt, deadline, now)
	if err != nil {
		return nil, err
	}
	name := ".stage2a-local-test-ancillary-" + soulStartClaimName(
		expectedSelectors.InstallationID, expectedSelectors.StartID) + ".json"
	if err := commitStage2aReservation(dir, name, canonical); err != nil {
		return nil, err
	}
	return signStage2aVerifiedLocalTestEnvelope(stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aLocalTestAncillaryPurpose, payload: canonical,
		machineUID: store.uid, machineGID: store.gid,
	}, enrolledKey, sign)
}
