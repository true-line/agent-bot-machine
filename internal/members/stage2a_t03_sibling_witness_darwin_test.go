//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestStage2aT03SiblingWitnessBindsIssuedLeaseAndReviewedMetadata(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	primary := "sha256:" + strings.Repeat("b", 64)
	path := "/private/fixture/sibling/state/child-one/credential"
	meta := Stage2aT03CredentialMetadata{Schema: "agent-bot-machine/stage2a-t03-credential-metadata/v1",
		Path: path, Device: "1", Inode: "2", Generation: "3", UID: 301, GID: 301,
		Mode: "0600", SizeBytes: "12", BirthSeconds: "100", BirthNanos: "1",
		ModifySeconds: "101", ModifyNanos: "2", ChangeSeconds: "102", ChangeNanos: "3"}
	raw, err := marshalStage2aReservationJCS(meta)
	if err != nil {
		t.Fatal(err)
	}
	metaDigest := stage2aReservationSHA256(raw)
	q := Stage2aStopRequest{ReservationSHA256: digest, InstallationID: "sibling-one", StartID: "st_0123456789abcdef01234567"}
	state := &stage2aT03SiblingWitnessState{PrimaryReservationSHA256: primary,
		ChallengeBase64URL: "challenge", Path: path, ExpectedDigest: metaDigest,
		IssuedSequence: 7, IssuedAtMS: 1_000, ExpiresAtMS: 3_000}
	w := Stage2aT03SiblingCredentialWitness{Schema: "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1",
		ChallengeBase64URL: state.ChallengeBase64URL, PrimaryReservationSHA256: primary,
		SiblingReservationSHA256: digest, SiblingInstallationID: q.InstallationID,
		SiblingStartID: q.StartID, ChildReceiptSHA256: digest, LeaseSequence: 7,
		CredentialPath: path, Metadata: meta, MetadataSHA256: metaDigest, ObservedAtMS: 1_500}
	if !stage2aT03WitnessMatchesIssued(state, w, q, digest, 301, 2_000) {
		t.Fatal("matching sibling observation refused")
	}
	for _, change := range []func(*Stage2aT03SiblingCredentialWitness){
		func(v *Stage2aT03SiblingCredentialWitness) { v.CredentialPath += "-other" },
		func(v *Stage2aT03SiblingCredentialWitness) { v.Metadata.Path += "-other" },
		func(v *Stage2aT03SiblingCredentialWitness) { v.Metadata.UID++ },
		func(v *Stage2aT03SiblingCredentialWitness) { v.Metadata.Mode = "0644" },
		func(v *Stage2aT03SiblingCredentialWitness) { v.MetadataSHA256 = primary },
		func(v *Stage2aT03SiblingCredentialWitness) { v.LeaseSequence-- },
		func(v *Stage2aT03SiblingCredentialWitness) { v.ObservedAtMS = 999 },
	} {
		bad := w
		change(&bad)
		if stage2aT03WitnessMatchesIssued(state, bad, q, digest, 301, 2_000) {
			t.Fatal("mismatched sibling witness accepted")
		}
	}
	if stage2aT03WitnessMatchesIssued(state, w, q, digest, 301, 3_001) {
		t.Fatal("expired sibling witness accepted")
	}
	state.First = &stage2aT03SiblingWitnessReceipt{Witness: w, LeaseIssuedAtMS: 1_000, ReceivedAtMS: 2_000}
	state.Latest = state.First
	review := stage2aT03Review{SiblingPath: path, SiblingCredentialMetadataSHA256: metaDigest}
	if stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 3_000) {
		t.Fatal("first witness reused after credential attempt")
	}
	second := w
	second.LeaseSequence = 8
	state.Latest = &stage2aT03SiblingWitnessReceipt{Witness: second, LeaseIssuedAtMS: 2_400, ReceivedAtMS: 2_400}
	if stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 3_000) {
		t.Fatal("pre-attempt witness counted as post-attempt")
	}
	state.Latest.ReceivedAtMS = 2_600
	if stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 3_000) {
		t.Fatal("pre-attempt signed lease counted as post-attempt")
	}
	state.Latest.LeaseIssuedAtMS = 2_501
	if stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 3_000) {
		t.Fatal("pre-attempt observation counted as post-attempt")
	}
	state.Latest.Witness.ObservedAtMS = 2_501
	if !stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 3_000) {
		t.Fatal("fresh later-lease witness refused")
	}
	if stage2aT03SecondWitnessMatches(state, review, primary, "challenge", 2_500, 7_601) {
		t.Fatal("stale second witness accepted")
	}
}
