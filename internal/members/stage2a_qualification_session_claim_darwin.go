//go:build darwin

package members

// The installed A store, not the Q peer or an HQ request, consumes one Q
// session for this signed reservation and start. The caller verifies the
// reservation signature and exact selectors before entering this boundary.
func claimStage2aQualificationSessionV3(store stage2aAdminClaimStore,
	begin stage2aQualificationBeginV1, reservation []byte) error {
	if !soulInstallationID.MatchString(begin.InstallationID) ||
		!soulStartID.MatchString(begin.StartID) ||
		begin.ReservationSHA256 != stage2aQualificationSHA256(reservation) ||
		len(reservation) == 0 || len(reservation) > 64<<10 {
		return errStage2aReservationAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, begin.InstallationID)
	if err != nil {
		return errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(begin.InstallationID, begin.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(begin.InstallationID), store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-admin-envelope-"+slot,
			store.uid, store.gid, reservation, 64<<10) != nil {
		return errStage2aReservationAuthority
	}
	return spendStage2aAdminName(dir, ".stage2a-q-session-"+slot, store.uid, store.gid)
}
