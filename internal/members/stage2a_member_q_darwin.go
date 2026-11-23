//go:build darwin

package members

// A member lease or aggregate Ready needs the retained Q process and owner
// driver to be the exact live peers originally admitted for this start.
func (run *stage2aProtectedQRun) recheckMemberQ() error {
	if run == nil || !run.install.Review.DriverLive || run.ctx == nil ||
		run.ctx.Err() != nil || run.checkLive == nil {
		return errStage2aReservationAuthority
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.closed || run.session == nil || run.session.closed || run.session.conn == nil ||
		run.driver == nil || run.driver.conn == nil ||
		run.session.peer.recheck() != nil || run.driver.peer.recheck() != nil ||
		run.checkLive() != nil {
		return errStage2aReservationAuthority
	}
	return nil
}
