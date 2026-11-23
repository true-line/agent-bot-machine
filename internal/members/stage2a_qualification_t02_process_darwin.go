package members

// Stage2aT02ProcessWitness is a bounded projection of Darwin's live kernel
// process record. It deliberately omits argv and environment bytes.
type Stage2aT02ProcessWitness struct {
	PID          int    `json:"pid"`
	ParentPID    int    `json:"parent_pid"`
	StartSeconds int64  `json:"start_seconds"`
	StartMicros  int32  `json:"start_micros"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Executable   string `json:"executable"`
}

// ObserveStage2aT02Process checks a live process and its exact approved
// executable and argv on both sides of one kernel identity sample. Callers
// must pin the executable's content and signature independently.
func ObserveStage2aT02Process(pid, parentPID, uid, gid int, executable string,
	argv []string) (Stage2aT02ProcessWitness, error) {
	observed, err := observeSoulProcess(pid, executable, argv)
	if err != nil || parentPID <= 0 || uid <= 0 || gid <= 0 ||
		observed.Kernel.ParentPID != parentPID || observed.Kernel.RealUID != uint32(uid) ||
		observed.Kernel.EffectiveUID != uint32(uid) || observed.Kernel.SavedUID != uint32(uid) ||
		observed.Kernel.RealGID != uint32(gid) || observed.Kernel.PrimaryGroupGID != uint32(gid) ||
		observed.Kernel.SavedGID != uint32(gid) {
		return Stage2aT02ProcessWitness{}, errStage2aReservationAuthority
	}
	return Stage2aT02ProcessWitness{PID: pid, ParentPID: parentPID,
		StartSeconds: observed.Kernel.StartSeconds, StartMicros: observed.Kernel.StartMicros,
		UID: uint32(uid), GID: uint32(gid), Executable: executable}, nil
}
