package qualification

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
)

var bridgeSoulID = regexp.MustCompile(`^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// bridgeReport is the v2 protected-only extension. The report is an
// authenticated claim, not a substitute for resolving the independent
// Machine and HQ observations that each reference names.
type bridgeReport struct {
	Assignment struct {
		InstallationID string          `json:"installation_id"`
		SoulID         string          `json:"soul_id"`
		StartID        string          `json:"start_id"`
		LaunchID       string          `json:"launch_id"`
		RuntimeID      string          `json:"runtime_id"`
		PlanID         string          `json:"plan_id"`
		PlanDigest     string          `json:"plan_digest"`
		ReservationSHA string          `json:"machine_reservation_sha256"`
		Observation    reportReference `json:"machine_observation"`
	} `json:"assignment"`
	Principals struct {
		RunnerUID        uint32 `json:"runner_uid"`
		BridgeUID        uint32 `json:"bridge_uid"`
		CredentialUID    uint32 `json:"credential_uid"`
		HQUID            uint32 `json:"hq_uid"`
		MachineUID       uint32 `json:"machine_uid"`
		BridgePrivateGID uint32 `json:"bridge_private_gid"`
		RunnerPrivateGID uint32 `json:"runner_private_gid"`
	} `json:"principals"`
	Endpoints struct {
		HQBroker    bridgeEndpoint `json:"hq_broker"`
		SoulsMember bridgeEndpoint `json:"souls_member"`
		HTTPRelay   bridgeEndpoint `json:"http_relay"`
	} `json:"endpoints"`
	Handoff struct {
		Transport      string     `json:"transport"`
		RecipientUID   uint32     `json:"recipient_uid"`
		BootstrapSHA   string     `json:"bootstrap_sha256"`
		BindReceiptSHA string     `json:"bind_receipt_sha256"`
		BOnlyCustody   bridgePass `json:"b_only_custody"`
		RDenied        bridgePass `json:"r_denied"`
		CDenied        bridgePass `json:"c_denied"`
		OtherBDenied   bridgePass `json:"other_b_denied"`
	} `json:"handoff"`
	Admission struct {
		RunnerEndpoint   bridgePass `json:"runner_endpoint"`
		MemberHello      bridgePass `json:"member_hello"`
		HQBrokerHMACBind bridgePass `json:"hq_broker_hmac_bind"`
		HQBindReceiptSHA string     `json:"hq_bind_receipt_sha256"`
		BindBeforeACP    bridgePass `json:"bind_before_acp"`
		RelayPeer        bridgePass `json:"relay_peer"`
	} `json:"admission"`
	Lifecycle struct {
		OneUse                bridgePass `json:"one_use"`
		RestartReplayRefused  bridgePass `json:"restart_replay_refused"`
		FailedBindPreventsACP bridgePass `json:"failed_bind_prevents_acp"`
		StopCleanup           bridgePass `json:"stop_cleanup"`
	} `json:"lifecycle"`
}

type bridgePass struct {
	Outcome  string          `json:"outcome"`
	Evidence reportReference `json:"evidence"`
}

type bridgeEndpoint struct {
	SocketPath      string     `json:"socket_path"`
	ParentUID       uint32     `json:"parent_uid"`
	ParentGID       uint32     `json:"parent_gid"`
	ParentMode      string     `json:"parent_mode"`
	ParentInode     uint64     `json:"parent_inode"`
	SocketUID       uint32     `json:"socket_uid"`
	SocketGID       uint32     `json:"socket_gid"`
	SocketMode      string     `json:"socket_mode"`
	SocketInode     uint64     `json:"socket_inode"`
	ObservedPeerUID uint32     `json:"observed_peer_uid"`
	MachineCustody  bridgePass `json:"machine_custody"`
	KernelPeerCheck bridgePass `json:"kernel_peer_check"`
}

func passing(p bridgePass) bool { return p.Outcome == "pass" && reportRef(p.Evidence) }

func endpointValid(e bridgeEndpoint, owner, group, peer uint32) bool {
	return reportPath(e.SocketPath) && e.ParentUID == owner && e.SocketUID == owner &&
		e.ParentGID == group && e.SocketGID == group && e.ParentMode == "2750" &&
		e.SocketMode == "0660" && e.ParentInode > 0 && e.SocketInode > 0 &&
		e.ObservedPeerUID == peer && passing(e.MachineCustody) && passing(e.KernelPeerCheck)
}

func bridgeFields(raw json.RawMessage, names ...string) (map[string]json.RawMessage, error) {
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, names...) {
		return nil, ErrUnqualified
	}
	return fields, nil
}

func bridgePassFields(raw json.RawMessage) error {
	_, err := bridgeFields(raw, "outcome", "evidence")
	return err
}

func bridgeEndpointFields(raw json.RawMessage) error {
	f, err := bridgeFields(raw, "socket_path", "parent_uid", "parent_gid", "parent_mode", "parent_inode", "socket_uid", "socket_gid", "socket_mode", "socket_inode", "observed_peer_uid", "machine_custody", "kernel_peer_check")
	if err != nil {
		return err
	}
	for _, name := range []string{"machine_custody", "kernel_peer_check"} {
		if bridgePassFields(f[name]) != nil {
			return ErrUnqualified
		}
	}
	return nil
}

func reportShapeV2(raw []byte) error {
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil || len(fields) != 18 {
		return ErrUnqualified
	}
	bridgeRaw, ok := fields["bridge"]
	if !ok {
		return ErrUnqualified
	}
	bridge, err := bridgeFields(bridgeRaw, "assignment", "principals", "endpoints", "handoff", "admission", "lifecycle")
	if err != nil {
		return err
	}
	if _, err = bridgeFields(bridge["assignment"], "installation_id", "soul_id", "start_id", "launch_id", "runtime_id", "plan_id", "plan_digest", "machine_reservation_sha256", "machine_observation"); err != nil {
		return err
	}
	if _, err = bridgeFields(bridge["principals"], "runner_uid", "bridge_uid", "credential_uid", "hq_uid", "machine_uid", "bridge_private_gid", "runner_private_gid"); err != nil {
		return err
	}
	endpoints, err := bridgeFields(bridge["endpoints"], "hq_broker", "souls_member", "http_relay")
	if err != nil {
		return err
	}
	for _, name := range []string{"hq_broker", "souls_member", "http_relay"} {
		if bridgeEndpointFields(endpoints[name]) != nil {
			return ErrUnqualified
		}
	}
	handoff, err := bridgeFields(bridge["handoff"], "transport", "recipient_uid", "bootstrap_sha256", "bind_receipt_sha256", "b_only_custody", "r_denied", "c_denied", "other_b_denied")
	if err != nil {
		return err
	}
	for _, name := range []string{"b_only_custody", "r_denied", "c_denied", "other_b_denied"} {
		if bridgePassFields(handoff[name]) != nil {
			return ErrUnqualified
		}
	}
	admissionFields, err := bridgeFields(bridge["admission"], "runner_endpoint", "member_hello", "hq_broker_hmac_bind", "hq_bind_receipt_sha256", "bind_before_acp", "relay_peer")
	if err != nil {
		return err
	}
	for _, name := range []string{"runner_endpoint", "member_hello", "hq_broker_hmac_bind", "bind_before_acp", "relay_peer"} {
		if bridgePassFields(admissionFields[name]) != nil {
			return ErrUnqualified
		}
	}
	lifecycle, err := bridgeFields(bridge["lifecycle"], "one_use", "restart_replay_refused", "failed_bind_prevents_acp", "stop_cleanup")
	if err != nil {
		return err
	}
	for _, name := range []string{"one_use", "restart_replay_refused", "failed_bind_prevents_acp", "stop_cleanup"} {
		if bridgePassFields(lifecycle[name]) != nil {
			return ErrUnqualified
		}
	}
	// Reuse the complete v1 common-field checks without allowing a v1 payload
	// to become v2: the outer verifier separately requires v2 schema/purpose.
	delete(fields, "bridge")
	fields["schema_version"] = []byte("1")
	common, err := json.Marshal(fields)
	if err != nil || reportShape(common) != nil {
		return ErrUnqualified
	}
	var commonReport reportDocument
	if json.Unmarshal(common, &commonReport) != nil {
		return ErrUnqualified
	}
	var b bridgeReport
	d := json.NewDecoder(bytes.NewReader(bridgeRaw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		return ErrUnqualified
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrUnqualified
	}
	a, p, e, h, admission, life := b.Assignment, b.Principals, b.Endpoints, b.Handoff, b.Admission, b.Lifecycle
	if !reportID.MatchString(a.InstallationID) || !reportID.MatchString(a.StartID) ||
		!reportID.MatchString(a.LaunchID) || !reportID.MatchString(a.RuntimeID) ||
		!reportID.MatchString(a.PlanID) || !validSHA(a.PlanDigest) ||
		!validSHA(a.ReservationSHA) || !reportRef(a.Observation) ||
		a.Observation != commonReport.SoulStart.MachineObservation ||
		!bridgeSoulID.MatchString(a.SoulID) ||
		p.RunnerUID == 0 || p.BridgeUID == 0 || p.CredentialUID == 0 ||
		p.RunnerUID == p.BridgeUID || p.RunnerUID == p.CredentialUID ||
		p.RunnerUID == p.HQUID || p.RunnerUID == p.MachineUID ||
		p.BridgeUID == p.CredentialUID || p.BridgeUID == p.HQUID ||
		p.BridgeUID == p.MachineUID || p.CredentialUID == p.HQUID ||
		p.CredentialUID == p.MachineUID || p.HQUID == p.MachineUID ||
		p.BridgePrivateGID == 0 || p.RunnerPrivateGID == 0 ||
		p.BridgePrivateGID == p.RunnerPrivateGID {
		return ErrUnqualified
	}
	if !endpointValid(e.HQBroker, p.HQUID, p.BridgePrivateGID, p.BridgeUID) ||
		!endpointValid(e.SoulsMember, p.RunnerUID, p.BridgePrivateGID, p.BridgeUID) ||
		!endpointValid(e.HTTPRelay, p.BridgeUID, p.RunnerPrivateGID, p.RunnerUID) ||
		e.HQBroker.SocketPath == e.SoulsMember.SocketPath ||
		e.HQBroker.SocketPath == e.HTTPRelay.SocketPath ||
		e.SoulsMember.SocketPath == e.HTTPRelay.SocketPath ||
		e.HQBroker.SocketInode == e.SoulsMember.SocketInode ||
		e.HQBroker.SocketInode == e.HTTPRelay.SocketInode ||
		e.SoulsMember.SocketInode == e.HTTPRelay.SocketInode ||
		e.HQBroker.ParentInode == e.SoulsMember.ParentInode ||
		e.HQBroker.ParentInode == e.HTTPRelay.ParentInode ||
		e.SoulsMember.ParentInode == e.HTTPRelay.ParentInode {
		return ErrUnqualified
	}
	if h.Transport != "one-use-inherited-anonymous-fds" || h.RecipientUID != p.BridgeUID ||
		!validSHA(h.BootstrapSHA) || !validSHA(h.BindReceiptSHA) ||
		!passing(h.BOnlyCustody) || !passing(h.RDenied) || !passing(h.CDenied) ||
		!passing(h.OtherBDenied) || !validSHA(admission.HQBindReceiptSHA) ||
		!passing(admission.RunnerEndpoint) || !passing(admission.MemberHello) ||
		!passing(admission.HQBrokerHMACBind) || !passing(admission.BindBeforeACP) ||
		!passing(admission.RelayPeer) || !passing(life.OneUse) ||
		!passing(life.RestartReplayRefused) || !passing(life.FailedBindPreventsACP) ||
		!passing(life.StopCleanup) {
		return ErrUnqualified
	}
	return nil
}
