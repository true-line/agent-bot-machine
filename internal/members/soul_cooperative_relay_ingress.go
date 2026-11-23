package members

const SoulCooperativeRelayIngressPurposeV3 = "agent-bot/soul-cooperative-relay-ingress/v3"

type SoulCooperativeRelayIngressRequestV3 struct {
	Stage2aStopRequest
	AttachSHA256        string `json:"attach_sha256"`
	MemberID            string `json:"member_id"`
	MemberLaunchID      string `json:"member_launch_id"`
	MemberSelector      string `json:"member_selector"`
	ReadySHA256         string `json:"ready_sha256"`
	BLeaseSHA256        string `json:"b_lease_sha256"`
	BLeaseSequence      uint64 `json:"b_lease_sequence"`
	MemberLeaseSHA256   string `json:"member_lease_sha256"`
	MemberLeaseSequence uint64 `json:"member_lease_sequence"`
	PeerSHA256          string `json:"peer_sha256"`
	Model               string `json:"model"`
	PromptSHA256        string `json:"prompt_sha256"`
}

type SoulCooperativeRelayIngressReplyV3 struct {
	ReceiptEnvelopeBase64URL string `json:"receipt_envelope_base64url"`
	ReceiptSHA256            string `json:"receipt_sha256"`
	Model                    string `json:"model"`
	RequestSHA256            string `json:"request_sha256"`
	ProviderConfigSHA256     string `json:"provider_config_sha256"`
	ConfigBase64URL          string `json:"config_base64url"`
	ResponseText             string `json:"response_text"`
	ExpiresAtMS              int64  `json:"expires_at_ms"`
}

func ParseSoulCooperativeRelayIngressRequestV3(raw []byte) (SoulCooperativeRelayIngressRequestV3, error) {
	var q SoulCooperativeRelayIngressRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.ReadySHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BLeaseSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.MemberLeaseSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.PeerSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.PromptSHA256) ||
		q.BLeaseSequence == 0 || q.MemberLeaseSequence == 0 ||
		(q.MemberID != "m_lead" && q.MemberID != "m_spec") ||
		!soulLaunchID.MatchString(q.MemberLaunchID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) ||
		!stage2aBindingID.MatchString(q.Model) {
		return SoulCooperativeRelayIngressRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
