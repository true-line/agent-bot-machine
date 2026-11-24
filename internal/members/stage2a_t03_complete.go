package members

import "errors"

type Stage2aT03CompleteRequest struct {
	Stage2aStopRequest
	Result  Stage2aT03ProbeResult    `json:"result"`
	Network Stage2aT03NetworkReceipt `json:"network"`
}

type Stage2aT03NetworkReceipt struct {
	Schema                 string `json:"schema"`
	ChallengeBase64URL     string `json:"challenge_base64url"`
	ChildReceiptSHA256     string `json:"child_receipt_sha256"`
	ProbeLeaseSequence     uint64 `json:"probe_lease_sequence"`
	PositiveReceiptSHA256  string `json:"positive_receipt_sha256"`
	ReachabilityIPv4SHA256 string `json:"reachability_ipv4_sha256"`
	ReachabilityIPv6SHA256 string `json:"reachability_ipv6_sha256"`
	IPv4RequestsBefore     uint64 `json:"ipv4_requests_before"`
	IPv4RequestsAfter      uint64 `json:"ipv4_requests_after"`
	IPv6RequestsBefore     uint64 `json:"ipv6_requests_before"`
	IPv6RequestsAfter      uint64 `json:"ipv6_requests_after"`
	ObservedAtMS           int64  `json:"observed_at_ms"`
}

func ParseStage2aT03CompleteRequest(raw []byte) (Stage2aT03CompleteRequest, error) {
	var q Stage2aT03CompleteRequest
	if err := decodeStage2aT03Request(raw, &q); err != nil || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aT03CompleteRequest{}, errors.New("invalid protected T03 completion")
	}
	return q, nil
}
