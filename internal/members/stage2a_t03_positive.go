package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const stage2aT03PositiveSchema = "agent-bot/stage2a-t03-positive-receipt/v1"
const stage2aT03ProviderAlgorithm = "agent-bot-stage2a-local-provider-v1"

type Stage2aT03ArmRequest struct {
	Stage2aStopRequest
	Receipt Stage2aT03PositiveReceipt `json:"receipt"`
}

// The paired HQ request authenticates the relay completion and its provider
// observations together. A checks the receipt against the installed start
// before it can authorize any direct qualification stimulus.
type Stage2aT03PositiveReceipt struct {
	Schema                 string              `json:"schema"`
	ChildReceiptSHA256     string              `json:"child_receipt_sha256"`
	FinalizationSHA256     string              `json:"finalization_sha256"`
	BindReceiptSHA256      string              `json:"bind_receipt_sha256"`
	RelaySocket            string              `json:"relay_socket"`
	ProviderConfigSHA256   string              `json:"provider_config_sha256"`
	ProviderIPv4URL        string              `json:"provider_ipv4_url"`
	ProviderIPv6URL        string              `json:"provider_ipv6_url"`
	RequestSHA256          string              `json:"request_sha256"`
	Model                  string              `json:"model"`
	PromptSHA256           string              `json:"prompt_sha256"`
	ProviderReplySHA256    string              `json:"provider_reply_sha256"`
	ResponseWireSHA256     string              `json:"response_wire_sha256"`
	ResponseWireBytes      int                 `json:"response_wire_bytes"`
	HTTPStatus             int                 `json:"http_status"`
	CompletedAtMS          int64               `json:"completed_at_ms"`
	ProviderSelector       string              `json:"provider_selector"`
	ReachabilityIPv4SHA256 string              `json:"reachability_ipv4_sha256"`
	ReachabilityIPv6SHA256 string              `json:"reachability_ipv6_sha256"`
	IPv4RequestCount       uint64              `json:"ipv4_request_count"`
	IPv6RequestCount       uint64              `json:"ipv6_request_count"`
	Peer                   Stage2aT03RelayPeer `json:"peer"`
	PeerSHA256             string              `json:"peer_sha256"`
}

// Stage2aT03RelayPeer is B's rechecked Darwin audit-token observation of the
// accepted R-to-B socket peer and its direct parent. All fields are JSON
// integers in B's canonical peer record; A independently observes the live
// processes before accepting a protected positive receipt.
type Stage2aT03RelayPeer struct {
	UID                uint32 `json:"uid"`
	PID                int    `json:"pid"`
	PIDVersion         int    `json:"pid_version"`
	StartSeconds       int64  `json:"start_seconds"`
	StartMicros        int32  `json:"start_micros"`
	ParentPID          int    `json:"parent_pid"`
	ParentUID          uint32 `json:"parent_uid"`
	ParentStartSeconds int64  `json:"parent_start_seconds"`
	ParentStartMicros  int32  `json:"parent_start_micros"`
}

func (p Stage2aT03RelayPeer) valid() bool {
	return p.UID >= 300 && p.UID <= 399 && p.PID > 1 && p.PIDVersion > 0 &&
		p.StartSeconds > 0 && p.StartMicros >= 0 && p.StartMicros < 1_000_000 &&
		p.ParentPID > 1 && p.ParentPID != p.PID && p.ParentUID == p.UID &&
		p.ParentStartSeconds > 0 && p.ParentStartMicros >= 0 && p.ParentStartMicros < 1_000_000
}

func stage2aT03PeerCanonical(p Stage2aT03RelayPeer) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func ParseStage2aT03ArmRequest(raw []byte) (Stage2aT03ArmRequest, error) {
	var q Stage2aT03ArmRequest
	if err := decodeStage2aT03Request(raw, &q); err != nil ||
		!validStage2aStopRequest(q.Stage2aStopRequest) || !q.Receipt.valid() || !q.providerMatchesStart() {
		return Stage2aT03ArmRequest{}, errors.New("invalid protected T03 positive receipt")
	}
	return q, nil
}

func (r Stage2aT03PositiveReceipt) valid() bool {
	if r.Schema != stage2aT03PositiveSchema || r.HTTPStatus != 200 ||
		r.IPv4RequestCount > 1 || r.IPv6RequestCount > 1 || r.IPv4RequestCount+r.IPv6RequestCount != 1 ||
		r.ResponseWireBytes <= 0 || r.ResponseWireBytes > 1<<20 || r.CompletedAtMS <= 0 ||
		!stage2aAbsolutePath(r.RelaySocket) || len(r.RelaySocket) > 103 ||
		!stage2aBindingID.MatchString(r.Model) || r.ProviderSelector != stage2aT03ProviderAlgorithm {
		return false
	}
	for _, digest := range []string{r.ChildReceiptSHA256, r.FinalizationSHA256, r.BindReceiptSHA256,
		r.ProviderConfigSHA256, r.RequestSHA256, r.PromptSHA256, r.ProviderReplySHA256, r.ResponseWireSHA256,
		r.ReachabilityIPv4SHA256, r.ReachabilityIPv6SHA256, r.PeerSHA256} {
		if !stage2aPrefixedDigest.MatchString(digest) {
			return false
		}
	}
	peer, err := stage2aT03PeerCanonical(r.Peer)
	if err != nil || !r.Peer.valid() || fmt.Sprintf("sha256:%x", sha256.Sum256(peer)) != r.PeerSHA256 {
		return false
	}
	v4, ok4 := stage2aT03ParseLoopbackURL(r.ProviderIPv4URL, "127.0.0.1")
	v6, ok6 := stage2aT03ParseLoopbackURL(r.ProviderIPv6URL, "::1")
	return ok4 && ok6 && v4 == v6
}

func stage2aT03ParseLoopbackURL(raw, host string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != host || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.Host != net.JoinHostPort(host, u.Port()) || raw != "http://"+u.Host {
		return "", false
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	return u.Port(), err == nil && port > 0 && strconv.FormatUint(port, 10) == u.Port()
}

// The reviewed provider has one listener on each literal loopback family.
// Both addresses derive from the same paired, signed start selectors.
func stage2aT03ProviderURLs(q Stage2aStopRequest) (string, string) {
	digest := sha256.Sum256([]byte(stage2aT03ProviderAlgorithm + "\x00" +
		q.HQEpoch + "\x00" + q.InstallationID + "\x00" + q.StartID))
	port := strconv.Itoa(49152 + int(binary.BigEndian.Uint16(digest[:2]))%16384)
	return "http://127.0.0.1:" + port, "http://[::1]:" + port
}

func (q Stage2aT03ArmRequest) providerMatchesStart() bool {
	v4, v6 := stage2aT03ProviderURLs(q.Stage2aStopRequest)
	return q.Receipt.ProviderIPv4URL == v4 && q.Receipt.ProviderIPv6URL == v6
}

type Stage2aT03ReadyRequest struct {
	Stage2aStopRequest
	Ready Stage2aT03ProbeReady `json:"ready"`
}

func ParseStage2aT03ReadyRequest(raw []byte) (Stage2aT03ReadyRequest, error) {
	var q Stage2aT03ReadyRequest
	if err := decodeStage2aT03Request(raw, &q); err != nil || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aT03ReadyRequest{}, errors.New("invalid protected T03 ready")
	}
	return q, nil
}

func ParseStage2aT03SiblingCredentialWitnessRequest(raw []byte) (Stage2aT03SiblingCredentialWitnessRequest, error) {
	var q Stage2aT03SiblingCredentialWitnessRequest
	if err := decodeStage2aT03Request(raw, &q); err != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		q.Witness.Schema != "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1" ||
		!validStage2aLiveChallenge(q.Witness.ChallengeBase64URL) ||
		!stage2aPrefixedDigest.MatchString(q.Witness.PrimaryReservationSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.Witness.SiblingReservationSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.Witness.ChildReceiptSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.Witness.MetadataSHA256) ||
		q.Witness.LeaseSequence == 0 || q.Witness.LeaseSequence > (1<<53)-1 ||
		!stage2aAbsolutePath(q.Witness.CredentialPath) || q.Witness.ObservedAtMS <= 0 {
		return Stage2aT03SiblingCredentialWitnessRequest{}, errors.New("invalid protected T03 sibling credential witness")
	}
	return q, nil
}

func decodeStage2aT03Request(raw []byte, q any) error {
	invalid := errors.New("invalid protected T03 request")
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil {
		return invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(q) != nil || d.Decode(new(any)) != io.EOF {
		return invalid
	}
	return nil
}
