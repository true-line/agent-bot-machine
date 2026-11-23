package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func ParseSoulCooperativeProvisionalMapRequest(raw []byte) (Stage2aMemberProvisionalMapRequest, error) {
	var q Stage2aMemberProvisionalMapRequest
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aMemberProvisionalMapRequest{}, errSoulCooperativeAuthority
	}
	_, _, err := decodeSoulCooperativeProvisionalMap(q)
	if err != nil {
		return Stage2aMemberProvisionalMapRequest{}, errSoulCooperativeAuthority
	}
	return q, nil
}

func decodeSoulCooperativeProvisionalMap(q Stage2aMemberProvisionalMapRequest) ([]byte,
	Stage2aProvisionalMemberMap, error) {
	var mapping Stage2aProvisionalMemberMap
	if !stage2aPrefixedDigest.MatchString(q.ProvisionalHQMappingSHA256) ||
		len(q.ProvisionalHQMappingBase64URL) == 0 ||
		len(q.ProvisionalHQMappingBase64URL) > base64.RawURLEncoding.EncodedLen(4096) {
		return nil, mapping, errSoulCooperativeAuthority
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.ProvisionalHQMappingBase64URL)
	if err != nil || len(raw) == 0 || len(raw) > 4096 ||
		base64.RawURLEncoding.EncodeToString(raw) != q.ProvisionalHQMappingBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != q.ProvisionalHQMappingSHA256 ||
		stage2aStrictJSON(raw) != nil || stage2aDecodeExact(raw, &mapping) != nil {
		return nil, Stage2aProvisionalMemberMap{}, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) ||
		mapping.Contract != "hq/v1" || mapping.Kind != "stage2a-provisional-member-map" ||
		mapping.SchemaVersion != 1 || mapping.ProfileInForce != "managed-cooperative" ||
		mapping.RuntimeState != "provisional" || mapping.ACPAuthority != "withheld" ||
		!stage2aPrefixedDigest.MatchString(mapping.AssignmentEnvelopeSHA256) ||
		!stage2aBindingID.MatchString(mapping.HostID) ||
		!soulInstallationID.MatchString(mapping.InstallationID) ||
		!soulIdentity.MatchString(mapping.SoulID) ||
		!soulStartID.MatchString(mapping.StartID) || !soulHQEpoch.MatchString(mapping.HQEpoch) ||
		len(mapping.Members) != 2 || mapping.Members[0].MemberID >= mapping.Members[1].MemberID ||
		mapping.Members[0].RuntimeID == mapping.Members[1].RuntimeID ||
		mapping.Members[0].ChannelBinding == mapping.Members[1].ChannelBinding {
		return nil, Stage2aProvisionalMemberMap{}, errSoulCooperativeAuthority
	}
	for _, member := range mapping.Members {
		if !stage2aBindingID.MatchString(member.MemberID) ||
			!stage2aBindingID.MatchString(member.RuntimeID) ||
			!stage2aProvisionalChannelBinding.MatchString(member.ChannelBinding) ||
			!stage2aMemberSelectorPattern.MatchString(member.MemberSelector) {
			return nil, Stage2aProvisionalMemberMap{}, errSoulCooperativeAuthority
		}
	}
	issued, e1 := time.Parse(time.RFC3339Nano, mapping.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(issued) || expires.Sub(issued) > 20*time.Second {
		return nil, Stage2aProvisionalMemberMap{}, errSoulCooperativeAuthority
	}
	return raw, mapping, nil
}
