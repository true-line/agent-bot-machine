//go:build darwin

package members

import "unicode/utf8"

// The owner reviews two explicit rows in the installed v3 policy. For the
// stock local fixture both rows repeat the same nonsecret client placeholder;
// later relay authorization must bind each row to its signed selector and
// independently A-attested CLI parent, never to this placeholder alone.
type stage2aMemberBridgeQualification struct {
	MemberID        string `json:"member_id"`
	Model           string `json:"model"`
	RequestSHA256   string `json:"request_sha256"`
	HeadersSHA256   string `json:"headers_sha256"`
	ClientKeySHA256 string `json:"client_key_sha256"`
	HTTPHost        string `json:"http_host"`
	MessagesQuery   string `json:"messages_query"`
	ResponseText    string `json:"response_text"`
}

func (r stage2aMemberBridgeQualification) qualification() Stage2aBridgeQualification {
	return Stage2aBridgeQualification{Model: r.Model, RequestSHA256: r.RequestSHA256,
		HeadersSHA256: r.HeadersSHA256, ClientKeySHA256: r.ClientKeySHA256,
		HTTPHost: r.HTTPHost, MessagesQuery: r.MessagesQuery, ResponseText: r.ResponseText}
}

func stage2aValidMemberBridgeQualificationRows(rows []stage2aMemberBridgeQualification,
	base Stage2aBridgeQualification) bool {
	if len(rows) != 2 || !stage2aBindingID.MatchString(rows[0].MemberID) ||
		!stage2aBindingID.MatchString(rows[1].MemberID) || rows[0].MemberID >= rows[1].MemberID ||
		!stage2aBindingID.MatchString(base.Model) ||
		!stage2aPrefixedDigest.MatchString(base.RequestSHA256) ||
		!stage2aPrefixedDigest.MatchString(base.HeadersSHA256) ||
		!stage2aPrefixedDigest.MatchString(base.ClientKeySHA256) ||
		base.ClientKeySHA256 != stage2aFixtureClientKeySHA256 ||
		!stage2aBindingID.MatchString(base.HTTPHost) ||
		!stage2aMessagesQuery.MatchString(base.MessagesQuery) ||
		len(base.ResponseText) == 0 || len(base.ResponseText) > 2048 ||
		!utf8.ValidString(base.ResponseText) {
		return false
	}
	return rows[0].qualification() == base && rows[1].qualification() == base
}

func stage2aMemberBridgeQualificationsMatchRoles(rows []stage2aMemberBridgeQualification,
	roles []stage2aHelloMember, base Stage2aBridgeQualification) bool {
	return len(roles) == 2 && stage2aValidMemberBridgeQualificationRows(rows, base) &&
		rows[0].MemberID == roles[0].MemberID && rows[1].MemberID == roles[1].MemberID
}
