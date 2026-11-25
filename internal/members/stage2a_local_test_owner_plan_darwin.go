//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"time"
)

const stage2aLocalTestOwnerPlanSchema = "agent-bot-machine/stage2a-observed-body-local-test-owner-plan/v1"

type stage2aLocalTestOwnerMember struct {
	MemberID               string `json:"member_id"`
	Role                   string `json:"role"`
	QualificationMode      string `json:"qualification_mode"`
	AdapterID              string `json:"adapter_id"`
	AdapterVersion         string `json:"adapter_version"`
	AdapterManifestRelpath string `json:"adapter_manifest_relpath"`
	AdapterManifestSHA256  string `json:"adapter_manifest_sha256"`
	CommandPath            string `json:"command_path"`
	CommandSHA256          string `json:"command_sha256"`
	AdjacentCLIPath        string `json:"adjacent_cli_path"`
	AdjacentCLISHA256      string `json:"adjacent_cli_sha256"`
}

type stage2aLocalTestHeaderShape struct {
	Schema           string            `json:"schema"`
	AllowExtra       bool              `json:"allow_extra"`
	Host             string            `json:"host"`
	Forbidden        []string          `json:"forbidden"`
	RequiredFixed    map[string]string `json:"required_fixed"`
	RequiredVolatile map[string]string `json:"required_volatile"`
}

type stage2aLocalTestAncillaryProfile struct {
	Schema               string                      `json:"schema"`
	BodyProfile          string                      `json:"body_profile"`
	MaxAncillary         int                         `json:"max_ancillary"`
	AncillaryHTTPStatus  int                         `json:"ancillary_http_status"`
	NormalizedBodySHA256 string                      `json:"normalized_body_sha256"`
	FirstHeaderShape     stage2aLocalTestHeaderShape `json:"first_header_shape"`
	FirstHeadersSHA256   string                      `json:"first_headers_sha256"`
	SecondHeaderShape    stage2aLocalTestHeaderShape `json:"second_header_shape"`
	SecondHeadersSHA256  string                      `json:"second_headers_sha256"`
	Order                []string                    `json:"order"`
	TargetAfter          []string                    `json:"target_after"`
}

// This object is root-reviewed input. Its exact canonical digest is joined
// to a separate local-test Q approval and root-produced install receipt.
// No field in it may be supplied by an HQ start or observed ingress request.
type stage2aLocalTestOwnerPlan struct {
	Schema                 string                           `json:"schema"`
	Enabled                bool                             `json:"enabled"`
	Revision               string                           `json:"revision"`
	SelectedMemberID       string                           `json:"selected_member_id"`
	Members                []stage2aLocalTestOwnerMember    `json:"members"`
	Model                  string                           `json:"model"`
	HTTPHost               string                           `json:"http_host"`
	MessagesQuery          string                           `json:"messages_query"`
	BodyProfile            string                           `json:"body_profile"`
	OwnerPromptSHA256      string                           `json:"owner_prompt_sha256"`
	RFirstBriefSHA256      string                           `json:"r_first_brief_sha256"`
	StaticProjectionSHA256 string                           `json:"static_projection_sha256"`
	ClientKeySHA256        string                           `json:"client_key_sha256"`
	HeaderShape            stage2aLocalTestHeaderShape      `json:"header_shape"`
	AncillaryProfile       stage2aLocalTestAncillaryProfile `json:"ancillary_profile"`
	ChildPathProfile       string                           `json:"child_path_profile"`
	RunnerHomeLexical      string                           `json:"runner_home_lexical"`
	ExpiresAt              string                           `json:"expires_at"`
}

func parseStage2aLocalTestOwnerPlan(raw []byte, fixture Stage2aBridgeQualification,
	approvedUntil time.Time) (stage2aLocalTestOwnerPlan, string, error) {
	var p stage2aLocalTestOwnerPlan
	if len(raw) == 0 || len(raw) > 64<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &p) != nil || !p.valid(fixture, approvedUntil) {
		return stage2aLocalTestOwnerPlan{}, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(p)
	if err != nil {
		return stage2aLocalTestOwnerPlan{}, "", errStage2aReservationAuthority
	}
	return p, stage2aReservationSHA256(canonical), nil
}

func (p stage2aLocalTestOwnerPlan) valid(fixture Stage2aBridgeQualification, approvedUntil time.Time) bool {
	if p.Schema != stage2aLocalTestOwnerPlanSchema || !p.Enabled ||
		!qualificationRevision.MatchString(p.Revision) ||
		!stage2aBindingID.MatchString(p.SelectedMemberID) || len(p.Members) != 2 ||
		!stage2aBindingID.MatchString(p.Model) ||
		!stage2aBindingID.MatchString(p.HTTPHost) ||
		!stage2aMessagesQuery.MatchString(p.MessagesQuery) ||
		!stage2aPrefixedDigest.MatchString(p.ClientKeySHA256) ||
		p.Model != fixture.Model || p.HTTPHost != fixture.HTTPHost ||
		p.MessagesQuery != fixture.MessagesQuery || p.ClientKeySHA256 != fixture.ClientKeySHA256 ||
		p.BodyProfile != "stage2a-stock-observed-local-test/v1" ||
		!stage2aPrefixedDigest.MatchString(p.OwnerPromptSHA256) ||
		!stage2aPrefixedDigest.MatchString(p.RFirstBriefSHA256) ||
		!stage2aPrefixedDigest.MatchString(p.StaticProjectionSHA256) ||
		!p.HeaderShape.valid("stage2a-observed-body-header-shape/v1", p.HTTPHost) ||
		!p.AncillaryProfile.valid(p.HTTPHost) || !approvedUntil.After(time.Time{}) {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || expires.After(approvedUntil) || !expires.After(time.Time{}) {
		return false
	}
	if p.ChildPathProfile != "per-start-runner-home/v1" ||
		!stage2aAbsolutePath(p.RunnerHomeLexical) ||
		path.Clean(p.RunnerHomeLexical) != p.RunnerHomeLexical {
		return false
	}
	if p.Members[0].MemberID == p.Members[1].MemberID ||
		p.Members[0].Role != "lead" || p.Members[1].Role != "specialist" ||
		p.Members[0].MemberID != p.SelectedMemberID ||
		p.Members[0].QualificationMode != "observed-body-local-test/v1" ||
		p.Members[1].QualificationMode != "disabled" {
		return false
	}
	for _, m := range p.Members {
		if !m.valid() {
			return false
		}
	}
	return true
}

type stage2aLocalTestChildPaths struct {
	CWDLexical    string
	CWDEmitted    string
	HomeLexical   string
	HomeEmitted   string
	MemoryLexical string
	MemoryEmitted string
}

// The root plan pins only the installed runner home and path profile. Start
// ID is unknown until A reserves a start, so A derives its child directory
// from the same per-start slot as stage2aChildEnvironment. The caller must
// still compare the live descriptor/realpath to these exact strings.
func stage2aLocalTestPathsForStart(p stage2aLocalTestOwnerPlan,
	runnerAccount, installationID, startID string) (stage2aLocalTestChildPaths, error) {
	var empty stage2aLocalTestChildPaths
	if p.ChildPathProfile != "per-start-runner-home/v1" ||
		!soulInstallationID.MatchString(installationID) || !soulStartID.MatchString(startID) ||
		runnerAccount != soulRunnerName(installationID) ||
		p.RunnerHomeLexical != darwinSoulRunnerHome(runnerAccount) {
		return empty, errStage2aReservationAuthority
	}
	root := path.Join(p.RunnerHomeLexical, "state", "child-"+soulEndpointStartSlot(installationID, startID))
	cwd := path.Join(root, "work")
	home := path.Join(root, "home")
	if !strings.HasPrefix(cwd, "/var/") {
		return empty, errStage2aReservationAuthority
	}
	emitted := "/private" + cwd
	memory := path.Join(home, ".claude", "projects", stage2aLocalTestProjectSlug(emitted), "memory") + "/"
	return stage2aLocalTestChildPaths{
		CWDLexical: cwd, CWDEmitted: emitted, HomeLexical: home, HomeEmitted: "/private" + home,
		MemoryLexical: memory, MemoryEmitted: "/private" + memory,
	}, nil
}

// The stock client's project directory replaces each non-alphanumeric byte
// in the emitted cwd with '-'. In particular, the runner account's '_' is
// replaced too; replacing slashes alone creates a path the client never uses.
func stage2aLocalTestProjectSlug(emittedCWD string) string {
	var slug strings.Builder
	for i := 0; i < len(emittedCWD); i++ {
		ch := emittedCWD[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			slug.WriteByte(ch)
		} else {
			slug.WriteByte('-')
		}
	}
	return slug.String()
}

func (m stage2aLocalTestOwnerMember) valid() bool {
	if !stage2aBindingID.MatchString(m.MemberID) ||
		!stage2aBindingID.MatchString(m.AdapterID) ||
		!stage2aBindingID.MatchString(m.AdapterVersion) ||
		m.AdapterManifestRelpath == "" || path.IsAbs(m.AdapterManifestRelpath) ||
		path.Clean(m.AdapterManifestRelpath) != m.AdapterManifestRelpath ||
		strings.HasPrefix(m.AdapterManifestRelpath, "../") ||
		!stage2aAbsolutePath(m.CommandPath) || !stage2aAbsolutePath(m.AdjacentCLIPath) ||
		m.CommandPath == m.AdjacentCLIPath {
		return false
	}
	return stage2aPrefixedDigest.MatchString(m.AdapterManifestSHA256) &&
		stage2aPrefixedDigest.MatchString(m.CommandSHA256) &&
		stage2aPrefixedDigest.MatchString(m.AdjacentCLISHA256)
}

func (h stage2aLocalTestHeaderShape) valid(schema, host string) bool {
	if h.Schema != schema || h.AllowExtra || h.Host != host ||
		!slices.Equal(h.Forbidden, []string{"authorization", "cookie", "proxy-authorization"}) ||
		len(h.RequiredFixed) == 0 || len(h.RequiredFixed) > 32 ||
		len(h.RequiredVolatile) == 0 || len(h.RequiredVolatile) > 8 {
		return false
	}
	for name, value := range h.RequiredFixed {
		if !stage2aLocalTestHeaderToken(name) || value == "" || len(value) > 512 ||
			strings.ContainsAny(value, "\r\n\x00") ||
			slices.Contains(h.Forbidden, name) || h.RequiredVolatile[name] != "" {
			return false
		}
	}
	for name, value := range h.RequiredVolatile {
		if !stage2aLocalTestHeaderToken(name) || value == "" || len(value) > 128 ||
			strings.ContainsAny(value, "\r\n\x00") ||
			slices.Contains(h.Forbidden, name) || h.RequiredFixed[name] != "" {
			return false
		}
	}
	return true
}

func stage2aLocalTestHeaderToken(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func (a stage2aLocalTestAncillaryProfile) valid(host string) bool {
	if a.Schema != "stage2a-stock-ancillary-local-test-profile/v2" ||
		a.BodyProfile != "stage2a-stock-ancillary-one-block/v1" ||
		a.MaxAncillary != 2 || a.AncillaryHTTPStatus != 422 ||
		!stage2aPrefixedDigest.MatchString(a.NormalizedBodySHA256) ||
		!stage2aPrefixedDigest.MatchString(a.FirstHeadersSHA256) ||
		!stage2aPrefixedDigest.MatchString(a.SecondHeadersSHA256) ||
		!slices.Equal(a.Order, []string{"first", "second"}) ||
		!slices.Equal(a.TargetAfter, []string{"first"}) ||
		!a.FirstHeaderShape.valid("stage2a-stock-ancillary-header-shape/v1", host) ||
		!a.SecondHeaderShape.valid("stage2a-stock-ancillary-header-shape/v1", host) {
		return false
	}
	for _, row := range []struct {
		shape  stage2aLocalTestHeaderShape
		digest string
	}{{a.FirstHeaderShape, a.FirstHeadersSHA256}, {a.SecondHeaderShape, a.SecondHeadersSHA256}} {
		raw, err := marshalStage2aReservationJCS(row.shape)
		if err != nil || stage2aReservationSHA256(raw) != row.digest {
			return false
		}
	}
	return true
}

func stage2aLocalTestOwnerPlanFromPolicy(raw json.RawMessage, fixture Stage2aBridgeQualification,
	approvedUntil time.Time) (stage2aLocalTestOwnerPlan, string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return stage2aLocalTestOwnerPlan{}, "", errStage2aReservationAuthority
	}
	return parseStage2aLocalTestOwnerPlan(raw, fixture, approvedUntil)
}
