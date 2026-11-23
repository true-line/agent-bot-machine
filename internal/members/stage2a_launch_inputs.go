package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const stage2aLaunchPurpose = "agent-bot/stage2a-launch-inputs/v1"

const (
	stage2aStockCLIPath      = "runtime/bin/claude"
	stage2aStockCLISHA256    = "e85547190ef8cd983033ba61b17194045a6fea00035da349efeabed86badacc9"
	stage2aStockCLISizeBytes = uint64(354630016)
	stage2aStockCLIMaxBytes  = uint64(384 << 20)
)

var stage2aEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var stage2aCDHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Stage2aLaunchInputRecords holds the full portable launch-input OBJECT in
// soul-contracts machine/v1. It cannot prove the projected file bytes, system
// images, process code closure or immutable snapshot custody by itself.
type Stage2aLaunchInputRecords struct {
	Files               []Stage2aDefinitionRecord `json:"files"`
	HostProjection      Stage2aHostProjection     `json:"host_projection"`
	SelectedCommand     string                    `json:"selected_command"`
	Argv                []string                  `json:"argv"`
	Environment         map[string]string         `json:"environment"`
	EffectiveConfig     map[string]any            `json:"effective_config"`
	SystemImages        Stage2aSystemImages       `json:"system_images"`
	SandboxPolicyDigest string                    `json:"sandbox_policy_digest"`
	ComponentDigests    map[string]string         `json:"component_digests"`
	AdapterTransport    string                    `json:"adapter_transport,omitempty"`
}

type Stage2aHostProjection struct {
	Adapters     map[string]any `json:"adapters"`
	Installation map[string]any `json:"installation"`
}

type Stage2aSystemImages struct {
	ProductVersion string               `json:"product_version"`
	BuildVersion   string               `json:"build_version"`
	DarwinKernel   string               `json:"darwin_kernel"`
	Selected       []Stage2aSystemImage `json:"selected"`
}

type Stage2aSystemImage struct {
	Path               string `json:"path"`
	SigningRequirement string `json:"signing_requirement"`
	CDHash             string `json:"cdhash"`
}

func stage2aAbsolutePath(p string) bool {
	if len(p) < 2 || len(p) > 4096 || p[0] != '/' || strings.Contains(p, "\\") ||
		strings.Contains(p, "//") || path.Clean(p) != p {
		return false
	}
	for i := range p {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// stage2aStrictJSON checks duplicate keys and the contract's bounded nested
// JSON shape after a typed producer has serialized its object. This avoids
// accepting a RawMessage hidden in an otherwise ordinary map value.
func stage2aStrictJSON(raw []byte) error {
	return stage2aStrictJSONBounded(raw, 1<<20, 4096)
}

// V3 inventory sidecars contain hundreds of individually reviewed file rows.
// Keep the v1/v2 parser budget unchanged; only the sidecar reader may request
// a larger explicit node budget for those complete inventories.
func stage2aStrictJSONBounded(raw []byte, maxBytes, maxNodes int) error {
	if maxBytes <= 0 || maxNodes <= 0 || len(raw) == 0 || len(raw) > maxBytes ||
		!utf8.Valid(raw) || !json.Valid(raw) ||
		!stage2aValidJSONSurrogates(raw) {
		return errors.New("invalid Stage 2a JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var read func(int) error
	read = func(depth int) error {
		if depth > 16 || nodes >= maxNodes {
			return errors.New("Stage 2a JSON exceeds nesting or node limit")
		}
		nodes++
		token, err := d.Token()
		if err != nil {
			return err
		}
		if value, ok := token.(json.Number); ok {
			number, err := strconv.ParseFloat(string(value), 64)
			if err != nil || math.IsInf(number, 0) || math.IsNaN(number) ||
				math.Abs(number) > (1<<53)-1 {
				return errors.New("Stage 2a JSON number exceeds exact JCS range")
			}
			return nil
		}
		switch token {
		case json.Delim('{'):
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return errors.New("duplicate or invalid Stage 2a JSON key")
				}
				keys[name] = true
				if err := read(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := read(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return nil
		}
	}
	if err := read(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Stage 2a JSON has trailing data")
	}
	return nil
}

// encoding/json accepts unpaired UTF-16 surrogate escapes and decodes them
// as U+FFFD. Inspect the original quoted bytes before Token or Unmarshal can
// erase the difference between an invalid escaped input and an approved rune.
func stage2aValidJSONSurrogates(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted || i+1 >= len(raw) {
				return false
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return false
			}
			first, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if first >= 0xdc00 && first <= 0xdfff {
				return false
			}
			if first >= 0xd800 && first <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				second, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if err != nil || second < 0xdc00 || second > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return !quoted
}

func stage2aJSONSize(value any, max int) bool {
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= max
}

// encoding/json replaces invalid UTF-8 in Go strings with U+FFFD. Validate
// every free-form string before marshalling so distinct observed exec or host
// bytes cannot collapse onto the owner's approved replacement character.
// Host projections and effective config are parsed JSON values; custom
// marshalers are refused because their source strings cannot be inspected.
func stage2aValidJSONStrings(value any, depth int, nodes *int) bool {
	if depth > 16 || *nodes >= 4096 {
		return false
	}
	(*nodes)++
	switch v := value.(type) {
	case nil, bool, float32, float64,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	case string:
		return utf8.ValidString(v)
	case json.Number:
		return utf8.ValidString(string(v))
	case json.RawMessage:
		return stage2aStrictJSON(v) == nil
	case []any:
		for _, item := range v {
			if !stage2aValidJSONStrings(item, depth+1, nodes) {
				return false
			}
		}
		return true
	case []string:
		for _, item := range v {
			if !stage2aValidJSONStrings(item, depth+1, nodes) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, item := range v {
			if !utf8.ValidString(key) || !stage2aValidJSONStrings(item, depth+1, nodes) {
				return false
			}
		}
		return true
	case map[string]string:
		for key, item := range v {
			if !utf8.ValidString(key) || !stage2aValidJSONStrings(item, depth+1, nodes) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func stage2aValidLaunchStrings(input Stage2aLaunchInputRecords) bool {
	for _, arg := range input.Argv {
		if !utf8.ValidString(arg) {
			return false
		}
	}
	for key, value := range input.Environment {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return false
		}
	}
	images := input.SystemImages
	if !utf8.ValidString(images.ProductVersion) || !utf8.ValidString(images.BuildVersion) ||
		!utf8.ValidString(images.DarwinKernel) {
		return false
	}
	for _, image := range images.Selected {
		if !utf8.ValidString(image.SigningRequirement) {
			return false
		}
	}
	nodes := 0
	return stage2aValidJSONStrings(input.HostProjection.Adapters, 0, &nodes) &&
		stage2aValidJSONStrings(input.HostProjection.Installation, 0, &nodes) &&
		stage2aValidJSONStrings(input.EffectiveConfig, 0, &nodes)
}

// This exact oversized stock CLI is admitted for measurement only. The
// reviewed plan, frozen manifest, sealed R row and installed bytes still
// have to join before a one-use start can be authorized.
func stage2aQualifiedStockCLIRecord(file Stage2aDefinitionRecord) bool {
	return file.Path == stage2aStockCLIPath && file.Kind == "regular" && file.Mode == "0550" &&
		file.Size != nil && *file.Size == stage2aStockCLISizeBytes &&
		*file.Size <= stage2aStockCLIMaxBytes && file.SHA256 == stage2aStockCLISHA256
}

func stage2aLaunchFiles(files []Stage2aDefinitionRecord) (map[string]bool, error) {
	invalid := errors.New("invalid Stage 2a launch-input file records")
	if len(files) == 0 || len(files) > 64 {
		return nil, invalid
	}
	digests := make(map[string]bool, len(files))
	aliases := make(map[string]bool, len(files))
	filesSeen := make(map[string]bool, len(files))
	directories := make(map[string]bool, len(files))
	children := map[string]map[string]string{}
	var previous string
	var total uint64
	hostFiles := map[string]bool{"host/adapters.json": false, "host/installation.json": false}
	for i, file := range files {
		if !stage2aRecordPath(file.Path) || !stage2aReadOnlyMode(file.Mode) ||
			file.Kind != "regular" || file.Size == nil || file.SHA256 == "" ||
			!soulDigest.MatchString(file.SHA256) ||
			(*file.Size > stage2aMaxFileBytes && !stage2aQualifiedStockCLIRecord(file)) ||
			total > stage2aMaxTotalBytes-*file.Size ||
			(i != 0 && file.Path <= previous) || aliases[strings.ToLower(file.Path)] {
			return nil, invalid
		}
		total += *file.Size
		parent := ""
		parts := strings.Split(file.Path, "/")
		for partIndex, part := range parts {
			if children[parent] == nil {
				children[parent] = map[string]string{}
			}
			folded := strings.ToLower(part)
			if stored, exists := children[parent][folded]; exists && stored != part {
				return nil, invalid
			}
			children[parent][folded] = part
			parent = path.Join(parent, part)
			if partIndex < len(parts)-1 {
				if filesSeen[parent] {
					return nil, invalid
				}
				directories[parent] = true
			}
		}
		if directories[file.Path] {
			return nil, invalid
		}
		filesSeen[file.Path] = true
		if _, required := hostFiles[file.Path]; required {
			if *file.Size > 64<<10 {
				return nil, invalid
			}
			hostFiles[file.Path] = true
		}
		previous = file.Path
		aliases[strings.ToLower(file.Path)] = true
		digests["sha256:"+file.SHA256] = true
	}
	for _, present := range hostFiles {
		if !present {
			return nil, invalid
		}
	}
	return digests, nil
}

// Stage2aLaunchInputDigest validates and hashes the complete launch-input
// object. A future root producer must compare its parsed host projection
// against separately opened JSON files, its named digests against actual
// selected bytes/processes, and every value against a root-receipted plan.
func Stage2aLaunchInputDigest(input Stage2aLaunchInputRecords) (string, []byte, error) {
	invalid := errors.New("invalid Stage 2a launch-input records")
	digests, err := stage2aLaunchFiles(input.Files)
	images := input.SystemImages
	if err != nil || !stage2aAbsolutePath(input.SelectedCommand) ||
		len(input.Argv) == 0 || len(input.Argv) > 128 || input.Argv[0] != input.SelectedCommand ||
		len(input.Environment) > 256 || input.Environment == nil ||
		len(input.HostProjection.Adapters) > 256 || input.HostProjection.Adapters == nil ||
		len(input.HostProjection.Installation) > 256 || input.HostProjection.Installation == nil ||
		len(input.EffectiveConfig) > 256 || input.EffectiveConfig == nil ||
		(input.EffectiveConfig["profile"] != "managed-protected" &&
			input.EffectiveConfig["profile"] != "managed-cooperative") ||
		(input.EffectiveConfig["profile"] == "managed-protected" && input.AdapterTransport != "") ||
		(input.AdapterTransport != "" && input.AdapterTransport != "brokered-b" &&
			input.AdapterTransport != "direct-comms") ||
		len(images.Selected) == 0 || len(images.Selected) > 256 ||
		!stage2aValidLaunchStrings(input) ||
		!stage2aJSONSize(input.HostProjection.Adapters, 64<<10) ||
		!stage2aJSONSize(input.HostProjection.Installation, 64<<10) ||
		!stage2aJSONSize(input.EffectiveConfig, 64<<10) ||
		!stage2aJSONSize(input.Environment, 64<<10) ||
		!stage2aJSONSize(input.Argv, 64<<10) {
		return "", nil, invalid
	}
	for _, arg := range input.Argv {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return "", nil, invalid
		}
	}
	for key, value := range input.Environment {
		if key == "B_ONLY_TOKEN" || !stage2aEnvName.MatchString(key) ||
			len(value) > 8192 || strings.ContainsRune(value, 0) {
			return "", nil, invalid
		}
	}
	if len(images.ProductVersion) == 0 || len(images.ProductVersion) > 128 ||
		len(images.BuildVersion) == 0 || len(images.BuildVersion) > 128 ||
		len(images.DarwinKernel) == 0 || len(images.DarwinKernel) > 128 ||
		!stage2aJSONSize(images, 512<<10) {
		return "", nil, invalid
	}
	previous := ""
	imageAliases := make(map[string]bool, len(images.Selected))
	for i, image := range images.Selected {
		if !stage2aAbsolutePath(image.Path) || (i != 0 && image.Path <= previous) ||
			imageAliases[strings.ToLower(image.Path)] ||
			len(image.SigningRequirement) == 0 || len(image.SigningRequirement) > 4096 ||
			!stage2aCDHash.MatchString(image.CDHash) {
			return "", nil, invalid
		}
		imageAliases[strings.ToLower(image.Path)] = true
		previous = image.Path
	}
	for _, arg := range []string{"machine", "hq", "souls", "bridge", "comms_broker", "adapter", "harness", "test_provider"} {
		value := input.ComponentDigests[arg]
		if !digests[value] {
			return "", nil, invalid
		}
	}
	if len(input.ComponentDigests) != 8 || !digests[input.SandboxPolicyDigest] {
		return "", nil, invalid
	}
	raw, err := json.Marshal(input)
	if err != nil || stage2aStrictJSON(raw) != nil {
		return "", nil, invalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 1<<20 {
		return "", nil, invalid
	}
	sum := sha256.Sum256(append([]byte(stage2aLaunchPurpose+"\x00"), canonical...))
	return fmt.Sprintf("sha256:%x", sum), canonical, nil
}

// CheckStage2aApprovedLaunchInputs compares the entire portable object with
// an independently sourced owner-approved one. This has no launch authority.
func CheckStage2aApprovedLaunchInputs(observed, approved Stage2aLaunchInputRecords) (string, error) {
	got, raw, err := Stage2aLaunchInputDigest(observed)
	if err != nil {
		return "", err
	}
	_, want, err := Stage2aLaunchInputDigest(approved)
	if err != nil || !bytes.Equal(raw, want) {
		return "", errors.New("Stage 2a launch inputs differ from owner-approved object")
	}
	return got, nil
}

// CheckStage2aHostProjectionBytes binds the separately hashed raw host JSON
// records to the parsed values in the full launch-input object. The caller
// must supply these bytes from pinned, no-follow snapshot descriptors and
// verify the snapshot's root custody and identity independently.
func CheckStage2aHostProjectionBytes(input Stage2aLaunchInputRecords, adapters, installation []byte) error {
	if _, _, err := Stage2aLaunchInputDigest(input); err != nil {
		return errors.New("invalid Stage 2a launch inputs for host projection")
	}
	for _, item := range []struct {
		path     string
		raw      []byte
		expected map[string]any
	}{
		{"host/adapters.json", adapters, input.HostProjection.Adapters},
		{"host/installation.json", installation, input.HostProjection.Installation},
	} {
		if len(item.raw) == 0 || len(item.raw) > 64<<10 || stage2aStrictJSON(item.raw) != nil {
			return errors.New("invalid Stage 2a host projection JSON")
		}
		var record *Stage2aDefinitionRecord
		for i := range input.Files {
			if input.Files[i].Path == item.path {
				record = &input.Files[i]
				break
			}
		}
		sum := sha256.Sum256(item.raw)
		if record == nil || record.Size == nil || *record.Size != uint64(len(item.raw)) ||
			record.SHA256 != fmt.Sprintf("%x", sum) {
			return errors.New("Stage 2a host projection bytes differ from measured file")
		}
		var parsed map[string]any
		if err := json.Unmarshal(item.raw, &parsed); err != nil || parsed == nil {
			return errors.New("invalid Stage 2a host projection object")
		}
		actual, err := jsoncanonicalizer.Transform(item.raw)
		if err != nil {
			return errors.New("invalid Stage 2a host projection canonical JSON")
		}
		expectedRaw, err := json.Marshal(item.expected)
		if err != nil || stage2aStrictJSON(expectedRaw) != nil {
			return errors.New("invalid Stage 2a expected host projection")
		}
		want, err := jsoncanonicalizer.Transform(expectedRaw)
		if err != nil || !bytes.Equal(actual, want) {
			return errors.New("Stage 2a host projection differs from parsed approved value")
		}
	}
	return nil
}
