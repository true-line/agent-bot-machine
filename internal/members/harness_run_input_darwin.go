//go:build darwin

package members

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	launchDigest  = regexp.MustCompile("^[a-f0-9]{64}$")
	launchAdapter = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	launchID      = regexp.MustCompile("^ln_[0-9a-f]{24}$")
	launchSoul    = regexp.MustCompile("^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
	launchRole    = regexp.MustCompile("^[a-z][a-z0-9-]{0,31}$")
	// Souls generates a new 24-byte token for each member launch.
	launchToken    = regexp.MustCompile("^[0-9a-f]{48}$")
	errLaunchInput = errors.New("invalid harness launch request")
)

type harnessRunInput struct {
	PlanDigest, AdapterID, LaunchID, SoulID, MemberID, Role, MemberToken string
}

// A single bounded LF-delimited record precedes ACP on the private stdin pipe.
// Keep the returned reader for ACP: ReadSlice may already have buffered it.
// Never put the header or a decoding error containing input into a diagnostic.
func readHarnessRunInput(input io.Reader) (harnessRunInput, *bufio.Reader, error) {
	reader := bufio.NewReaderSize(input, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return harnessRunInput{}, nil, errLaunchInput
	}
	var request harnessRunInput
	fields := map[string]*string{
		"plan_digest": &request.PlanDigest, "adapter_id": &request.AdapterID,
		"launch_id": &request.LaunchID, "soul_id": &request.SoulID,
		"member_id": &request.MemberID, "role": &request.Role, "member_token": &request.MemberToken,
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return harnessRunInput{}, nil, errLaunchInput
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		target := fields[name]
		if err != nil || !ok || target == nil || decoder.Decode(target) != nil {
			return harnessRunInput{}, nil, errLaunchInput
		}
		delete(fields, name)
	}
	end, err := decoder.Token()
	if len(fields) != 0 || err != nil || end != json.Delim('}') {
		return harnessRunInput{}, nil, errLaunchInput
	}
	if _, err := decoder.Token(); err != io.EOF || !launchDigest.MatchString(request.PlanDigest) ||
		!launchAdapter.MatchString(request.AdapterID) || !launchID.MatchString(request.LaunchID) ||
		!launchSoul.MatchString(request.SoulID) || !launchAdapter.MatchString(request.MemberID) ||
		!launchRole.MatchString(request.Role) || !launchToken.MatchString(request.MemberToken) {
		return harnessRunInput{}, nil, errLaunchInput
	}
	return request, reader, nil
}

// Match the address reserved by HQ's launchMemberSocket, including its compact
// name for long account names. The installed rule selects the account, and HQ
// reserves the unique launch ID. Neither socket path is an input to the pipe.
func harnessRunSockets(account, id string) (broker, member string, err error) {
	if !accountName.MatchString(account) || !launchID.MatchString(id) {
		return "", "", errLaunchInput
	}
	dir := filepath.Join(DarwinBrokerDir, account)
	broker = filepath.Join(dir, "broker.sock")
	hex := id[3:]
	member = filepath.Join(dir, "member-"+hex+".sock")
	if len(member) > 103 {
		room := 103 - len(dir) - 1
		if room < 11 {
			return "", "", errLaunchInput
		}
		value, _ := new(big.Int).SetString(hex, 16)
		name := value.Text(36)
		name = strings.Repeat("0", 19-len(name)) + name
		if len(name) > room {
			name = name[len(name)-room:]
		}
		member = filepath.Join(dir, name)
	}
	return broker, member, nil
}
