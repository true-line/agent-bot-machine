// Fixed ACP test adapter for a disposable Darwin qualification runner.
// A prompt authenticates to the assigned Souls socket and binds the assigned
// broker. It never evaluates prompt text, spawns commands, or emits credentials.
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const context = "agent-bot-hq/bind/v1"

var invalid = errors.New("fixture operation unavailable")
var noncePattern = regexp.MustCompile("^[a-f0-9]{64}$")
var bindingPattern = regexp.MustCompile("^[A-Za-z0-9_-]{16,128}$")
var runtimePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
var soulPattern = regexp.MustCompile("^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")

type local struct {
	net.Conn
	input    *bufio.Reader
	sequence int
}

func connect(path string) (*local, error) {
	if !filepath.IsAbs(path) || len(path) > 103 {
		return nil, invalid
	}
	c, e := net.DialTimeout("unix", path, 2*time.Second)
	if e != nil {
		return nil, invalid
	}
	if e = c.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		c.Close()
		return nil, invalid
	}
	return &local{Conn: c, input: bufio.NewReaderSize(c, 64*1024+1)}, nil
}
func (c *local) request(op string, payload any, result any) error {
	c.sequence++
	request := struct {
		ID      int    `json:"id"`
		Op      string `json:"op"`
		Payload any    `json:"payload"`
	}{c.sequence, op, payload}
	if e := json.NewEncoder(c.Conn).Encode(request); e != nil {
		return invalid
	}
	line, e := c.input.ReadSlice('\n')
	if e != nil {
		return invalid
	}
	var response struct {
		ID     int
		OK     bool
		Result json.RawMessage
	}
	if json.Unmarshal(line, &response) != nil || response.ID != request.ID || !response.OK || json.Unmarshal(response.Result, result) != nil {
		return invalid
	}
	return nil
}
func bind() error {
	entry, e := connect(os.Getenv("AGENT_BOT_SOULS_SOCKET"))
	if e != nil {
		return e
	}
	defer entry.Close()
	var identity struct {
		Soul   string `json:"soul_id"`
		Member string `json:"member_id"`
		Role   string `json:"role"`
	}
	if e = entry.request("hello", map[string]string{"token": os.Getenv("AGENT_BOT_SOULS_MEMBER_TOKEN")}, &identity); e != nil || !soulPattern.MatchString(identity.Soul) || identity.Member != os.Getenv("AGENT_BOT_SOULS_MEMBER_ID") || identity.Role != os.Getenv("AGENT_BOT_SOULS_ROLE") {
		return invalid
	}
	var runtime struct {
		ID      string `json:"runtime_id"`
		Binding string `json:"channel_binding"`
		Epoch   int    `json:"installation_epoch"`
		Lease   int    `json:"lease_generation"`
	}
	if e = entry.request("runtime", struct{}{}, &runtime); e != nil || !runtimePattern.MatchString(runtime.ID) || !bindingPattern.MatchString(runtime.Binding) || runtime.Epoch < 1 || runtime.Lease < 1 {
		return invalid
	}
	broker, e := connect(os.Getenv("AGENT_BOT_SOULS_BROKER"))
	if e != nil {
		return e
	}
	defer broker.Close()
	var challenge struct {
		ID                        string `json:"runtime_id"`
		Algorithm, Context, Nonce string
	}
	if e = broker.request("bind.challenge", map[string]string{"runtime_id": runtime.ID}, &challenge); e != nil || challenge.ID != runtime.ID || challenge.Algorithm != "hmac-sha256" || challenge.Context != context || !noncePattern.MatchString(challenge.Nonce) {
		return invalid
	}
	mac := hmac.New(sha256.New, []byte(runtime.Binding))
	io.WriteString(mac, context+"\n"+challenge.Nonce+"\n"+runtime.ID)
	var result struct {
		ID string `json:"runtime_id"`
	}
	if e = broker.request("bind", map[string]string{"runtime_id": runtime.ID, "proof": hex.EncodeToString(mac.Sum(nil))}, &result); e != nil || result.ID != runtime.ID {
		return invalid
	}
	return nil
}

// The controller keeps these reachable listeners open outside the sandbox.
// A timeout or connection refusal is not evidence of policy enforcement.
func denied(network, address string) error {
	c, err := net.DialTimeout(network, address, 2*time.Second)
	if err == nil {
		c.Close()
		return invalid
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		return invalid
	}
	return nil
}

func probe(ipv4, ipv6 int, sibling string) error {
	if ipv4 < 1 || ipv4 > 65535 || ipv6 < 1 || ipv6 > 65535 ||
		!filepath.IsAbs(sibling) || filepath.Dir(sibling) != filepath.Dir(os.Getenv("AGENT_BOT_SOULS_SOCKET")) ||
		sibling == os.Getenv("AGENT_BOT_SOULS_SOCKET") {
		return invalid
	}
	for _, target := range []struct{ network, address string }{
		{"tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(ipv4))},
		{"tcp6", net.JoinHostPort("::1", strconv.Itoa(ipv6))},
		{"unix", sibling},
	} {
		if denied(target.network, target.address) != nil {
			return invalid
		}
	}
	return nil
}
func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	read := bufio.NewScanner(os.Stdin)
	read.Buffer(make([]byte, 4096), 64*1024)
	out := json.NewEncoder(os.Stdout)
	initialized, session := false, false
	for read.Scan() {
		var msg struct {
			JSONRPC string
			ID      json.RawMessage
			Method  string
			Params  struct {
				SessionID string `json:"sessionId"`
				Probe     struct {
					IPv4Port int    `json:"ipv4_port"`
					IPv6Port int    `json:"ipv6_port"`
					Sibling  string `json:"sibling"`
				} `json:"probe"`
			}
		}
		if json.Unmarshal(read.Bytes(), &msg) != nil || msg.JSONRPC != "2.0" {
			os.Exit(1)
		}
		if len(msg.ID) == 0 || bytes.Equal(msg.ID, []byte("null")) {
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": msg.ID}
		switch {
		case msg.Method == "initialize" && !initialized:
			response["result"] = map[string]any{"protocolVersion": 1, "agentCapabilities": struct{}{}, "authMethods": []string{}}
			initialized = true
		case msg.Method == "session/new" && initialized && !session:
			response["result"] = map[string]string{"sessionId": "fixture-session"}
			session = true
		case msg.Method == "session/prompt" && session && msg.Params.SessionID == "fixture-session":
			if probe(msg.Params.Probe.IPv4Port, msg.Params.Probe.IPv6Port, msg.Params.Probe.Sibling) != nil || bind() != nil {
				response["error"] = map[string]any{"code": -32603, "message": "fixture member bind unavailable"}
			} else {
				response["result"] = map[string]string{"stopReason": "end_turn"}
			}
		default:
			response["error"] = map[string]any{"code": -32601, "message": "unsupported fixture operation"}
		}
		if out.Encode(response) != nil {
			os.Exit(1)
		}
	}
	if read.Err() != nil {
		os.Exit(1)
	}
	// Remain alive after ACP EOF. The launcher must stop this process group;
	// a natural fixture exit cannot count as cutoff evidence.
	time.Sleep(20 * time.Second)
}
