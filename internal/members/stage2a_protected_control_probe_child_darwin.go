//go:build darwin

package members

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"
)

// RunStage2aProtectedControlProbeV1 is a fixed one-use negative control. The
// R-UID wrapper launches this very Machine binary under the installed child
// Seatbelt profile; the subcommand cannot alter that profile or widen it.
// Its result is raw observation, not an A signature or a physical gate pass.
func RunStage2aProtectedControlProbeV1() int {
	self, err := os.Executable()
	if err != nil || self != SoulLauncher || len(os.Args) != 2 ||
		os.Args[1] != stage2aProtectedControlProbeCommand ||
		os.Getuid() < 300 || os.Getuid() > 399 || os.Getuid() != os.Geteuid() ||
		os.Getgid() != os.Getuid() || os.Getgid() != os.Getegid() {
		return harnessRefused
	}
	if _, err := os.Stdout.Write([]byte{'R'}); err != nil {
		return harnessRefused
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, stage2aProtectedControlProbeLimit+1))
	if err != nil || len(raw) < 2 || len(raw) > stage2aProtectedControlProbeLimit ||
		raw[len(raw)-1] != '\n' || stage2aStrictJSON(bytes.TrimSuffix(raw, []byte{'\n'})) != nil {
		return harnessRefused
	}
	var request struct {
		Stage2aProtectedControlProbeSpec
		RelaySocket string `json:"relay_socket"`
	}
	if stage2aDecodeExact(bytes.TrimSuffix(raw, []byte{'\n'}), &request) != nil ||
		request.Schema != stage2aProtectedControlProbeSchema ||
		request.ProviderPort < 49152 || request.ProviderPort > 65535 ||
		request.ProviderPort != stage2aProtectedProviderPortV1(request.HQEpoch,
			request.InstallationID, request.StartID) ||
		!stage2aBindingID.MatchString(request.ProviderModel) ||
		!stage2aPrefixedDigest.MatchString(request.ProviderRequestSHA256) ||
		!stage2aAbsolutePath(request.RelaySocket) ||
		!stage2aAbsolutePath(request.SiblingTokenPath) ||
		!stage2aAbsolutePath(request.SiblingRelaySocket) ||
		request.RelaySocket == request.SiblingRelaySocket {
		return harnessRefused
	}
	result := stage2aProtectedControlProbeResult{
		Schema: stage2aProtectedControlProbeSchema, Kind: "negative-control",
		PID: os.Getpid(), UID: os.Getuid(),
		DirectIPv4: stage2aProtectedProbeDirectHTTP("tcp4", "127.0.0.1", request.ProviderPort,
			request.ProviderModel, request.ProviderRequestSHA256),
		DirectIPv6: stage2aProtectedProbeDirectHTTP("tcp6", "::1", request.ProviderPort,
			request.ProviderModel, request.ProviderRequestSHA256),
		AssignedRelay: stage2aProtectedProbeDial("unix", request.RelaySocket),
		SiblingSocket: stage2aProtectedProbeDial("unix", request.SiblingRelaySocket),
		SiblingToken:  stage2aProtectedProbeOpen(request.SiblingTokenPath),
		CapturedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > stage2aProtectedControlProbeLimit {
		return harnessRefused
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return harnessRefused
	}
	return 0
}

// A successful connection is deliberately reported as a refusal by the
// parent. The exact POST is what would reach HQ if confinement failed.
func stage2aProtectedProbeDirectHTTP(network, host string, port int, model, requestSHA string) string {
	if (network != "tcp4" && network != "tcp6") || port < 49152 || port > 65535 ||
		!stage2aBindingID.MatchString(model) || !stage2aPrefixedDigest.MatchString(requestSHA) {
		return "unproven"
	}
	body, err := json.Marshal(struct {
		Model         string `json:"model"`
		RequestSHA256 string `json:"request_sha256"`
	}{model, requestSHA})
	if err != nil {
		return "unproven"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+address+"/stage2a/local-provider/v1", bytes.NewReader(body))
	if err != nil {
		return "unproven"
	}
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(req)
	if response != nil {
		_ = response.Body.Close()
		return "connected"
	}
	if errors.Is(err, syscall.EPERM) {
		return "EPERM"
	}
	if errors.Is(err, syscall.EACCES) {
		return "EACCES"
	}
	return "unproven"
}

func stage2aProtectedProbeDial(network, address string) string {
	connection, err := net.DialTimeout(network, address, 250*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
		return "connected"
	}
	if errors.Is(err, syscall.EPERM) {
		return "EPERM"
	}
	if errors.Is(err, syscall.EACCES) {
		return "EACCES"
	}
	return "unproven"
}

func stage2aProtectedProbeOpen(path string) string {
	file, err := os.Open(path)
	if file != nil {
		_ = file.Close()
		return "opened"
	}
	if errors.Is(err, syscall.EPERM) {
		return "EPERM"
	}
	if errors.Is(err, syscall.EACCES) {
		return "EACCES"
	}
	return "unproven"
}
