//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

var stage2aQualificationTokenV1 = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func stage2aQualificationKeysV1(raw []byte, required []string, optional string) (map[string]json.RawMessage, error) {
	if stage2aQualificationCanonical(raw) != nil {
		return nil, errStage2aQualificationFrame
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errStage2aQualificationFrame
	}
	if len(fields) != len(required) && !(optional != "" && len(fields) == len(required)+1 && fields[optional] != nil) {
		return nil, errStage2aQualificationFrame
	}
	for _, key := range required {
		if fields[key] == nil {
			return nil, errStage2aQualificationFrame
		}
	}
	return fields, nil
}

type stage2aQualificationProcessRequestV1 struct {
	Role string `json:"role"`
	PID  int    `json:"pid"`
}
type stage2aQualificationPathRequestV1 struct {
	Role string `json:"role"`
	Path string `json:"path"`
}
type stage2aQualificationStimulusRefV1 struct {
	URI    string `json:"uri"`
	SHA256 string `json:"sha256"`
}
type stage2aQualificationObserveV1 struct {
	Schema      string                                 `json:"schema"`
	Kind        string                                 `json:"kind"`
	SessionID   string                                 `json:"session_id"`
	Sequence    int                                    `json:"sequence"`
	Gate        string                                 `json:"gate"`
	Phase       string                                 `json:"phase"`
	EventID     string                                 `json:"event_id"`
	Processes   []stage2aQualificationProcessRequestV1 `json:"processes"`
	Paths       []stage2aQualificationPathRequestV1    `json:"paths"`
	StimulusRef *stage2aQualificationStimulusRefV1     `json:"stimulus_ref,omitempty"`
}

func validateStage2aQualificationObservationV1(requestRaw, responseRaw []byte,
	sessionID, challengeSHA string, sequence int, profile string, pathRoots []string) error {
	requestFields, err := stage2aQualificationKeysV1(requestRaw,
		[]string{"schema", "kind", "session_id", "sequence", "gate", "phase", "event_id", "processes", "paths"}, "stimulus_ref")
	if err != nil {
		return errStage2aQualificationFrame
	}
	responseFields, err := stage2aQualificationKeysV1(responseRaw,
		[]string{"schema", "kind", "session_id", "challenge_sha256", "sequence", "request_sha256", "captured_at", "gate", "phase", "event_id", "processes", "paths"}, "stimulus_ref")
	if err != nil {
		return errStage2aQualificationFrame
	}
	var request stage2aQualificationObserveV1
	var response struct {
		Schema          string            `json:"schema"`
		Kind            string            `json:"kind"`
		SessionID       string            `json:"session_id"`
		ChallengeSHA256 string            `json:"challenge_sha256"`
		Sequence        int               `json:"sequence"`
		RequestSHA256   string            `json:"request_sha256"`
		CapturedAt      string            `json:"captured_at"`
		Gate            string            `json:"gate"`
		Phase           string            `json:"phase"`
		EventID         string            `json:"event_id"`
		Processes       []json.RawMessage `json:"processes"`
		Paths           []json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(requestRaw, &request) != nil || json.Unmarshal(responseRaw, &response) != nil ||
		request.Schema != stage2aQualificationSchemaV1 || request.Kind != "observe" ||
		request.SessionID != sessionID || request.Sequence != sequence || sequence <= 0 || sequence > 1024 ||
		response.Schema != stage2aQualificationSchemaV1 || response.Kind != "observation" ||
		response.SessionID != sessionID || response.Sequence != sequence ||
		response.ChallengeSHA256 != challengeSHA || response.RequestSHA256 != stage2aQualificationSHA256(requestRaw) ||
		!stage2aQualificationTimestampV1.MatchString(response.CapturedAt) ||
		response.Gate != request.Gate || response.Phase != request.Phase || response.EventID != request.EventID ||
		!stage2aQualificationTokenV1.MatchString(request.Phase) || !stage2aQualificationTokenV1.MatchString(request.EventID) ||
		len(request.Processes) > 16 || len(request.Paths) > 32 || len(response.Processes) != len(request.Processes) ||
		len(response.Paths) != len(request.Paths) ||
		(profile == "managed-protected" && request.Gate == "T21") ||
		(profile == "managed-cooperative" && request.Gate != "T21") ||
		(request.Gate != "T01" && request.Gate != "T02" && request.Gate != "T03" && request.Gate != "T21") {
		return errStage2aQualificationFrame
	}
	if _, err := time.Parse(time.RFC3339Nano, response.CapturedAt); err != nil {
		return errStage2aQualificationFrame
	}
	if (requestFields["stimulus_ref"] == nil) != (responseFields["stimulus_ref"] == nil) ||
		requestFields["stimulus_ref"] != nil && !bytes.Equal(requestFields["stimulus_ref"], responseFields["stimulus_ref"]) {
		return errStage2aQualificationFrame
	}
	if request.StimulusRef != nil && (!stage2aQualificationPrintable(request.StimulusRef.URI, 512) ||
		!stage2aQualificationDigest(request.StimulusRef.SHA256)) {
		return errStage2aQualificationFrame
	}
	var rawProcesses, rawPaths []json.RawMessage
	if json.Unmarshal(requestFields["processes"], &rawProcesses) != nil ||
		json.Unmarshal(requestFields["paths"], &rawPaths) != nil ||
		len(rawProcesses) != len(request.Processes) || len(rawPaths) != len(request.Paths) {
		return errStage2aQualificationFrame
	}
	if requestFields["stimulus_ref"] != nil {
		if _, err := stage2aQualificationKeysV1(requestFields["stimulus_ref"], []string{"uri", "sha256"}, ""); err != nil {
			return errStage2aQualificationFrame
		}
	}
	for i, req := range request.Processes {
		if _, err := stage2aQualificationKeysV1(rawProcesses[i], []string{"role", "pid"}, ""); err != nil {
			return errStage2aQualificationFrame
		}
		if !stage2aQualificationTokenV1.MatchString(req.Role) || req.PID <= 0 || req.PID > 2147483647 {
			return errStage2aQualificationFrame
		}
		fields, err := stage2aQualificationKeysV1(response.Processes[i], []string{"role", "pid", "status", "stdout", "stderr"}, "")
		if err != nil {
			return errStage2aQualificationFrame
		}
		var observed struct {
			Role   string `json:"role"`
			PID    int    `json:"pid"`
			Status int    `json:"status"`
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
		}
		if json.Unmarshal(response.Processes[i], &observed) != nil || len(fields) != 5 ||
			observed.Role != req.Role || observed.PID != req.PID || observed.Status < 0 || observed.Status > 255 ||
			len(observed.Stdout) > 2048 || len(observed.Stderr) > 2048 {
			return errStage2aQualificationFrame
		}
		for _, c := range observed.Stdout + observed.Stderr {
			if c > 0x7f {
				return errStage2aQualificationFrame
			}
		}
	}
	for i, req := range request.Paths {
		if _, err := stage2aQualificationKeysV1(rawPaths[i], []string{"role", "path"}, ""); err != nil {
			return errStage2aQualificationFrame
		}
		if !stage2aQualificationTokenV1.MatchString(req.Role) || !stage2aAbsolutePath(req.Path) {
			return errStage2aQualificationFrame
		}
		within := false
		for _, root := range pathRoots {
			if req.Path == root || len(req.Path) > len(root) && bytes.HasPrefix([]byte(req.Path), []byte(root+"/")) {
				within = true
				break
			}
		}
		if !within {
			return errStage2aQualificationFrame
		}
		if stage2aQualificationCanonical(response.Paths[i]) != nil {
			return errStage2aQualificationFrame
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(response.Paths[i], &fields) != nil || fields["role"] == nil || fields["path"] == nil || fields["exists"] == nil {
			return errStage2aQualificationFrame
		}
		var observed struct {
			Role string `json:"role"`
			Path string `json:"path"`
		}
		if json.Unmarshal(response.Paths[i], &observed) != nil || observed.Role != req.Role || observed.Path != req.Path {
			return errStage2aQualificationFrame
		}
		switch string(fields["exists"]) {
		case "true":
			if len(fields) != 9 {
				return errStage2aQualificationFrame
			}
			for _, key := range []string{"dev", "ino", "uid", "gid", "mode", "type"} {
				if fields[key] == nil {
					return errStage2aQualificationFrame
				}
			}
			var present struct {
				Dev  string `json:"dev"`
				Ino  string `json:"ino"`
				UID  int    `json:"uid"`
				GID  int    `json:"gid"`
				Mode int    `json:"mode"`
				Type string `json:"type"`
			}
			if json.Unmarshal(response.Paths[i], &present) != nil || !stage2aQualificationDecimal(present.Dev) || !stage2aQualificationDecimal(present.Ino) ||
				present.UID < 0 || present.GID < 0 || present.Mode < 0 || present.Mode > 07777 ||
				(present.Type != "file" && present.Type != "directory" && present.Type != "symlink" && present.Type != "other") {
				return errStage2aQualificationFrame
			}
		case "false", "null":
			if len(fields) != 4 || fields["error"] == nil {
				return errStage2aQualificationFrame
			}
			var code string
			if json.Unmarshal(fields["error"], &code) != nil {
				return errStage2aQualificationFrame
			}
			if string(fields["exists"]) == "false" && code != "ENOENT" && code != "ENOTDIR" {
				return errStage2aQualificationFrame
			}
			if string(fields["exists"]) == "null" && code != "EACCES" && code != "EPERM" {
				return errStage2aQualificationFrame
			}
		default:
			return errStage2aQualificationFrame
		}
	}
	return nil
}

func stage2aQualificationDecimal(value string) bool {
	if value == "" || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
