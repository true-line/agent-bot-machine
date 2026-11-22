//go:build darwin

package members

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const stage2aQualificationFrameMax = 65536

var errStage2aQualificationFrame = errors.New("invalid Stage 2a qualification frame")

// The independent qualification runner's local stream has one 4-byte
// big-endian length and one canonical ASCII JSON object per frame. A frame is
// raw observation input; it never grants a pass or signing authority.
func readStage2aQualificationFrame(r io.Reader) ([]byte, error) {
	raw, _, err := readStage2aQualificationObservedFrame(r)
	return raw, err
}

// Retain the bytes actually read from Q, including the length prefix. An
// archive producer must not reconstruct the prefix after the connection ends.
func readStage2aQualificationObservedFrame(r io.Reader) ([]byte, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, errStage2aQualificationFrame
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > stage2aQualificationFrameMax {
		return nil, nil, errStage2aQualificationFrame
	}
	frame := make([]byte, 4+length)
	copy(frame, header[:])
	raw := frame[4:]
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, nil, errStage2aQualificationFrame
	}
	if stage2aQualificationCanonical(raw) != nil {
		return nil, nil, errStage2aQualificationFrame
	}
	return raw, frame, nil
}

func writeStage2aQualificationFrame(w io.Writer, value any) ([]byte, error) {
	raw, err := marshalStage2aReservationJCS(value)
	if err != nil || stage2aQualificationCanonical(raw) != nil {
		return nil, errStage2aQualificationFrame
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if n, err := w.Write(header[:]); err != nil || n != len(header) {
		return nil, errStage2aQualificationFrame
	}
	if n, err := w.Write(raw); err != nil || n != len(raw) {
		return nil, errStage2aQualificationFrame
	}
	return append(header[:], raw...), nil
}

func stage2aQualificationCanonical(raw []byte) error {
	if len(raw) == 0 || len(raw) > stage2aQualificationFrameMax || stage2aStrictJSON(raw) != nil {
		return errStage2aQualificationFrame
	}
	for _, b := range raw {
		if b >= 0x80 {
			return errStage2aQualificationFrame
		}
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return errStage2aQualificationFrame
	}
	if _, ok := value.(map[string]any); !ok {
		return errStage2aQualificationFrame
	}
	if stage2aQualificationIntegers(value) != nil {
		return errStage2aQualificationFrame
	}
	var output bytes.Buffer
	e := json.NewEncoder(&output)
	e.SetEscapeHTML(false)
	if e.Encode(value) != nil || !bytes.Equal(bytes.TrimSuffix(output.Bytes(), []byte("\n")), raw) {
		return errStage2aQualificationFrame
	}
	return nil
}

func stage2aQualificationIntegers(value any) error {
	switch v := value.(type) {
	case json.Number:
		if len(v) == 0 || len(v) > 16 || v[0] == '-' && len(v) == 1 || string(v) == "-0" {
			return errStage2aQualificationFrame
		}
		for i, c := range v {
			if c < '0' || c > '9' {
				if i != 0 || c != '-' {
					return errStage2aQualificationFrame
				}
			}
		}
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < -((1<<53)-1) || n > (1<<53)-1 {
			return errStage2aQualificationFrame
		}
	case []any:
		for _, item := range v {
			if stage2aQualificationIntegers(item) != nil {
				return errStage2aQualificationFrame
			}
		}
	case map[string]any:
		for _, item := range v {
			if stage2aQualificationIntegers(item) != nil {
				return errStage2aQualificationFrame
			}
		}
	}
	return nil
}
