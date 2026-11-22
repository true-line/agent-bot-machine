//go:build darwin

package members

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestStage2aQualificationFramesRejectAmbiguity(t *testing.T) {
	var stream bytes.Buffer
	framed, err := writeStage2aQualificationFrame(&stream, map[string]any{"kind": "ready", "sequence": 0})
	if err != nil || !bytes.Equal(stream.Bytes(), framed) {
		t.Fatal("canonical frame write", err)
	}
	raw, observed, err := readStage2aQualificationObservedFrame(&stream)
	if err != nil || string(raw) != `{"kind":"ready","sequence":0}` || !bytes.Equal(observed, framed) {
		t.Fatal("canonical frame read", err)
	}
	frame := func(raw string) []byte {
		var b bytes.Buffer
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(raw)))
		b.Write(h[:])
		b.WriteString(raw)
		return b.Bytes()
	}
	for _, bad := range [][]byte{
		{0, 0, 0, 0}, {0, 1, 0, 1}, {0, 0, 0, 4, '{', '}'},
		frame(`{"kind":"ready","kind":"done"}`),
		frame(`{ "kind":"ready"}`),
		frame(`{"sequence":1.5}`),
		frame(`{"sequence":-0}`),
		frame(`{"sequence":9007199254740992}`),
		frame(`{"kind":"r\u00e9ady"}`),
		frame(`["ready"]`),
	} {
		if _, err := readStage2aQualificationFrame(bytes.NewReader(bad)); err == nil {
			t.Fatalf("accepted ambiguous frame %q", bad)
		}
	}
}

func mustStage2aQualificationFrame(t *testing.T, value any) []byte {
	t.Helper()
	var stream bytes.Buffer
	framed, err := writeStage2aQualificationFrame(&stream, value)
	if err != nil || !bytes.Equal(stream.Bytes(), framed) {
		t.Fatal("canonical frame write", err)
	}
	return framed
}
