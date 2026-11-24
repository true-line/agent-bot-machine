package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type stage2aDriverPhaseCapture struct {
	phase  stage2aDriverRunPhase
	review stage2aDriverReview
	peer   stage2aQualificationDriverPeer
	trace  []stage2aDriverEvidence
}

type stage2aDriverArchiveEvidence struct {
	SourceBase64URL  string `json:"source_base64url"`
	WitnessBase64URL string `json:"os_witness_base64url"`
}

func marshalStage2aDriverArchive(capture stage2aDriverPhaseCapture, session stage2aQualificationSessionResultV1,
	q stage2aQualificationPreSignArtifactsV1, now time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	if !stage2aQualificationDigest(q.IndexSHA256) || !stage2aQualificationDigest(q.EOFReceiptSHA256) ||
		!stage2aQualificationDigest(q.WireSHA256) {
		return nil, errStage2aReservationAuthority
	}
	payload, err := stage2aDriverReceiptPayload(session, capture.phase, capture.review, capture.peer, capture.trace, now)
	if err != nil {
		return nil, err
	}
	payload.QIndexSHA256, payload.QEOFSHA256, payload.QWireSHA256 = q.IndexSHA256, q.EOFReceiptSHA256, q.WireSHA256
	receipt, err := signStage2aEnvelope(payload, 1, stage2aDriverReceiptPurpose, key, sign)
	if err != nil {
		return nil, err
	}
	evidence := make([]stage2aDriverArchiveEvidence, 0, len(capture.trace))
	for _, pair := range capture.trace {
		evidence = append(evidence, stage2aDriverArchiveEvidence{
			SourceBase64URL:  base64.RawURLEncoding.EncodeToString(pair.artifact),
			WitnessBase64URL: base64.RawURLEncoding.EncodeToString(pair.osWitness),
		})
	}
	raw, err := marshalStage2aReservationJCS(map[string]any{
		"schema": stage2aDriverCaseSchema, "kind": "phase-archive", "baseline_only": capture.phase == stage2aDriverBeforeLaunch,
		"q_index_sha256": q.IndexSHA256, "q_eof_sha256": q.EOFReceiptSHA256, "q_wire_sha256": q.WireSHA256,
		"receipt_base64url": base64.RawURLEncoding.EncodeToString(receipt), "evidence": evidence,
	})
	if err != nil || len(raw) > 1<<20 {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}
