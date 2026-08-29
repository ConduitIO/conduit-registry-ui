// Copyright © 2026 Meroxa, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Real Sigstore fixture generation for the artifacts pass (WS4 S3).
//
// The verdict engine verifies REAL cryptographic material, so its fixtures
// must be real bundles — not synthetic JSON. sigstore-go's
// pkg/testing/ca.VirtualSigstore (the same CA the conduit module's own
// adversarial corpus uses) signs with a locally-generated Fulcio/Rekor/TSA
// key set, so the whole trust chain verifies offline against a locally
// generated TrustedRoot.
//
// The VirtualSigstore's public surface returns opaque TestEntity values
// (sign/attest results) with no JSON serialization path, so the bundles are
// assembled into protobuf Sigstore bundles here from the CA's public
// primitives:
//
//   - signature bundles are v0.1 message-signature bundles (cert chain +
//     hashedrekord Rekor entry with a signed-entry-timestamp inclusion
//     PROMISE — the verifier's promise path, tlog.VerifySET, with no
//     inclusion proof required);
//   - provenance bundles are v0.3 DSSE-attestation bundles (cert chain +
//     intoto Rekor entry with a full inclusion PROOF plus an RFC3161
//     timestamp, satisfying the verifier's observer-timestamp requirement
//     on the proof path);
//   - the TrustedRoot JSON deliberately carries the Rekor log key ID as
//     DECODED bytes (not the ASCII-hex bytes ca.RekorLogs puts in its
//     in-process TransparencyLog.ID) so the root survives a JSON
//     round-trip: the parse side re-encodes hex(KeyId) as the map key, so
//     KeyId must be the raw key ID for the bundle entries' LogId.KeyId and
//     the SET signature's LogID field to line up single-hex on both sides.
//
// The fixture generator (fixturegen_test.go) uses these builders so the
// vitest integration suite can drive the REAL binary against offline
// bundles via --trust-root-file; artifacts_test.go uses them in-process via
// the engine's WithRoot seam.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

// newVirtualCA creates the offline CA plus its JSON-round-trip-safe
// TrustedRoot. The root shares the CA's keys; its Rekor log ID is carried
// as DECODED bytes so it survives the JSON round-trip (see the package
// doc).
func newVirtualCA(t *testing.T) (*ca.VirtualSigstore, root.TrustedMaterial) {
	t.Helper()
	ss, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("creating virtual sigstore CA: %v", err)
	}
	tm := virtualTrustRootFor(t, ss)
	return ss, tm
}

// virtualTrustRootFor builds the round-trip-safe TrustedRoot for a given
// CA instance.
func virtualTrustRootFor(t *testing.T, ss *ca.VirtualSigstore) root.TrustedMaterial {
	t.Helper()
	logID, err := ss.RekorLogID()
	if err != nil {
		t.Fatalf("rekor log id: %v", err)
	}
	logIDRaw, err := hex.DecodeString(logID)
	if err != nil {
		t.Fatalf("decoding rekor log id: %v", err)
	}
	tl := ss.RekorLogs()[logID]
	tm, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		ss.FulcioCertificateAuthorities(),
		ss.CTLogs(),
		ss.TimestampingAuthorities(),
		map[string]*root.TransparencyLog{
			logID: {
				BaseURL:             tl.BaseURL,
				ID:                  logIDRaw,
				ValidityPeriodStart: tl.ValidityPeriodStart,
				ValidityPeriodEnd:   tl.ValidityPeriodEnd,
				HashFunc:            tl.HashFunc,
				PublicKey:           tl.PublicKey,
				SignatureHashFunc:   tl.SignatureHashFunc,
			},
		},
	)
	if err != nil {
		t.Fatalf("building virtual trust root: %v", err)
	}
	return tm
}

// virtualTrustRootJSON is the JSON-serialized round-trip-safe root for
// --trust-root-file (the vitest integration suite drives the REAL binary).
func virtualTrustRootJSON(t *testing.T, ss *ca.VirtualSigstore) []byte {
	t.Helper()
	data, err := json.Marshal(virtualTrustRootFor(t, ss))
	if err != nil {
		t.Fatalf("serializing trust root: %v", err)
	}
	return data
}

// signerForLeaf loads the leaf private key with the same algorithm
// details the CA signs with (ECDSA P256 / SHA-256).
func signerForLeaf(t *testing.T, leafKey any) signature.Signer {
	t.Helper()
	details, err := signature.GetAlgorithmDetails(v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	if err != nil {
		t.Fatalf("algorithm details: %v", err)
	}
	signer, err := signature.LoadSignerFromAlgorithmDetails(leafKey, details)
	if err != nil {
		t.Fatalf("loading leaf signer: %v", err)
	}
	return signer
}

// signatureBundleJSON builds a v0.1 message-signature bundle covering
// artifactBytes, signed by a fresh VirtualSigstore leaf for the given SAN
// identity + OIDC issuer, with a Rekor inclusion promise (SET).
func signatureBundleJSON(t *testing.T, ss *ca.VirtualSigstore, identity, issuer string, artifactBytes []byte) []byte {
	t.Helper()
	ctx := context.Background()
	integratedTime := time.Now().Add(5 * time.Minute)

	leafCert, leafKey, err := ss.GenerateLeafCert(identity, issuer)
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}
	signer := signerForLeaf(t, leafKey)

	digest := sha256.Sum256(artifactBytes)
	sig, err := signer.SignMessage(bytes.NewReader(artifactBytes))
	if err != nil {
		t.Fatalf("signing artifact: %v", err)
	}

	// The Rekor hashedrekord entry, canonicalized the way Rekor stores it —
	// the exact body the SET signature covers (base64 string).
	body := canonicalRekorBody(t, ctx, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), artifactBytes, leafCert, sig)
	set := signRekorPayload(t, ss, body, integratedTime, 1000)
	entry := tlogEntry(t, body, integratedTime, 1000, ss, set, nil, "hashedrekord", hashedrekord.New().DefaultVersion())

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: certChain(t, ss, leafCert),
			},
			TlogEntries: []*rekorv1.TransparencyLogEntry{entry},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sig,
			},
		},
	}
	return marshalBundle(t, pb)
}

// provenanceBundleJSON builds a v0.3 DSSE-attestation bundle over the
// in-toto statement JSON, with a Rekor inclusion PROOF and an RFC3161
// timestamp (the verifier's proof path needs an observer timestamp).
func provenanceBundleJSON(t *testing.T, ss *ca.VirtualSigstore, identity, issuer string, statementJSON []byte) []byte {
	t.Helper()
	ctx := context.Background()
	integratedTime := time.Now().Add(5 * time.Minute)

	leafCert, leafKey, err := ss.GenerateLeafCert(identity, issuer)
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}
	signer := signerForLeaf(t, leafKey)
	dsseSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             leafCert.PublicKey.(*ecdsa.PublicKey),
	})
	if err != nil {
		t.Fatalf("building dsse signer: %v", err)
	}
	envelope, err := dsseSigner.SignPayload(ctx, "application/vnd.in-toto+json", statementJSON)
	if err != nil {
		t.Fatalf("signing attestation envelope: %v", err)
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decoding envelope signature: %v", err)
	}

	// The Rekor intoto entry (the envelope JSON string is the entry's
	// spec.content.envelope).
	body := canonicalRekorBody(t, ctx, intoto.KIND, intoto.New().DefaultVersion(), envelopeBytes, leafCert, sig)
	set := signRekorPayload(t, ss, body, integratedTime, 1000)
	proof := inclusionProof(t, ss, body)
	entry := tlogEntry(t, body, integratedTime, 1000, ss, set, proof, "intoto", intoto.New().DefaultVersion())

	tsr, err := ss.TimestampResponse(sig)
	if err != nil {
		t.Fatalf("timestamp response: %v", err)
	}

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{
			// A v0.3 bundle carries the LEAF certificate, not the chain:
			// sigstore-go's own v0.3 validation rejects X.509 chains here,
			// and the verifier rebuilds the chain from the trust root's
			// Fulcio certificate authorities.
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
			},
			TlogEntries: []*rekorv1.TransparencyLogEntry{entry},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: tsr}},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				// RAW payload bytes for the same reason as the signature:
				// protojson base64-encodes on marshal, and the verifier
				// decodes — the encoded string must never be stored as
				// bytes.
				Payload:     statementJSON,
				PayloadType: envelope.PayloadType,
				Signatures: []*protodsse.Signature{
					// RAW signature bytes: protojson base64-encodes them on
					// marshal, and the verifier base64-decodes the parsed
					// string — storing the already-encoded string here would
					// double-encode and break the bundle-entry equality
					// check.
					{Sig: sig, Keyid: envelope.Signatures[0].KeyID},
				},
			},
		},
	}
	return marshalBundle(t, pb)
}

// canonicalRekorBody builds a Rekor entry of the given kind and returns the
// canonicalized body bytes (exactly what Rekor stores and what the SET
// signature covers). artifactBytes is the signed blob: the artifact itself
// for hashedrekord entries, the envelope JSON for intoto entries.
func canonicalRekorBody(t *testing.T, ctx context.Context, kind, apiVersion string, artifactBytes []byte, leafCert *x509.Certificate, sig []byte) []byte {
	t.Helper()
	leafCertPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("pem-encoding cert: %v", err)
	}
	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{leafCertPEM},
		PKIFormat:      string(pki.X509),
	}
	switch kind {
	case hashedrekord.KIND:
		props.ArtifactHash = hex.EncodeToString(sha256Sum(artifactBytes))
		props.SignatureBytes = sig
	case intoto.KIND:
		props.ArtifactBytes = artifactBytes
		props.SignatureBytes = sig
	}
	proposed, err := types.NewProposedEntry(ctx, kind, apiVersion, props)
	if err != nil {
		t.Fatalf("proposed rekor entry: %v", err)
	}
	entry, err := types.CreateVersionedEntry(proposed)
	if err != nil {
		t.Fatalf("versioned rekor entry: %v", err)
	}
	body, err := types.CanonicalizeEntry(ctx, entry)
	if err != nil {
		t.Fatalf("canonicalizing rekor entry: %v", err)
	}
	return body
}

// signRekorPayload signs the SET over the canonicalized body with the CA's
// Rekor key, exactly like the CA's own Sign path (the SET covers
// base64(body) + integratedTime + logIndex + logID).
func signRekorPayload(t *testing.T, ss *ca.VirtualSigstore, body []byte, integratedTime time.Time, logIndex int64) []byte {
	t.Helper()
	logID, err := ss.RekorLogID()
	if err != nil {
		t.Fatalf("rekor log id: %v", err)
	}
	set, err := ss.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(body),
		IntegratedTime: integratedTime.Unix(),
		LogIndex:       logIndex,
		LogID:          logID,
	})
	if err != nil {
		t.Fatalf("signing rekor payload: %v", err)
	}
	return set
}

// inclusionProof builds a Rekor v1 inclusion proof via the CA's own proof
// generator.
func inclusionProof(t *testing.T, ss *ca.VirtualSigstore, body []byte) *rekorv1.InclusionProof {
	t.Helper()
	proof, err := ss.GetInclusionProof(body)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	return &rekorv1.InclusionProof{
		LogIndex: *proof.LogIndex,
		RootHash: mustHexDecode(t, *proof.RootHash),
		TreeSize: *proof.TreeSize,
		Checkpoint: &rekorv1.Checkpoint{
			Envelope: *proof.Checkpoint,
		},
		Hashes: hexHashes(t, proof),
	}
}

func hexHashes(t *testing.T, proof *models.InclusionProof) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(proof.Hashes))
	for _, h := range proof.Hashes {
		out = append(out, mustHexDecode(t, h))
	}
	return out
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decoding %q: %v", s, err)
	}
	return b
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// tlogEntry builds the protobuf TransparencyLogEntry for one Rekor entry:
// a promise (SET) when proof is nil, an inclusion proof otherwise.
func tlogEntry(t *testing.T, body []byte, integratedTime time.Time, logIndex int64, ss *ca.VirtualSigstore, set []byte, proof *rekorv1.InclusionProof, kind, apiVersion string) *rekorv1.TransparencyLogEntry {
	t.Helper()
	logID, err := ss.RekorLogID()
	if err != nil {
		t.Fatalf("rekor log id: %v", err)
	}
	logIDRaw, err := hex.DecodeString(logID)
	if err != nil {
		t.Fatalf("decoding rekor log id: %v", err)
	}
	entry := &rekorv1.TransparencyLogEntry{
		LogIndex: logIndex,
		LogId: &protocommon.LogId{
			KeyId: logIDRaw,
		},
		KindVersion: &rekorv1.KindVersion{
			Kind:    kind,
			Version: apiVersion,
		},
		IntegratedTime:    integratedTime.Unix(),
		CanonicalizedBody: body,
	}
	if proof != nil {
		entry.InclusionProof = proof
	} else {
		entry.InclusionPromise = &rekorv1.InclusionPromise{SignedEntryTimestamp: set}
	}
	return entry
}

// certChain is the bundle's leaf -> intermediate -> root chain in the
// order sigstore-go's own CA produces it.
func certChain(t *testing.T, ss *ca.VirtualSigstore, leaf *x509.Certificate) *protocommon.X509CertificateChain {
	t.Helper()
	cas := ss.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		t.Fatal("virtual CA exposes no fulcio certificate authorities")
	}
	caProto := cas[0].(*root.FulcioCertificateAuthority)
	var chain []*protocommon.X509Certificate
	chain = append(chain, &protocommon.X509Certificate{RawBytes: leaf.Raw})
	for _, intermed := range caProto.Intermediates {
		chain = append(chain, &protocommon.X509Certificate{RawBytes: intermed.Raw})
	}
	chain = append(chain, &protocommon.X509Certificate{RawBytes: caProto.Root.Raw})
	return &protocommon.X509CertificateChain{Certificates: chain}
}

// marshalBundle serializes a protobuf bundle to JSON via the sigstore-go
// wrapper (which validates the shape at marshal time — a malformed fixture
// fails here, not in the verifier). The X509 certificate chain is allowed
// only for v0.3+ bundles (sigstore-go's AllowCertificateChain option; v0.1
// bundles reject the option itself), mirroring the real-world transition.
func marshalBundle(t *testing.T, pb *protobundle.Bundle) []byte {
	t.Helper()
	opts := []bundle.Option{}
	// v0.1 is the only pre-0.3 bundle version this suite emits; anything
	// else gets the chain allowed.
	if strings.TrimPrefix(pb.MediaType, "application/vnd.dev.sigstore.bundle+json;version=") != "0.1" {
		opts = append(opts, bundle.AllowCertificateChain())
	}
	b, err := bundle.NewBundle(pb, opts...)
	if err != nil {
		t.Fatalf("building sigstore bundle: %v", err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("serializing bundle: %v", err)
	}
	return data
}
