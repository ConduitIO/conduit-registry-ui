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

// The verdict engine's test matrix (WS4 S3). Every case drives the engine
// IN-PROCESS through its WithRoot seam (artifactVerifier with an explicit
// trust root — no bundle serialization needed), against REAL sigstore
// material: each fixture is signed by a fresh VirtualSigstore leaf, with a
// real Rekor SET/proof and (for provenance) a real RFC3161 timestamp, all
// verifying against the CA's own key material. Nothing here is synthetic —
// a "tampered" case really does contain bytes that fail to verify.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conduitio/conduit/pkg/registry"
	"github.com/conduitio/conduit/pkg/registry/index"
	"github.com/conduitio/conduit/pkg/registry/trust"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"strings"
)

const (
	testIssuer          = "https://token.actions.githubusercontent.com"
	testIdentityPattern = `^https://github\.com/ConduitIO/conduit-connector-postgres/\.github/workflows/publish\.yml@refs/tags/v.*$`
	testSigningIdentity = "https://github.com/ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"
)

// fixtureBundle holds the three real-sigstore fixture pieces for one
// artifact: the artifact bytes, its signature bundle, its provenance
// bundle, and the index-declared sha256 (hex).
type fixtureBundle struct {
	artifact       []byte
	sigBundle      []byte
	provBundle     []byte
	declaredSHA256 string
}

// makeFixture produces a well-signed artifact fixture whose declared sha256
// matches the signed bytes: signature bundle signed by testSigningIdentity,
// provenance bundle signed by the SLSA builder identity, statement subject
// bound to the same digest.
func makeFixture(t *testing.T, ss *ca.VirtualSigstore) fixtureBundle {
	t.Helper()
	artifact := []byte("conduit-connector-postgres-v0.14.1-linux-amd64.tar.gz payload")
	digest := fmt.Sprintf("%x", sha256Sum(artifact))
	sigBundle := signatureBundleJSON(t, ss, testSigningIdentity, testIssuer, artifact)
	provBundle := provenanceBundleJSON(t, ss, trust.ExpectedBuilderID, testIssuer, slsaStatementJSON(digest))
	return fixtureBundle{
		artifact:       artifact,
		sigBundle:      sigBundle,
		provBundle:     provBundle,
		declaredSHA256: digest,
	}
}

// slsaStatementJSON is a real SLSA v1 in-toto statement (the shape
// slsa-github-generator emits), with one subject per digestHex (a
// multi-artifact release carries one subject per artifact) and the expected
// builder id.
func slsaStatementJSON(digestHex ...string) []byte {
	subjects := make([]string, 0, len(digestHex))
	for _, d := range digestHex {
		subjects = append(subjects, fmt.Sprintf(`{"name": "artifact", "digest": {"sha256": %q}}`, d))
	}
	return []byte(fmt.Sprintf(`{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [%s],
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {"buildType": "https://slsa.dev/build-type/github/v1.0.0"},
			"runDetails": {"builder": {"id": %q}}
		}
	}`, strings.Join(subjects, ", "), trust.ExpectedBuilderID))
}

// writeFixture writes the bundles as local files (fetchBundle's offline
// path) and returns the artifact as an index entry.
func writeFixture(t *testing.T, f fixtureBundle) index.Artifact {
	t.Helper()
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "sig.json")
	provPath := filepath.Join(dir, "prov.json")
	if err := os.WriteFile(sigPath, f.sigBundle, 0o600); err != nil {
		t.Fatalf("writing sig bundle fixture: %v", err)
	}
	if err := os.WriteFile(provPath, f.provBundle, 0o600); err != nil {
		t.Fatalf("writing prov bundle fixture: %v", err)
	}
	return index.Artifact{
		OS:     "linux",
		Arch:   "amd64",
		Kind:   "standalone",
		URL:    "https://example.test/artifact.tar.gz",
		SHA256: f.declaredSHA256,
		Size:   int64(len(f.artifact)),
		Signature: index.SignatureRef{
			BundleURL: sigPath,
		},
		SLSAProvenance: &index.ProvenanceRef{
			BundleURL:     provPath,
			PredicateType: "https://slsa.dev/provenance/v1",
		},
	}
}

func connectorPayload(versions ...index.ConnectorVersion) index.Payload {
	return index.Payload{
		SchemaVersion: 1,
		Index:         index.IndexMeta{Version: 42, Timestamp: time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)},
		Connectors: []index.Connector{
			{
				Name: "conduit-connector-postgres",
				Publisher: index.Publisher{
					ExpectedOIDCIssuer:      testIssuer,
					ExpectedIdentityPattern: testIdentityPattern,
				},
				Versions: versions,
			},
		},
	}
}

func runVerdicts(t *testing.T, payload index.Payload, ss *ca.VirtualSigstore, now time.Time) artifactsReport {
	t.Helper()
	report, err := verifyArtifacts(context.Background(), payload, artifactsOptions{
		trustRoot: virtualTrustRootFor(t, ss),
		now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("verifyArtifacts: %v", err)
	}
	return report
}

func versionOf(t *testing.T, report artifactsReport, connector, version string) versionVerdict {
	t.Helper()
	for _, c := range report.Connectors {
		if c.Name != connector {
			continue
		}
		for _, v := range c.Versions {
			if v.Version == version {
				return v
			}
		}
	}
	t.Fatalf("no verdict for %s@%s in report", connector, version)
	return versionVerdict{}
}

func TestArtifactVerdictsPass(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, f)},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictPass {
		t.Fatalf("expected pass, got %q (%q)", vv.Verdict, vv.Reason)
	}
	if len(vv.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact verdict, got %d", len(vv.Artifacts))
	}
	if a := vv.Artifacts[0]; a.Verdict != verdictPass || a.Reason != "" {
		t.Fatalf("expected artifact pass without reason, got %q %q", a.Verdict, a.Reason)
	}
	// The whole version's fixture (both bundles) is tiny — nothing near the
	// 1 MiB served-bytes cap, because only bundles are ever fetched, never
	// the artifact itself.
	if total := len(f.sigBundle) + len(f.provBundle); int64(total) >= registry.MaxBundleBytes {
		t.Fatalf("fixture served bytes %d exceed the %d bundle cap", total, registry.MaxBundleBytes)
	}
}

func TestArtifactVerdictsIdentityMismatchIsFail(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	// Re-sign the SAME artifact bytes with a DIFFERENT (valid) signing
	// identity: the signature verifies cryptographically, the identity does
	// not match the connector's pin.
	artifact := f.artifact
	wrongIdentity := "https://github.com/Evil/evil/.github/workflows/publish.yml@refs/tags/v1.0.0"
	f.sigBundle = signatureBundleJSON(t, ss, wrongIdentity, testIssuer, artifact)
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, f)},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictFail {
		t.Fatalf("expected fail, got %q", vv.Verdict)
	}
	if vv.Reason != reasonSigIdentityMismatch {
		t.Fatalf("expected %q, got %q", reasonSigIdentityMismatch, vv.Reason)
	}
}

func TestArtifactVerdictsTamperedDeclaredDigestIsFail(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	// The bundle was signed over the real bytes; the index lies about what
	// the sha256 is. The digest binding must fail the signature check.
	f.declaredSHA256 = fmt.Sprintf("%x", sha256Sum([]byte("some other artifact bytes")))
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, f)},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictFail || vv.Reason != reasonSigDoesNotVerify {
		t.Fatalf("expected fail(%q), got %q (%q)", reasonSigDoesNotVerify, vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsProvenanceSubjectMismatchIsFail(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	// Signature is fine; the provenance attests to a DIFFERENT artifact's
	// digest than the index declares for this artifact.
	other := []byte("a different artifact entirely")
	f.provBundle = provenanceBundleJSON(t, ss, trust.ExpectedBuilderID, testIssuer,
		slsaStatementJSON(fmt.Sprintf("%x", sha256Sum(other))))
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, f)},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictFail || vv.Reason != reasonProvBinding {
		t.Fatalf("expected fail(%q), got %q (%q)", reasonProvBinding, vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsMissingProvenanceIsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	entry := writeFixture(t, f)
	entry.SLSAProvenance = nil // version-level ref also absent
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted || vv.Reason != reasonNoProvenance {
		t.Fatalf("expected not_attempted(%q), got %q (%q)", reasonNoProvenance, vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsVersionLevelProvenanceApplies(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	entry := writeFixture(t, f)
	entry.SLSAProvenance = nil // artifact-level ref absent; version-level applies
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
		SLSAProvenance: &index.ProvenanceRef{
			BundleURL:     writeProvBundleFile(t, f),
			PredicateType: "https://slsa.dev/provenance/v1",
		},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictPass {
		t.Fatalf("expected pass with version-level provenance, got %q (%q)", vv.Verdict, vv.Reason)
	}
}

func writeProvBundleFile(t *testing.T, f fixtureBundle) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prov.json")
	if err := os.WriteFile(p, f.provBundle, 0o600); err != nil {
		t.Fatalf("writing prov bundle: %v", err)
	}
	return p
}

func TestArtifactVerdictsFetchFailureIsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	entry := writeFixture(t, f)
	entry.Signature.BundleURL = "https://example.test/missing-sig.json"
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted {
		t.Fatalf("expected not_attempted, got %q (%q)", vv.Verdict, vv.Reason)
	}
	if !strings.HasPrefix(vv.Reason, reasonSigFetchFailed+": ") {
		t.Fatalf("unexpected reason %q", vv.Reason)
	}
}

func TestArtifactVerdictsHTTP5xxIsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	entry := writeFixture(t, f)
	entry.Signature.BundleURL = srv.URL
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted {
		t.Fatalf("expected not_attempted, got %q (%q)", vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsOversizedBundleIsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), int(registry.MaxBundleBytes)+1))
	}))
	defer srv.Close()
	entry := writeFixture(t, f)
	entry.Signature.BundleURL = srv.URL
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted {
		t.Fatalf("expected not_attempted, got %q (%q)", vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsMalformedSHA256IsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	entry := writeFixture(t, f)
	entry.SHA256 = "not-a-hex-digest"
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{entry},
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted || vv.Reason != reasonInvalidSHA256 {
		t.Fatalf("expected not_attempted(%q), got %q (%q)", reasonInvalidSHA256, vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsNoArtifactsIsNotAttempted(t *testing.T) {
	ss, _ := newVirtualCA(t)
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
	})

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted || vv.Reason != reasonNoArtifacts {
		t.Fatalf("expected not_attempted(%q), got %q (%q)", reasonNoArtifacts, vv.Verdict, vv.Reason)
	}
}

func TestArtifactVerdictsLooseIdentityPatternIsFail(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	payload := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, f)},
	})
	payload.Connectors[0].Publisher.ExpectedIdentityPattern = `^.*$`

	report := runVerdicts(t, payload, ss, time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC))
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictFail || vv.Reason != reasonPatternTooLoose {
		t.Fatalf("expected fail(%q), got %q (%q)", reasonPatternTooLoose, vv.Verdict, vv.Reason)
	}
}

// Aggregation: fail > not_attempted > pass.
func TestArtifactVerdictsAggregation(t *testing.T) {
	ss, _ := newVirtualCA(t)
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)

	// One pass + one missing-provenance artifact: the version is NOT
	// green — a single well-signed artifact does not vouch for the others.
	passF := makeFixture(t, ss)
	naF := makeFixture(t, ss)
	naEntry := writeFixture(t, naF)
	naEntry.SLSAProvenance = nil
	mixed := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.1",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{writeFixture(t, passF), naEntry},
	})
	report := runVerdicts(t, mixed, ss, now)
	vv := versionOf(t, report, "conduit-connector-postgres", "0.14.1")
	if vv.Verdict != verdictNotAttempted || vv.Reason != reasonNoProvenance {
		t.Fatalf("pass+not_attempted: expected not_attempted(%q), got %q (%q)", reasonNoProvenance, vv.Verdict, vv.Reason)
	}

	// One fail + one not_attempted: fail wins, carrying the FIRST fail's
	// reason even though a later artifact could not even be checked.
	failF := makeFixture(t, ss)
	wrongIdentity := "https://github.com/Evil/evil/.github/workflows/publish.yml@refs/tags/v1.0.0"
	failF.sigBundle = signatureBundleJSON(t, ss, wrongIdentity, testIssuer, failF.artifact)
	failEntry := writeFixture(t, failF)
	failEntry.SLSAProvenance = nil
	mixedFail := connectorPayload(index.ConnectorVersion{
		Version:           "0.14.2",
		MinConduitVersion: "0.14.0",
		Artifacts:         []index.Artifact{failEntry, naEntry},
	})
	report = runVerdicts(t, mixedFail, ss, now)
	vv = versionOf(t, report, "conduit-connector-postgres", "0.14.2")
	if vv.Verdict != verdictFail || vv.Reason != reasonSigIdentityMismatch {
		t.Fatalf("fail+not_attempted: expected fail(%q), got %q (%q)", reasonSigIdentityMismatch, vv.Verdict, vv.Reason)
	}
}

func TestArtifactReportShape(t *testing.T) {
	ss, _ := newVirtualCA(t)
	f := makeFixture(t, ss)
	now := time.Date(2026, 7, 14, 10, 30, 0, 0, time.UTC)
	payload := connectorPayload(
		index.ConnectorVersion{
			Version:           "0.14.1",
			MinConduitVersion: "0.14.0",
			Artifacts:         []index.Artifact{writeFixture(t, f)},
		},
		index.ConnectorVersion{
			Version:           "0.14.0",
			MinConduitVersion: "0.14.0",
			Artifacts:         []index.Artifact{writeFixture(t, f)},
			Yanked:            &index.YankReason{Reason: "bad build"},
		},
	)

	report := runVerdicts(t, payload, ss, now)
	if report.SchemaVersion != 1 {
		t.Fatalf("expected schemaVersion 1, got %d", report.SchemaVersion)
	}
	if report.GeneratedAt != "2026-07-14T10:30:00Z" {
		t.Fatalf("expected generatedAt 2026-07-14T10:30:00Z, got %q", report.GeneratedAt)
	}
	if report.IndexVersion != 42 {
		t.Fatalf("expected indexVersion 42, got %d", report.IndexVersion)
	}
	if report.IndexTimestamp != "2026-07-14T09:00:00Z" {
		t.Fatalf("expected indexTimestamp 2026-07-14T09:00:00Z, got %q", report.IndexTimestamp)
	}
	if report.VerifierVersion == "" || report.VerifierVersion == "unknown" {
		t.Fatalf("expected a real verifier version from build info, got %q", report.VerifierVersion)
	}
	if len(report.Connectors) != 1 || report.Connectors[0].Name != "conduit-connector-postgres" {
		t.Fatalf("unexpected connectors in report: %+v", report.Connectors)
	}
	if len(report.Connectors[0].Versions) != 2 {
		t.Fatalf("expected 2 version verdicts, got %d", len(report.Connectors[0].Versions))
	}
	for _, v := range report.Connectors[0].Versions {
		if v.CheckedAt != "2026-07-14T10:30:00Z" {
			t.Fatalf("expected checkedAt to be the verdict clock, got %q", v.CheckedAt)
		}
	}
}
