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

// The per-version artifact verdict engine (WS4 S3). When the CLI runs with
// --artifacts, this pass runs AFTER the index pipeline succeeds and writes
// a three-state verdict per version — pass / fail(reason) /
// not_attempted(reason) — into an artifacts report JSON for the site build.
//
// Verdict semantics (the ratified WS4 plan, §3 "per-version signatures"):
//
//   - A version PASSES only when EVERY artifact's signature bundle
//     cryptographically verifies against the trust anchors AND the identity
//     pinned for the connector, AND the applicable SLSA provenance bundle
//     (artifact-level, else version-level — the same selection install.go
//     makes) verifies AND its subject digest binds to the index-declared
//     sha256 with the expected builder ID.
//   - FAIL means a bundle verified-failed: tampered bytes, a valid
//     signature by the wrong identity, or provenance that does not bind.
//   - NOT_ATTEMPTED means the verdict could not be reached: no provenance
//     reference in the index, a bundle that could not be fetched, or a
//     malformed index declaration. A missing reference is NEVER a pass —
//     there is no presence-pass: no bundle, no green.
//
// Version aggregation is fail > not_attempted > pass, carrying the first
// failure's reason.
//
// Deliberate constraints, mirroring the plan:
//
//   - Only SMALL bundles are fetched (bounded at registry.MaxBundleBytes,
//     1 MiB — the CLI's own cap); the artifact binaries themselves are
//     never downloaded. The digest binding does the rest: the signature
//     covers the sha256 the index declares, so a bundle that verifies
//     proves the DECLARED bytes are the signed bytes.
//   - Verdicts never fail the build. not_attempted and fail are data for
//     the site, not build failures — a transient bundle-host outage must
//     degrade badges, not take the site down. Only the pass itself failing
//     to complete (report write error) fails the build.
//   - This engine imports conduit's trust package wholesale — the exact
//     code the CLI's install path runs. No signature logic is rewritten.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/conduitio/conduit/pkg/foundation/cerrors"
	"github.com/conduitio/conduit/pkg/foundation/cerrors/conduiterr"
	"github.com/conduitio/conduit/pkg/registry"
	"github.com/conduitio/conduit/pkg/registry/index"
	"github.com/conduitio/conduit/pkg/registry/trust"
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// artifactVerdict is the three-state verdict for one version.
type artifactVerdict string

const (
	verdictPass         artifactVerdict = "pass"
	verdictFail         artifactVerdict = "fail"
	verdictNotAttempted artifactVerdict = "not_attempted"
)

// Reason strings are part of the report contract: they render verbatim in
// the site's badges and the /verify page, so they are short, stable, and
// answer "what do I do about this" — never raw error text.
const (
	reasonNoArtifacts          = "version declares no artifacts in the index"
	reasonInvalidSHA256        = "index declares an invalid sha256 for this artifact"
	reasonNoSignatureRef       = "no signature bundle reference in index"
	reasonSigFetchFailed       = "signature bundle could not be fetched"
	reasonSigDoesNotVerify     = "signature bundle does not verify against the trust anchors and the index-declared sha256"
	reasonSigIdentityMismatch  = "signature is valid but does not match the identity pinned for this connector"
	reasonPatternTooLoose      = "the pinned identity pattern failed defensive validation"
	reasonNoProvenance         = "no provenance in index"
	reasonProvFetchFailed      = "provenance bundle could not be fetched"
	reasonProvDoesNotVerify    = "provenance bundle does not verify against the trust anchors"
	reasonProvIdentityMismatch = "provenance is validly signed but does not match the identity pinned for this connector"
	reasonProvBinding          = "provenance does not bind to the index-declared sha256 and the expected builder"
)

// artifactVerdictEntry is one artifact's verdict row.
type artifactVerdictEntry struct {
	OS      string          `json:"os"`
	Arch    string          `json:"arch"`
	Kind    string          `json:"kind"`
	Verdict artifactVerdict `json:"verdict"`
	Reason  string          `json:"reason,omitempty"`
}

// versionVerdict aggregates the artifact verdicts for one version:
// fail > not_attempted > pass. checkedAt is the CLI's wall clock at verdict
// time — the badge's as-of date.
type versionVerdict struct {
	Version   string                 `json:"version"`
	Verdict   artifactVerdict        `json:"verdict"`
	Reason    string                 `json:"reason,omitempty"`
	CheckedAt string                 `json:"checkedAt"`
	Artifacts []artifactVerdictEntry `json:"artifacts"`
}

type entryVerdict struct {
	Name     string           `json:"name"`
	Versions []versionVerdict `json:"versions"`
}

// artifactsReport is the schemaVersion-1 report shape written to
// --artifacts. The build merges it into the render model; the footer and
// /verify page render indexVersion/indexTimestamp/verifierVersion as the
// "when and with what this was checked" record (WS4 4.14/4.16).
type artifactsReport struct {
	SchemaVersion   int            `json:"schemaVersion"`
	GeneratedAt     string         `json:"generatedAt"`
	IndexVersion    int64          `json:"indexVersion"`
	IndexTimestamp  string         `json:"indexTimestamp"`
	VerifierVersion string         `json:"verifierVersion"`
	Connectors      []entryVerdict `json:"connectors"`
	// Processors carry the identical trust code and verdict semantics (WS4
	// S5): a processor version's single arch-neutral artifact goes through
	// the same bundle verification and binding checks. Omitted when the
	// index declares none (the site's TS side treats the field as optional).
	Processors []entryVerdict `json:"processors,omitempty"`
}

// artifactsOptions carries the trust-root seam and clock. trustRoot nil
// means the embedded production Sigstore public-good trust root (the
// conduit CLI's own); a non-nil root is the test/offline facility
// (--trust-root-file) for fixtures signed by a VirtualSigstore CA.
type artifactsOptions struct {
	trustRoot root.TrustedMaterial
	now       func() time.Time
}

// artifactVerifier wraps the conduit trust entry points with the seam
// between the embedded production trust root and an explicit test root —
// one indirection so the engine body reads identically either way.
type artifactVerifier struct {
	tm root.TrustedMaterial
}

func (av artifactVerifier) verifySignature(ctx context.Context, digest []byte, bundleBytes []byte, identity trust.PinnedIdentity) (string, error) {
	if av.tm != nil {
		return trust.VerifyArtifactSignatureWithRoot(ctx, digest, bundleBytes, identity, av.tm)
	}
	return trust.VerifyArtifactSignature(ctx, digest, bundleBytes, identity)
}

func (av artifactVerifier) verifyAttestation(ctx context.Context, bundleBytes []byte, identity trust.PinnedIdentity) (*in_toto.Statement, error) {
	if av.tm != nil {
		return trust.VerifyAttestationEnvelopeWithRoot(ctx, bundleBytes, identity, av.tm)
	}
	return trust.VerifyAttestationEnvelope(ctx, bundleBytes, identity)
}

// verifyArtifacts computes the per-version verdicts for a VERIFIED payload
// (callers must only pass payloads that already passed index.Verify — the
// verdicts are over data the root signature already authorized). Errors
// here are infrastructure failures (trust root unusable), never verdicts.
func verifyArtifacts(ctx context.Context, payload index.Payload, opts artifactsOptions) (artifactsReport, error) {
	if opts.now == nil {
		opts.now = time.Now
	}
	now := opts.now().UTC()

	report := artifactsReport{
		SchemaVersion:   1,
		GeneratedAt:     now.Format(time.RFC3339),
		IndexVersion:    payload.Index.Version,
		IndexTimestamp:  payload.Index.Timestamp.UTC().Format(time.RFC3339),
		VerifierVersion: verifierVersion(),
		Connectors:      make([]entryVerdict, 0, len(payload.Connectors)),
	}

	for _, c := range payload.Connectors {
		cv := entryVerdict{Name: c.Name, Versions: make([]versionVerdict, 0, len(c.Versions))}
		identity := trust.PinnedIdentity{
			OIDCIssuer:      c.Publisher.ExpectedOIDCIssuer,
			IdentityPattern: c.Publisher.ExpectedIdentityPattern,
		}
		for _, v := range c.Versions {
			cv.Versions = append(cv.Versions, verdictForVersion(ctx, v.Version, v.Artifacts, v.SLSAProvenance, identity, opts))
		}
		report.Connectors = append(report.Connectors, cv)
	}

	// Processors: the same identity-pinning trust decision as connectors
	// (design doc D1) over a single arch-neutral wasip1/wasm artifact per
	// version (D2) — the exact bundle verification, the exact binding, the
	// exact three-state honesty floor.
	report.Processors = make([]entryVerdict, 0, len(payload.Processors))
	for _, p := range payload.Processors {
		pv := entryVerdict{Name: p.Name, Versions: make([]versionVerdict, 0, len(p.Versions))}
		identity := trust.PinnedIdentity{
			OIDCIssuer:      p.Publisher.ExpectedOIDCIssuer,
			IdentityPattern: p.Publisher.ExpectedIdentityPattern,
		}
		for _, v := range p.Versions {
			pv.Versions = append(pv.Versions, verdictForVersion(ctx, v.Version, []index.Artifact{v.Artifact}, v.SLSAProvenance, identity, opts))
		}
		report.Processors = append(report.Processors, pv)
	}
	return report, nil
}

// verdictForVersion verifies every artifact of one version and aggregates.
// versionProv is the version-level provenance reference (the fallback the
// CLI's own artifact-ref selection applies when an artifact declares none);
// artifacts is the version's per-(os,arch) artifact list — for processors,
// the single wasip1/wasm artifact.
func verdictForVersion(ctx context.Context, version string, artifacts []index.Artifact, versionProv *index.ProvenanceRef, identity trust.PinnedIdentity, opts artifactsOptions) versionVerdict {
	vv := versionVerdict{
		Version:   version,
		CheckedAt: opts.now().UTC().Format(time.RFC3339),
		Artifacts: make([]artifactVerdictEntry, 0, len(artifacts)),
	}

	if len(artifacts) == 0 {
		vv.Verdict = verdictNotAttempted
		vv.Reason = reasonNoArtifacts
		return vv
	}

	// fail > not_attempted > pass; the FIRST fail (else first
	// not_attempted) reason is the version's reason.
	var firstNA artifactVerdictEntry
	versionFail := false
	versionNA := false

	for _, a := range artifacts {
		entry := verifyArtifact(ctx, a, versionProv, identity, opts)
		vv.Artifacts = append(vv.Artifacts, entry)
		switch entry.Verdict {
		case verdictFail:
			versionFail = true
			vv.Verdict = verdictFail
			vv.Reason = entry.Reason
		case verdictNotAttempted:
			if !versionNA {
				firstNA = entry
				versionNA = true
			}
		}
		if versionFail {
			// First fail wins; don't let a later not_attempted overwrite it.
			return vv
		}
	}
	if versionNA {
		vv.Verdict = verdictNotAttempted
		vv.Reason = firstNA.Reason
		return vv
	}
	vv.Verdict = verdictPass
	return vv
}

// verifyArtifact returns one artifact's verdict:
//
//  1. digest from the index-declared sha256 — malformed is not_attempted
//     (the binding cannot be checked, but the index data is broken, not
//     the bundle);
//  2. signature bundle: missing reference -> not_attempted, fetch failure
//     -> not_attempted, verification failure -> fail (tampered bytes) or
//     fail (valid but wrong identity);
//  3. provenance (artifact-level else version-level, mirroring
//     registry.fetchArtifactRef; versionProv is the version-level ref):
//     missing -> not_attempted("no provenance in index") — NEVER a
//     presence-pass — fetch failure -> not_attempted, envelope verification
//     failure -> fail, subject/builder binding failure -> fail.
func verifyArtifact(ctx context.Context, a index.Artifact, versionProv *index.ProvenanceRef, identity trust.PinnedIdentity, opts artifactsOptions) artifactVerdictEntry {
	entry := artifactVerdictEntry{OS: a.OS, Arch: a.Arch, Kind: a.Kind, Verdict: verdictFail}

	digest, ok := decodeDigest(a.SHA256)
	if !ok {
		entry.Verdict = verdictNotAttempted
		entry.Reason = reasonInvalidSHA256
		return entry
	}

	// The defensive identity-pattern check the CLI's install path runs
	// before any verification — a too-loose pattern would make the
	// identity match meaningless, so it is a fail, not a pass.
	if err := trust.ValidateIdentityPattern(identity.IdentityPattern); err != nil {
		entry.Reason = reasonPatternTooLoose
		return entry
	}

	verifier := artifactVerifier{tm: opts.trustRoot}

	// --- signature bundle -------------------------------------------------
	sigBundle, fetchErr := fetchBundle(ctx, a.Signature.BundleURL)
	switch {
	case a.Signature.BundleURL == "":
		entry.Verdict = verdictNotAttempted
		entry.Reason = reasonNoSignatureRef
		return entry
	case fetchErr != nil:
		entry.Verdict = verdictNotAttempted
		entry.Reason = reasonSigFetchFailed + ": " + fetchErr.Error()
		return entry
	}

	if _, err := verifier.verifySignature(ctx, digest[:], sigBundle, identity); err != nil {
		entry.Reason = reasonForVerifyError(err, reasonSigDoesNotVerify, reasonSigIdentityMismatch)
		return entry
	}

	// --- provenance bundle -------------------------------------------------
	provRef := a.SLSAProvenance
	if provRef == nil {
		provRef = versionProv
	}
	if provRef == nil {
		entry.Verdict = verdictNotAttempted
		entry.Reason = reasonNoProvenance
		return entry
	}

	provBundle, fetchErr := fetchBundle(ctx, provRef.BundleURL)
	if fetchErr != nil {
		entry.Verdict = verdictNotAttempted
		entry.Reason = reasonProvFetchFailed + ": " + fetchErr.Error()
		return entry
	}

	statement, err := verifier.verifyAttestation(ctx, provBundle, trust.BuilderPinnedIdentity())
	if err != nil {
		entry.Reason = reasonForVerifyError(err, reasonProvDoesNotVerify, reasonProvIdentityMismatch)
		return entry
	}

	if err := trust.CheckProvenanceBinding(statement, digest, trust.ExpectedBuilderID); err != nil {
		entry.Reason = reasonProvBinding
		return entry
	}

	entry.Verdict = verdictPass
	return entry
}

// decodeDigest parses the index's lowercase-hex sha256 declaration.
func decodeDigest(hexSHA string) ([32]byte, bool) {
	var d [32]byte
	if len(hexSHA) != hex.EncodedLen(len(d)) {
		return d, false
	}
	raw, err := hex.DecodeString(hexSHA)
	if err != nil {
		return d, false
	}
	copy(d[:], raw)
	return d, true
}

// reasonForVerifyError maps a trust verification error onto the fail
// reason: CodeIdentityMismatch (the envelope verified, the identity did
// not) is its own reason; every other failure — tampered bytes, untrusted
// chain, missing tlog inclusion — is the generic does-not-verify reason.
func reasonForVerifyError(err error, genericReason, identityReason string) string {
	cerr, ok := conduiterr.Get(err)
	if ok && cerr.Code.Reason() == trust.CodeIdentityMismatch.Reason() {
		return identityReason
	}
	return genericReason
}

// Fetch failures map onto a fixed phrase vocabulary — the report's reason
// strings are part of its contract ("never raw error text": no URLs, no
// status lines, no DNS detail leaks into the site). Each phrase is also an
// error sentinel so the retry logic can tell a transient host response from
// a permanent outcome without string matching.
var (
	bundleErrUnreachable = cerrors.New("bundle host could not be reached")
	bundleErrNotFound    = cerrors.New("bundle not found at the declared URL")
	bundleErrRateLimited = cerrors.New("bundle host rate-limited the request")
	bundleErrRejected    = cerrors.New("bundle host rejected the request")
	bundleErrServer      = cerrors.New("bundle host returned a server error")
	bundleErrTooLarge    = cerrors.New("bundle exceeds the maximum allowed size")
	bundleErrUnreadable  = cerrors.New("bundle file could not be read")
)

// fetchBundle fetches one bundle, bounded at the CLI's own 1 MiB cap
// (registry.MaxBundleBytes), using the same LimitReader-plus-one technique
// as the pinned module's boundedfetch — the exact bound install.go
// enforces. An http(s) URL is fetched with bounded retries on transient
// 429/5xx responses: a bundle-host hiccup must degrade a verdict to
// not_attempted only after the retries are exhausted, never on the first
// 503. A local path (offline/test fixtures) is read from disk with the same
// cap.
//
// Every returned error's message is exactly one of the bundleErr* phrases
// above; the raw error stays inside this function.
func fetchBundle(ctx context.Context, url string) ([]byte, error) {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return fetchBundleHTTP(ctx, url)
	}
	data, err := os.ReadFile(url)
	if err != nil {
		return nil, bundleErrUnreadable
	}
	if int64(len(data)) > registry.MaxBundleBytes {
		return nil, bundleErrTooLarge
	}
	return data, nil
}

// fetchBundleAttempts bounds the total HTTP attempts (1 + retries);
// fetchBundleBackoff doubles per retry (100ms, 200ms — deliberately small:
// the whole artifacts pass runs inside the CLI's 30s context).
const (
	fetchBundleAttempts = 3
	fetchBundleBackoff  = 100 * time.Millisecond
)

func fetchBundleHTTP(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= fetchBundleAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(fetchBundleBackoff * time.Duration(1<<(attempt-2))):
			case <-ctx.Done():
				return nil, bundleErrUnreachable
			}
		}
		data, err := fetchBundleHTTPOnce(ctx, url)
		if err == nil {
			return data, nil
		}
		// Only transient host responses are retried; a client error (404,
		// a malformed URL, a too-large body) is permanent and returns
		// immediately.
		if !errors.Is(err, bundleErrRateLimited) && !errors.Is(err, bundleErrServer) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchBundleHTTPOnce(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, bundleErrUnreachable
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, bundleErrUnreachable
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, bundleErrRateLimited
	case resp.StatusCode == http.StatusNotFound:
		return nil, bundleErrNotFound
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, bundleErrRejected
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, bundleErrServer
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, registry.MaxBundleBytes+1))
	if err != nil {
		return nil, bundleErrUnreachable
	}
	if int64(len(data)) > registry.MaxBundleBytes {
		return nil, bundleErrTooLarge
	}
	return data, nil
}

// verifierVersion reports the pinned conduit module version from the
// binary's build info — the verifier the verdicts were computed with (the
// footer's "verifier version", WS4 4.14). Real values from the build, not
// hardcoded: the binary was built from this repo's go.mod, which pins the
// module.
func verifierVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, m := range bi.Deps {
		if m.Path == "github.com/conduitio/conduit" && m.Version != "" {
			return m.Version
		}
	}
	return "unknown"
}
