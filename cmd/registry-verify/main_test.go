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

// Round-trip tests, mirroring conduit-connector-registry's cmd/index-sign
// tests: the signer side here is the TEST (test keys, built from the same
// index package primitives — Canonicalize/KeyID/ed25519), and the verifier
// side is conduit's shipped index.Verify running through this CLI's run().
// Proving the two agree on canonicalization, keyId derivation, and envelope
// shape is the whole point: signer and verifier must never drift.
//
// The subprocess tests (TestExitCode_*) pin the BINARY contract — exit 0
// quiet on success, exit 1 + ERR_* on stderr on verification failure, exit
// 2 on usage errors — by re-executing this test binary with TestMain
// swapping productionAnchors for a deterministic test key.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conduitio/conduit/pkg/foundation/cerrors/conduiterr"
	"github.com/conduitio/conduit/pkg/registry"
	"github.com/conduitio/conduit/pkg/registry/index"
)

const (
	// helperEnv marks the subprocess as the re-exec'd helper; helperPubKeyEnv
	// carries the SPKI of the key the child should trust (base64 DER).
	helperEnv       = "REGISTRY_VERIFY_HELPER"
	helperPubKeyEnv = "REGISTRY_VERIFY_HELPER_PUB_KEY"
)

var testNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// TestMain swaps productionAnchors in the re-exec'd helper subprocess so
// realMain's full path (anchors load -> run -> exit code) is testable
// deterministically: no production keys, no network.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		spki, err := base64.StdEncoding.DecodeString(os.Getenv(helperPubKeyEnv))
		if err != nil {
			fmt.Fprintf(os.Stderr, "helper: decoding %s: %v\n", helperPubKeyEnv, err)
			os.Exit(exitUsage)
		}
		anyPub, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			fmt.Fprintf(os.Stderr, "helper: parsing pub key: %v\n", err)
			os.Exit(exitUsage)
		}
		pub, ok := anyPub.(ed25519.PublicKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "helper: pub key is %T, want ed25519\n", anyPub)
			os.Exit(exitUsage)
		}
		productionAnchors = func() (index.TrustAnchors, error) {
			return testAnchors(pub), nil
		}
	}
	os.Exit(m.Run())
}

// TestHelperProcess is the re-exec entry point: when helperEnv is set it
// runs the real CLI (realMain) with the args after "--" and exits with its
// code; otherwise it is a no-op test.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	sep := -1
	for i, a := range os.Args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		os.Exit(exitUsage)
	}
	os.Exit(realMain(os.Args[sep+1:]))
}

// runBinary re-executes this test binary as the CLI. The parent signs the
// served index with priv; the child trusts its public half.
func runBinary(t *testing.T, priv ed25519.PrivateKey, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshaling pub key: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--")
	cmd.Args = append(cmd.Args, args...)
	cmd.Env = append(os.Environ(),
		helperEnv+"=1",
		helperPubKeyEnv+"="+base64.StdEncoding.EncodeToString(spki),
	)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdoutBuf, &stderrBuf
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running helper: %v", err)
		}
		return stdoutBuf.String(), stderrBuf.String(), ee.ExitCode()
	}
	return stdoutBuf.String(), stderrBuf.String(), 0
}

// makePayload builds a schemaVersion-1 payload with the given version and
// timestamp. connectors stays empty (the registry repo's own signer tests
// use the same emptyPayload shape).
func makePayload(version int64, ts time.Time) json.RawMessage {
	return makePayloadWithConnectors(version, ts, []any{})
}

// makePayloadWithConnectors is makePayload with an explicit connectors[]
// (the wedge tests need content that differs across versions).
func makePayloadWithConnectors(version int64, ts time.Time, connectors []any) json.RawMessage {
	b, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"index": map[string]any{
			"version":   version,
			"timestamp": ts.UTC().Format(time.RFC3339),
		},
		"connectors": connectors,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// signPayload signs a payload the way the index-sign tool does — canonicalize
// (JCS), derive keyId via index.KeyID (never invented), ed25519-sign — and
// returns a signed envelope. Both sides of this test use the same imported
// index package, so a mismatch can only mean this CLI wired the pipeline up
// wrong, not that the crypto primitives drifted.
func signPayload(t *testing.T, payload json.RawMessage, role string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := index.Canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalizing payload: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("test key is not ed25519")
	}
	keyID, err := index.KeyID(pub)
	if err != nil {
		t.Fatalf("deriving keyId: %v", err)
	}
	env, err := json.Marshal(map[string]any{
		"payload": json.RawMessage(canonical),
		"signatures": []any{map[string]any{
			"role":      role,
			"keyId":     keyID,
			"algorithm": "ed25519",
			"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
		}},
	})
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	return env
}

// testAnchors trusts the key in BOTH roles: several tests sign root-first and
// freshness-later with the same key, and Verify resolves each role against its
// own map.
func testAnchors(pub ed25519.PublicKey) index.TrustAnchors {
	keyID, err := index.KeyID(pub)
	if err != nil {
		panic(err)
	}
	return index.TrustAnchors{
		Roots:     map[string]ed25519.PublicKey{keyID: pub},
		Freshness: map[string]ed25519.PublicKey{keyID: pub},
	}
}

// serve serves raw bytes as the index endpoint.
func serve(t *testing.T, raw []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tempPaths returns a fresh state path and out path in a temp dir, so no
// test ever touches the repo's committed verify/ files.
func tempPaths(t *testing.T) (statePath, outPath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "state.json"), filepath.Join(dir, "index.json")
}

func runVerify(t *testing.T, url, statePath, outPath string, anchors index.TrustAnchors, now time.Time, requireRoot bool) error {
	t.Helper()
	return run(context.Background(), options{
		indexURL:    url,
		outPath:     outPath,
		statePath:   statePath,
		anchors:     anchors,
		requireRoot: requireRoot,
		now:         func() time.Time { return now },
	})
}

func mustGenerateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestVerify_RootSignedIndexAccepted is the round-trip agreement test: a
// root-signed index must verify, the exact raw bytes must land on disk, and
// the high-water state must ratchet to the new version.
func TestVerify_RootSignedIndexAccepted(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	payload := makePayload(1, testNow)
	raw := signPayload(t, payload, "root", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	if err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading out: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("out file bytes differ from the fetched raw bytes (re-encoding?)\nwant %q\ngot  %q", raw, got)
	}

	state, err := index.LoadState(statePath)
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if state.Version != 1 {
		t.Fatalf("state version = %d, want 1 (high-water mark must ratchet)", state.Version)
	}
	if state.LastVerifiedContentHash == "" {
		t.Fatal("state content hash empty after a ROOT-verified index — must be persisted for freshness-only acceptance")
	}
}

// TestVerify_TamperedIndexFailsClosed: any change to the signed payload must
// fail with ERR_INDEX_INTEGRITY, never succeed.
func TestVerify_TamperedIndexFailsClosed(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	payload := makePayload(1, testNow)
	raw := signPayload(t, payload, "root", priv)

	// Bump the version AFTER signing: the signature no longer covers the bytes.
	var env struct {
		Payload    json.RawMessage `json:"payload"`
		Signatures json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Index struct {
			Version int64 `json:"version"`
		} `json:"index"`
	}
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(map[string]any{
		"payload":    makePayload(p.Index.Version+1, testNow),
		"signatures": json.RawMessage(env.Signatures),
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := serve(t, tampered)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("tampered index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_INTEGRITY" {
		t.Fatalf("error code = %s, want ERR_INDEX_INTEGRITY (%v)", code, err)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("tampered index must not write --out (fail closed), stat err = %v", statErr)
	}
}

// TestVerify_FreshnessOnlyFailsFirstTimeClient: a structurally valid
// freshness-signed index with no root signature must NOT satisfy a client
// with no prior root-verified content (empty state) — ERR_INDEX_INTEGRITY,
// not success. A freshness signature may extend freshness, never authorize
// content.
func TestVerify_FreshnessOnlyFailsFirstTimeClient(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	raw := signPayload(t, makePayload(1, testNow), "freshness", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("freshness-only index verified for a first-time client — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_INTEGRITY" {
		t.Fatalf("error code = %s, want ERR_INDEX_INTEGRITY (%v)", code, err)
	}
}

// TestVerify_FreshnessOnlyAcceptedOverByteIdenticalContent proves the
// freshness path works end to end when it SHOULD: a freshness signature over
// content matching the persisted content-subtree hash is accepted and
// ratchets version/timestamp — and only over that content.
func TestVerify_FreshnessOnlyAcceptedOverByteIdenticalContent(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	anchors := testAnchors(pub)
	statePath, outPath := tempPaths(t)

	// Phase 1: root-sign version 1 — establishes the content-subtree hash.
	rootSrv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
	if err := runVerify(t, rootSrv.URL, statePath, outPath, anchors, testNow, false); err != nil {
		t.Fatalf("root-signed bootstrap: %v", err)
	}

	// Phase 2: freshness-sign version 2 over identical (empty) content.
	freshSrv := serve(t, signPayload(t, makePayload(2, testNow.Add(time.Hour)), "freshness", priv))
	if err := runVerify(t, freshSrv.URL, statePath, outPath, anchors, testNow.Add(time.Hour), false); err != nil {
		t.Fatalf("freshness re-sign over identical content: %v", err)
	}
	state, err := index.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 {
		t.Fatalf("state version = %d, want 2", state.Version)
	}
	if state.LastVerifiedContentHash == "" {
		t.Fatal("content hash lost on the freshness ratchet")
	}

	// Phase 3: the SAME freshness key cannot authorize NEW content (version 3
	// over a changed connectors[] — here, one connector named "x").
	changed := makePayloadWithConnectors(3, testNow.Add(2*time.Hour), []any{map[string]any{"name": "x"}})
	newContentSrv := serve(t, signPayload(t, changed, "freshness", priv))
	err = runVerify(t, newContentSrv.URL, statePath, outPath, anchors, testNow.Add(2*time.Hour), false)
	if err == nil {
		t.Fatal("freshness signature over CHANGED content verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_INTEGRITY" {
		t.Fatalf("error code = %s, want ERR_INDEX_INTEGRITY (%v)", code, err)
	}
}

// TestVerify_RequireRootRefusesFreshnessOnly: with --require-root a
// freshness-only acceptance is refused outright (ERR_ROOT_SIGNATURE_REQUIRED)
// and the state floor is never touched — the wedge cannot open.
func TestVerify_RequireRootRefusesFreshnessOnly(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	anchors := testAnchors(pub)
	statePath, outPath := tempPaths(t)

	// Phase 1: root-signed bootstrap at version 1.
	rootSrv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
	if err := runVerify(t, rootSrv.URL, statePath, outPath, anchors, testNow, true); err != nil {
		t.Fatalf("root-signed bootstrap: %v", err)
	}

	// Phase 2: a freshness-only v99 over identical content — cryptographically
	// valid and content-matching, but --require-root refuses it outright.
	freshSrv := serve(t, signPayload(t, makePayload(99, testNow.Add(time.Hour)), "freshness", priv))
	err := runVerify(t, freshSrv.URL, statePath, outPath, anchors, testNow.Add(time.Hour), true)
	if err == nil {
		t.Fatal("freshness-only index accepted under --require-root — must fail closed")
	}
	if code := errCode(err); code != "ERR_ROOT_SIGNATURE_REQUIRED" {
		t.Fatalf("error code = %s, want ERR_ROOT_SIGNATURE_REQUIRED (%v)", code, err)
	}

	// The state floor is untouched: the next legit root-signed index still
	// verifies.
	state, err := index.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 {
		t.Fatalf("state version = %d, want 1 (freshness-only refusal must not ratchet)", state.Version)
	}
	nextRoot := serve(t, signPayload(t, makePayload(2, testNow.Add(2*time.Hour)), "root", priv))
	if err := runVerify(t, nextRoot.URL, statePath, outPath, anchors, testNow.Add(2*time.Hour), true); err != nil {
		t.Fatalf("next root-signed index refused after the freshness refusal: %v", err)
	}
}

// TestVerify_FreshnessRatchetsThenRootRejected NAMES the wedge this CLI's
// --require-root exists to close: in the default (CLI-mirroring) mode, a
// freshness-only v99 over identical content is accepted and ratchets the
// state to 99 — so the registry's next legit ROOT-signed index (v12, new
// content; the registry bumps versions independently) is refused forever as
// ERR_INDEX_ROLLBACK until a human edits verify/state.json.
func TestVerify_FreshnessRatchetsThenRootRejected(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	anchors := testAnchors(pub)
	statePath, outPath := tempPaths(t)

	// Phase 1: root-signed bootstrap at version 1.
	rootSrv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
	if err := runVerify(t, rootSrv.URL, statePath, outPath, anchors, testNow, false); err != nil {
		t.Fatalf("root-signed bootstrap: %v", err)
	}

	// Phase 2: freshness-signed v99 over identical content — accepted by
	// default (mirroring the CLI), ratcheting the state to 99.
	freshSrv := serve(t, signPayload(t, makePayload(99, testNow.Add(time.Hour)), "freshness", priv))
	if err := runVerify(t, freshSrv.URL, statePath, outPath, anchors, testNow.Add(time.Hour), false); err != nil {
		t.Fatalf("freshness v99 (default mode): %v", err)
	}

	// Phase 3: the registry's real next index — root-signed v12 with NEW
	// content — is refused as a rollback. This is the wedge.
	nextRoot := serve(t, signPayload(t, makePayloadWithConnectors(12, testNow.Add(2*time.Hour), []any{map[string]any{"name": "x"}}), "root", priv))
	err := runVerify(t, nextRoot.URL, statePath, outPath, anchors, testNow.Add(2*time.Hour), false)
	if err == nil {
		t.Fatal("the wedge did not close: legit root-signed index accepted after a freshness ratchet")
	}
	if code := errCode(err); code != "ERR_INDEX_ROLLBACK" {
		t.Fatalf("error code = %s, want ERR_INDEX_ROLLBACK (%v)", code, err)
	}
}

// TestVerify_StateNotRatchetedOnRejection: a rejected fetch must never touch
// the committed high-water mark (an attacker must not be able to push the
// trusted floor forward with garbage).
func TestVerify_StateNotRatchetedOnRejection(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	statePath, outPath := tempPaths(t)

	// Bootstrap state at version 1.
	rootSrv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
	if err := runVerify(t, rootSrv.URL, statePath, outPath, testAnchors(pub), testNow, false); err != nil {
		t.Fatalf("root-signed bootstrap: %v", err)
	}

	// Now serve a tampered index: rejected, and the state must be untouched.
	tampered := signPayload(t, makePayload(3, testNow), "root", priv)
	tampered = bytes.Replace(tampered, []byte(`"version":3`), []byte(`"version":4`), 1)
	srv := serve(t, tampered)
	if err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false); err == nil {
		t.Fatal("tampered index verified — must fail closed")
	}

	state, err := index.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 {
		t.Fatalf("state version = %d after a rejection, want 1 (never ratchet on a rejected fetch)", state.Version)
	}
}

// TestVerify_StateVersionCap: LoadState (pinned module) validates nothing;
// an implausible high-water version in the committed state file must fail
// loud with ERR_STATE_INVALID — not refuse every future index forever.
func TestVerify_StateVersionCap(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	for _, bad := range []int64{1<<63 - 1, -1, 1<<31 + 1} {
		t.Run(fmt.Sprintf("version=%d", bad), func(t *testing.T) {
			statePath, outPath := tempPaths(t)
			if err := index.SaveState(statePath, index.State{Version: bad}); err != nil {
				t.Fatal(err)
			}
			srv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
			err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
			if err == nil {
				t.Fatal("implausible state version accepted — must fail closed")
			}
			if code := errCode(err); code != "ERR_STATE_INVALID" {
				t.Fatalf("error code = %s, want ERR_STATE_INVALID (%v)", code, err)
			}
		})
	}
}

// TestVerify_StaleIndexFailsClosed: an index older than the CLI's own window
// (index.DefaultMaxStaleness, 7 days) must fail with ERR_INDEX_STALE even
// though the signature is valid.
func TestVerify_StaleIndexFailsClosed(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	staleTS := testNow.Add(-8 * 24 * time.Hour) // 8 days > DefaultMaxStaleness (7)
	raw := signPayload(t, makePayload(1, staleTS), "root", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("stale index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_STALE" {
		t.Fatalf("error code = %s, want ERR_INDEX_STALE (%v)", code, err)
	}
}

// TestVerify_RolledBackIndexFailsClosed: an index older than the committed
// high-water mark must fail with ERR_INDEX_ROLLBACK — the repo state file is
// what gives ephemeral CI runners their memory.
func TestVerify_RolledBackIndexFailsClosed(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	statePath, outPath := tempPaths(t)

	// The state file records version 5 as the last accepted index.
	if err := index.SaveState(statePath, index.State{Version: 5}); err != nil {
		t.Fatal(err)
	}

	raw := signPayload(t, makePayload(3, testNow), "root", priv)
	srv := serve(t, raw)

	err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("rolled-back index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_ROLLBACK" {
		t.Fatalf("error code = %s, want ERR_INDEX_ROLLBACK (%v)", code, err)
	}
}

// TestVerify_UnknownKeyFailsClosed: no signature keyId matching any anchor is
// the "upgrade the client" case — ERR_TRUST_ANCHOR_EXPIRED, never success.
func TestVerify_UnknownKeyFailsClosed(t *testing.T) {
	_, signerPriv := mustGenerateKey(t)
	raw := signPayload(t, makePayload(1, testNow), "root", signerPriv)

	unrelatedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(unrelatedPub), testNow, false)
	if err == nil {
		t.Fatal("index signed by an unknown key verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_TRUST_ANCHOR_EXPIRED" {
		t.Fatalf("error code = %s, want ERR_TRUST_ANCHOR_EXPIRED (%v)", code, err)
	}
}

// TestVerify_SchemaTooNewFailsClosed: a schemaVersion newer than this build
// understands must fail with ERR_SCHEMA_TOO_NEW even under a valid root
// signature (upgrade the client, never guess at the shape).
func TestVerify_SchemaTooNewFailsClosed(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	payload, err := json.Marshal(map[string]any{
		"schemaVersion": 2, // MaxSupportedSchemaVersion is 1
		"index":         map[string]any{"version": 1, "timestamp": testNow.UTC().Format(time.RFC3339)},
		"connectors":    []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := signPayload(t, payload, "root", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("schema-too-new index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_SCHEMA_TOO_NEW" {
		t.Fatalf("error code = %s, want ERR_SCHEMA_TOO_NEW (%v)", code, err)
	}
}

// TestVerify_UnreachableIndexFailsClosed: a fetch-layer failure (non-200)
// must fail with ERR_INDEX_UNREACHABLE, distinct from every other code.
func TestVerify_UnreachableIndexFailsClosed(t *testing.T) {
	pub, _ := mustGenerateKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	statePath, outPath := tempPaths(t)
	err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("unreachable index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_UNREACHABLE" {
		t.Fatalf("error code = %s, want ERR_INDEX_UNREACHABLE (%v)", code, err)
	}
}

// TestVerify_IndexTooLargeFailsClosed: an index over the 8 MiB fetch cap must
// fail with ERR_INDEX_TOO_LARGE — distinct from a plain fetch failure.
func TestVerify_IndexTooLargeFailsClosed(t *testing.T) {
	pub, _ := mustGenerateKey(t)
	big := bytes.Repeat([]byte("a"), 9*1024*1024) // > index.MaxIndexBytes (8 MiB)
	srv := serve(t, big)

	statePath, outPath := tempPaths(t)
	err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow, false)
	if err == nil {
		t.Fatal("oversized index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_TOO_LARGE" {
		t.Fatalf("error code = %s, want ERR_INDEX_TOO_LARGE (%v)", code, err)
	}
}

// TestErrCodeMapping pins the full error-code contract, including the
// fallbacks: the up-front anchor-unavailable failure and the generic
// ERR_VERIFY for unknown/un-coded errors.
func TestErrCodeMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"schema too new", conduiterr.New(index.CodeSchemaTooNew, "x"), "ERR_SCHEMA_TOO_NEW"},
		{"unreachable", conduiterr.New(index.CodeIndexUnreachable, "x"), "ERR_INDEX_UNREACHABLE"},
		{"too large", conduiterr.New(index.CodeIndexTooLarge, "x"), "ERR_INDEX_TOO_LARGE"},
		{"integrity", conduiterr.New(index.CodeIndexIntegrity, "x"), "ERR_INDEX_INTEGRITY"},
		{"anchor expired", conduiterr.New(index.CodeTrustAnchorExpired, "x"), "ERR_TRUST_ANCHOR_EXPIRED"},
		{"anchors unavailable", conduiterr.New(registry.CodeTrustAnchorsUnavailable, "x"), "ERR_TRUST_ANCHORS_UNAVAILABLE"},
		{"rollback", conduiterr.New(index.CodeIndexRollback, "x"), "ERR_INDEX_ROLLBACK"},
		{"stale", conduiterr.New(index.CodeIndexStale, "x"), "ERR_INDEX_STALE"},
		{"cli root required", &cliError{code: "ERR_ROOT_SIGNATURE_REQUIRED", msg: "x"}, "ERR_ROOT_SIGNATURE_REQUIRED"},
		{"cli state invalid", &cliError{code: "ERR_STATE_INVALID", msg: "x"}, "ERR_STATE_INVALID"},
		{"uncoded", errors.New("plain"), "ERR_VERIFY"},
		{"internal code", conduiterr.New(conduiterr.CodeInternal, "x"), "ERR_VERIFY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errCode(tc.err); got != tc.want {
				t.Fatalf("errCode(%v) = %s, want %s", tc.err, got, tc.want)
			}
		})
	}
}

// TestExitCode_SuccessIsQuietExit0 pins the binary contract on the happy
// path: exit 0, NO output on stdout or stderr, verified raw bytes on disk,
// state ratcheted. The payload timestamp is REAL now (not testNow): the
// child runs its staleness check against its own clock, and a fixed
// 2026-08-29 timestamp would go stale after seven days and break CI.
func TestExitCode_SuccessIsQuietExit0(t *testing.T) {
	_, priv := mustGenerateKey(t)
	raw := signPayload(t, makePayload(1, time.Now().UTC()), "root", priv)
	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	stdout, stderr, code := runBinary(t, priv, "--index", srv.URL, "--state", statePath, "--out", outPath)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty (success must be quiet)", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty on success", stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("out file not written: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("out bytes differ from the served raw bytes")
	}
	state, err := index.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 {
		t.Fatalf("state version = %d, want 1", state.Version)
	}
}

// TestExitCode_VerificationFailureExit1 pins the binary contract on failure:
// exit 1 and the stable ERR_* code on stderr.
func TestExitCode_VerificationFailureExit1(t *testing.T) {
	_, priv := mustGenerateKey(t)
	tampered := signPayload(t, makePayload(1, testNow), "root", priv)
	tampered = bytes.Replace(tampered, []byte(`"version":1`), []byte(`"version":2`), 1)
	srv := serve(t, tampered)
	statePath, outPath := tempPaths(t)

	stdout, stderr, code := runBinary(t, priv, "--index", srv.URL, "--state", statePath, "--out", outPath)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "ERR_INDEX_INTEGRITY") {
		t.Fatalf("stderr = %q, want it to contain ERR_INDEX_INTEGRITY", stderr)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("failed verification must not write --out, stat err = %v", err)
	}
}

// TestExitCode_UsageErrorExit2 pins the usage-error contract: exit 2 with a
// usage message and no ERR_* code (exit status distinguishes usage from
// verification failure).
func TestExitCode_UsageErrorExit2(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"non-positive timeout", []string{"--timeout", "0s"}},
		{"unknown flag", []string{"--bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, priv := mustGenerateKey(t)
			stdout, stderr, code := runBinary(t, priv, tc.args...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Fatal("usage errors must print a message to stderr")
			}
		})
	}
}
