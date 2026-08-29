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
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conduitio/conduit/pkg/registry/index"
)

var testNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// makePayload builds a schemaVersion-1 payload with the given version and
// timestamp. connectors stays empty (the registry repo's own signer tests use
// the same emptyPayload shape).
func makePayload(version int64, ts time.Time) json.RawMessage {
	b, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"index": map[string]any{
			"version":   version,
			"timestamp": ts.UTC().Format(time.RFC3339),
		},
		"connectors": []any{},
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

func runVerify(t *testing.T, url, statePath, outPath string, anchors index.TrustAnchors, now time.Time) error {
	t.Helper()
	return run(context.Background(), options{
		indexURL:  url,
		outPath:   outPath,
		statePath: statePath,
		anchors:   anchors,
		now:       func() time.Time { return now },
	})
}

// TestVerify_RootSignedIndexAccepted is the round-trip agreement test: a
// root-signed index must verify, the exact raw bytes must land on disk, and
// the high-water state must ratchet to the new version.
func TestVerify_RootSignedIndexAccepted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := makePayload(1, testNow)
	raw := signPayload(t, payload, "root", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	if err := runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow); err != nil {
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := makePayload(1, testNow)
	raw := signPayload(t, payload, "root", priv)

	// Bump the version AFTER signing: the signature no longer covers the bytes.
	var env struct {
		Payload json.RawMessage `json:"payload"`
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
	tamperedPayload := makePayload(p.Index.Version+1, testNow)
	var env2 struct {
		Payload    json.RawMessage `json:"payload"`
		Signatures json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env2); err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(map[string]any{
		"payload":    tamperedPayload,
		"signatures": json.RawMessage(env2.Signatures),
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := serve(t, tampered)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signPayload(t, makePayload(1, testNow), "freshness", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
	if err == nil {
		t.Fatal("freshness-only index verified for a first-time client — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_INTEGRITY" {
		t.Fatalf("error code = %s, want ERR_INDEX_INTEGRITY (%v)", code, err)
	}
}

// TestVerify_FreshnessOnlyAcceptedOverByteIdenticalContent proves the
// freshness path works end to end when it SHOULD: a freshness signature over
// byte-identical content (matching the persisted content-subtree hash) is
// accepted and ratchets version/timestamp — and only over byte-identical
// content.
func TestVerify_FreshnessOnlyAcceptedOverByteIdenticalContent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchors := testAnchors(pub)
	statePath, outPath := tempPaths(t)

	// Phase 1: root-sign version 1 — establishes the content-subtree hash.
	rootSrv := serve(t, signPayload(t, makePayload(1, testNow), "root", priv))
	if err := runVerify(t, rootSrv.URL, statePath, outPath, anchors, testNow); err != nil {
		t.Fatalf("root-signed bootstrap: %v", err)
	}

	// Phase 2: freshness-sign version 2 over identical (empty) content.
	freshSrv := serve(t, signPayload(t, makePayload(2, testNow.Add(time.Hour)), "freshness", priv))
	if err := runVerify(t, freshSrv.URL, statePath, outPath, anchors, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("freshness re-sign over byte-identical content: %v", err)
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
	changedPayload, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"index":         map[string]any{"version": 3, "timestamp": testNow.Add(2 * time.Hour).UTC().Format(time.RFC3339)},
		"connectors":    []any{map[string]any{"name": "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	newContentSrv := serve(t, signPayload(t, changedPayload, "freshness", priv))
	err = runVerify(t, newContentSrv.URL, statePath, outPath, anchors, testNow.Add(2*time.Hour))
	if err == nil {
		t.Fatal("freshness signature over CHANGED content verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_INTEGRITY" {
		t.Fatalf("error code = %s, want ERR_INDEX_INTEGRITY (%v)", code, err)
	}
}

// TestVerify_StaleIndexFailsClosed: an index older than the CLI's own window
// (index.DefaultMaxStaleness, 7 days) must fail with ERR_INDEX_STALE even
// though the signature is valid.
func TestVerify_StaleIndexFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	staleTS := testNow.Add(-8 * 24 * time.Hour) // 8 days > DefaultMaxStaleness (7)
	raw := signPayload(t, makePayload(1, staleTS), "root", priv)

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statePath, outPath := tempPaths(t)

	// The state file records version 5 as the last accepted index.
	if err := index.SaveState(statePath, index.State{Version: 5}); err != nil {
		t.Fatal(err)
	}

	raw := signPayload(t, makePayload(3, testNow), "root", priv)
	srv := serve(t, raw)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
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
	_, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signPayload(t, makePayload(1, testNow), "root", signerPriv)

	unrelatedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srv := serve(t, raw)
	statePath, outPath := tempPaths(t)

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(unrelatedPub), testNow)
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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

	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
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
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	statePath, outPath := tempPaths(t)
	err = runVerify(t, srv.URL, statePath, outPath, testAnchors(pub), testNow)
	if err == nil {
		t.Fatal("unreachable index verified — must fail closed")
	}
	if code := errCode(err); code != "ERR_INDEX_UNREACHABLE" {
		t.Fatalf("error code = %s, want ERR_INDEX_UNREACHABLE (%v)", code, err)
	}
}
