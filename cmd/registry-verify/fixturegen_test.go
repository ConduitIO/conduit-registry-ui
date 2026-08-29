package main

import (
	"context"
	"encoding/json"
	"github.com/conduitio/conduit/pkg/registry/index"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateSignedFixture generates a root-signed index fixture plus its
// TrustAnchors file from the committed TEMPLATE payload
// (test/fixtures/sample-index.json), so the site's build-pipeline tests can
// drive the REAL verifier CLI offline (vitest shells out to this test with
// FIXTURE_OUT_DIR set, then points --index / --anchors-file at the
// generated files). The fixture is signed with a freshly generated test key
// and stamped with `now`, so it is never stale at generation time and never
// touches production keys or the network.
//
// The committed template's own root signature is FAKE (a synthetic keyId and
// signature bytes — it exists only so the pre-S2 TS structural stub had an
// envelope to check). Nothing may ever treat it as trusted; that is asserted
// by TestCommittedTemplateIsNotTrusted below.
const fixtureOutDirEnv = "FIXTURE_OUT_DIR"

func TestGenerateSignedFixture(t *testing.T) {
	outDir := os.Getenv(fixtureOutDirEnv)
	if outDir == "" {
		t.Skip("FIXTURE_OUT_DIR not set — nothing to write; set it to generate the site's offline fixture (scripts/tests shell out to this)")
	}

	// Load the committed template and keep only its payload, the source of
	// the site's render-model data (schemaVersion 1, 2 connectors).
	templatePath := filepath.Join("..", "..", "test", "fixtures", "sample-index.json")
	templateRaw, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("reading template fixture: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(templateRaw, &envelope); err != nil {
		t.Fatalf("parsing template fixture: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope["payload"], &payload); err != nil {
		t.Fatalf("parsing template payload: %v", err)
	}

	// Stamp the current time so the fixture passes the CLI's own 7-day
	// staleness window against the wall clock.
	indexObj, ok := payload["index"].(map[string]any)
	if !ok {
		t.Fatalf("template payload has no index object")
	}
	indexObj["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	stampedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("re-marshaling stamped payload: %v", err)
	}

	// Sign exactly the way the index-sign tool does (signPayload: JCS
	// canonicalize + index.KeyID + ed25519), root role only — the site's
	// build always runs with --require-root.
	pub, priv := mustGenerateKey(t)
	signedEnvelope := signPayload(t, stampedPayload, "root", priv)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("creating fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "signed-index.json"), signedEnvelope, 0o644); err != nil {
		t.Fatalf("writing signed fixture: %v", err)
	}

	keyID, err := index.KeyID(pub)
	if err != nil {
		t.Fatalf("deriving keyId: %v", err)
	}
	anchors := map[string]any{
		"roots":     map[string]any{keyID: pub},
		"freshness": map[string]any{},
	}
	anchorsJSON, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("marshaling anchors file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "anchors.json"), anchorsJSON, 0o644); err != nil {
		t.Fatalf("writing anchors file: %v", err)
	}

	// Round-trip proof: the generated fixture must verify through run() with
	// the generated anchors, byte-for-byte, with --require-root — the exact
	// invocation the site build makes.
	statePath, outPath := tempPaths(t)
	if err := run(context.Background(), options{
		indexURL:    filepath.Join(outDir, "signed-index.json"),
		outPath:     outPath,
		statePath:   statePath,
		anchors:     testAnchors(pub),
		requireRoot: true,
		now:         time.Now,
	}); err != nil {
		t.Fatalf("generated fixture does not verify through the real pipeline: %v", err)
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading verified out file: %v", err)
	}
	if string(written) != string(signedEnvelope) {
		t.Fatalf("out bytes do not match the signed fixture")
	}
}

// TestCommittedTemplateIsNotTrusted is the honesty guard for the fixture
// strategy. The committed template's root signature is synthetic (a made-up
// keyId and signature bytes), so the real verifier must REFUSE it — anchored
// against the REAL production anchors (productionAnchors(), the same set the
// site build verifies with), not a test key: the premise is that the template
// is trusted by NO key in the production trust core. If this test starts
// passing, someone signed the template with a production root key and the
// "fake signature" premise in this file's doc comment is stale.
func TestCommittedTemplateIsNotTrusted(t *testing.T) {
	anchors, err := productionAnchors()
	if err != nil {
		t.Fatalf("production anchors unavailable: %v", err)
	}
	_, outPath := tempPaths(t)
	err = run(context.Background(), options{
		indexURL:    filepath.Join("..", "..", "test", "fixtures", "sample-index.json"),
		outPath:     outPath,
		statePath:   filepath.Join(t.TempDir(), "state.json"),
		anchors:     anchors,
		requireRoot: true,
		now:         time.Now,
	})
	if err == nil {
		t.Fatalf("committed template verified — the fake root signature is being trusted, fixture premise broken")
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Fatalf("rejected index still wrote an out file — fail-closed violated")
	}
}
