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

// Command registry-verify verifies the root-signed registry index at BUILD
// time and fails the build closed. It is the Go half of WS4 S2: the Astro
// build (PR-2) runs this CLI and copies the verified raw index bytes into
// dist/ — an unverified index never reaches the site.
//
// Import, don't reimplement. This CLI imports conduit's own verifier and
// trust anchors — pkg/registry/index.Verify and
// cmd/conduit/root/connectors.DefaultTrustAnchors, pinned as a module
// dependency — the exact code the conduit CLI ships. No signature logic is
// rewritten here and no PEM is copied: the site can never accept an index
// the conduit CLI would refuse, because it IS the CLI's verifier.
//
// Pipeline (mirrors pkg/registry.TrustedVerifier.VerifyIndex, R-1 §a-§b):
//
//  1. Fetch the index over HTTP (index.Fetch, bounded at 8 MiB).
//  2. Verify signatures against the compiled-in anchors (index.Verify) —
//     a structurally valid freshness-only index with no root signature is
//     ERR_INDEX_INTEGRITY, never accepted by a client that hasn't seen the
//     content; with --require-root it is refused outright.
//  3. Check rollback against the committed high-water state
//     (index.CheckRollback) — the state lives in the repo
//     (verify/state.json), because ephemeral CI runners have no memory.
//  4. Check staleness against index.DefaultMaxStaleness, the CLI's own 7-day
//     window (index.CheckStaleness).
//  5. Only after every check passes: write the RAW fetched bytes to --out
//     (the build copies them into dist/ — never a re-encoding, since the
//     signature is over exact bytes) and persist the new high-water mark
//     (index.SaveState) for the next build.
//
// # --require-root and the freshness ratchet wedge
//
// By default this CLI accepts a freshness-only index when the content
// matches the persisted root-verified content hash — exactly what the
// conduit CLI does. That acceptance carries a wedge: the freshness-signed
// index can carry ANY version, so a freshness signature over identical
// content at version 99 ratchets the committed state to 99, and the next
// LEGIT root-signed index — whose version the registry bumped independently
// (12, say) — is then refused forever as ERR_INDEX_ROLLBACK until a human
// edits verify/state.json. Latent while the registry's published index is
// root-only (the index-sign.yml postmortem), but unrecoverable without
// manual intervention when it is not.
//
// The site build (PR-2) must therefore run with --require-root: a freshness
// signature can never be the FIRST or ONLY signature this trust core
// accepts, so no freshness-signed index can ratchet the state floor. The
// default stays accept-freshness to mirror the CLI's own behavior for
// interactive use.
//
// # State-file threat model
//
// verify/state.json carries no authenticator and cannot have one: it is
// committed to this repo, and git review is the entire boundary. That is
// the correct boundary — anyone who can push to this repo can already edit
// the build itself (scripts/build-site.ts is a repo file), so the state
// file adds no capability an attacker doesn't already have. It exists
// purely to give ephemeral CI runners memory they otherwise lack. Its diff
// is a ~4-line review surface; a reviewer can see at a glance whether a
// ratchet is plausible. A sanity cap on load (see run) turns an implausible
// version into a loud ERR_STATE_INVALID instead of a silent permanent
// rollback refusal.
//
// # Exit contract
//
// Success is a quiet exit 0 (no output). Every verification failure prints
// a stable ERR_* code + message to stderr and exits 1. Usage errors (bad
// flags, non-positive --timeout) exit 2 with a usage message and no code —
// exit status distinguishes usage from verification failure. Stable codes:
//
//	ERR_SCHEMA_TOO_NEW             payload.schemaVersion newer than this build understands
//	ERR_INDEX_UNREACHABLE          fetch-layer failure (network/HTTP)
//	ERR_INDEX_TOO_LARGE            index exceeds the 8 MiB fetch cap
//	ERR_INDEX_INTEGRITY            tampered/corrupted index, or a freshness-only
//	                               index with no root signature and no prior content
//	ERR_TRUST_ANCHOR_EXPIRED       no signature keyId matches any compiled-in anchor
//	ERR_TRUST_ANCHORS_UNAVAILABLE  this build has no usable anchors (broken module)
//	ERR_INDEX_ROLLBACK             version below the committed high-water mark
//	ERR_INDEX_STALE                timestamp older than the CLI's 7-day window
//	ERR_ROOT_SIGNATURE_REQUIRED    --require-root set, index freshness-only
//	ERR_STATE_INVALID              state file has an implausible high-water version
//	ERR_VERIFY                     fallback for unknown/un-coded errors
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/conduitio/conduit/cmd/conduit/root/connectors"
	"github.com/conduitio/conduit/pkg/foundation/cerrors/conduiterr"
	"github.com/conduitio/conduit/pkg/registry"
	"github.com/conduitio/conduit/pkg/registry/index"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2

	defaultOutPath   = "verify/index.json"
	defaultStatePath = "verify/state.json"
	defaultTimeout   = 30 * time.Second

	// maxStateVersion caps the loaded high-water mark. Real index versions
	// are a small monotonic counter (bumped per signed rebuild, daily at
	// most); anything beyond this is a typo or corruption in the committed
	// state file, and must fail loud instead of refusing every future index
	// as a rollback forever.
	maxStateVersion = 1 << 31
)

// options are the verified pipeline's inputs. Anchors are injected so tests
// can run the pipeline against test keys; production always passes
// productionAnchors().
type options struct {
	indexURL    string
	outPath     string
	statePath   string
	anchors     index.TrustAnchors
	requireRoot bool // refuse an index accepted on a freshness signature alone
	now         func() time.Time
}

// cliError is a CLI-owned failure with a stable code, for the failure modes
// the conduit index package does not model: the --require-root policy
// refusal and an implausible state file. errCode maps it directly; neither
// condition exists in the conduit CLI's own failure space, so no conduit
// code fits.
type cliError struct {
	code string
	msg  string
}

func (e *cliError) Error() string { return e.msg }

// productionAnchors returns this build's compiled-in registry trust anchors:
// the pinned conduit module's go:embed'd production PEMs, parsed by that
// package's init. Never copied here. A stripped/broken module must fail
// closed (mirroring the CLI's own guardTrustAnchors discipline): a build
// with no anchors verifies nothing. The test binary swaps this in TestMain
// so the subprocess exit-code contract can be tested deterministically
// without production keys or network access to the live index.
var productionAnchors = func() (index.TrustAnchors, error) {
	if err := connectors.AnchorLoadErr(); err != nil {
		return index.TrustAnchors{}, conduiterr.Wrap(registry.CodeTrustAnchorsUnavailable,
			"this build has no usable registry trust anchors (defect in the pinned conduit module) — refusing to verify any index", err)
	}
	return connectors.DefaultTrustAnchors(), nil
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

// realMain parses args, loads the production anchors, and runs the verify
// pipeline, returning the process exit code. Separated from main so the
// exit-code contract is testable via subprocess (see main_test.go).
func realMain(args []string) int {
	fs := flag.NewFlagSet("registry-verify", flag.ContinueOnError)
	indexURL := fs.String("index", registry.DefaultIndexURL,
		"URL of the signed registry index to verify")
	outPath := fs.String("out", defaultOutPath,
		"where to write the verified RAW index bytes (the build copies these into dist/)")
	statePath := fs.String("state", defaultStatePath,
		"path of the committed high-water state file (index.State JSON)")
	timeout := fs.Duration("timeout", defaultTimeout, "fetch timeout")
	requireRoot := fs.Bool("require-root", false,
		"refuse an index accepted on a freshness signature alone — only a root signature authorizes this build's trust core (the site build must pass this; see the ratchet-wedge note in the package doc)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *timeout <= 0 {
		fmt.Fprintf(fs.Output(), "registry-verify: usage: --timeout must be positive\n")
		return exitUsage
	}

	anchors, err := productionAnchors()
	if err != nil {
		fail(err)
		return exitFail
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, options{
		indexURL:    *indexURL,
		outPath:     *outPath,
		statePath:   *statePath,
		anchors:     anchors,
		requireRoot: *requireRoot,
		now:         time.Now,
	}); err != nil {
		fail(err)
		return exitFail
	}
	return exitOK
}

// fail prints the stable error code + message to stderr. Every verification
// failure funnels through here, so no failure mode can exit 0.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "registry-verify: %s: %v\n", errCode(err), err)
}

// run executes the whole verify pipeline. It is separated from realMain so
// the round-trip tests can drive it against an httptest server and test
// keys.
func run(ctx context.Context, opts options) error {
	if opts.now == nil {
		opts.now = time.Now
	}

	// High-water mark from the committed state file; a missing file is the
	// zero State (no rollback protection on the very first fetch — the index
	// package's documented bootstrap gap, covered by staleness alone).
	//
	// LoadState (pinned module) validates nothing, so cap here: a merged
	// state file with an implausible version would otherwise refuse every
	// future index as a rollback — a permanent build DoS that survives until
	// a human edits verify/state.json.
	state, err := index.LoadState(opts.statePath)
	if err != nil {
		return err
	}
	if state.Version < 0 || state.Version > maxStateVersion {
		return &cliError{
			code: "ERR_STATE_INVALID",
			msg:  fmt.Sprintf("state file %s has an implausible high-water version %d (max %d) — fix the committed verify/state.json", opts.statePath, state.Version, maxStateVersion),
		}
	}

	raw, err := index.Fetch(ctx, opts.indexURL)
	if err != nil {
		return err
	}

	// Verify the exact bytes we will ship: signatures against the compiled-in
	// anchors, with the persisted content-subtree hash so a freshness-only
	// signature can only ever extend timestamp/version over content this
	// build has already root-verified — never authorize content on its own.
	verified, err := index.Verify(raw, opts.anchors, state.LastVerifiedContentHash)
	if err != nil {
		return err
	}

	// Policy gate, immediately after cryptographic acceptance: the build
	// trust core refuses a freshness-only index outright when required. The
	// state floor is never touched by a freshness-only acceptance under
	// --require-root, so the ratchet wedge (see package doc) cannot open.
	if opts.requireRoot && !verified.RootVerified {
		return &cliError{
			code: "ERR_ROOT_SIGNATURE_REQUIRED",
			msg: fmt.Sprintf(
				"index version %d was accepted on a freshness signature alone, but --require-root is set — only a root-signed index authorizes this build's trust core (a freshness-only acceptance ratchets the high-water mark and can wedge the next legit root-signed index out as a rollback)",
				verified.Payload.Index.Version),
		}
	}

	if err := index.CheckRollback(verified.Payload.Index.Version, state.Version); err != nil {
		return err
	}
	if err := index.CheckStaleness(verified.Payload.Index.Timestamp, opts.now(), index.DefaultMaxStaleness); err != nil {
		return err
	}

	// Every check passed. Write the RAW bytes first (atomic, so no step can
	// observe a torn index), then ratchet the high-water mark — never on a
	// rejected fetch, so an attacker can't push the trusted floor forward
	// with garbage.
	if err := writeRawAtomic(opts.outPath, raw); err != nil {
		return err
	}

	newState := index.State{
		Version:                 verified.Payload.Index.Version,
		LastVerifiedContentHash: state.LastVerifiedContentHash,
	}
	if verified.RootVerified {
		// Only a root-verified index updates the content hash: a
		// freshness-only acceptance by construction already matches the
		// persisted hash, so re-deriving it is a no-op at best and must never
		// widen what freshness alone can authorize.
		//
		// Precision note: the hash gates the JCS-canonicalized projection of
		// connectors[]/processors[] THROUGH THIS BUILD'S TYPED SCHEMA — not
		// the raw received bytes. Fields a future schemaVersion adds inside
		// connectors[] are invisible to it, which is exactly why Verify still
		// demands a root signature for any index this build cannot fully
		// model: freshness-only acceptance is only ever a re-sign of content
		// this build has already root-verified through its own typed model.
		hash, err := index.HashContentSubtree(verified.Payload.Connectors, verified.Payload.Processors)
		if err != nil {
			return conduiterr.Wrap(conduiterr.CodeInternal, "could not hash the verified content subtree", err)
		}
		newState.LastVerifiedContentHash = hash
	}
	if err := index.SaveState(opts.statePath, newState); err != nil {
		return err
	}
	return nil
}

// writeRawAtomic writes raw to path via a unique temp file + rename, so a
// concurrent or interrupted run can never expose a partially-written index
// to a step that reads it. The temp name is unique per run (CreateTemp), so
// concurrent runs can't collide on ".tmp".
//
// Unlike index.SaveState — which fsyncs, because a torn high-water mark
// write would corrupt the rollback floor (Invariant 5, atomic state writes)
// — the raw index is a regenerated build artifact: a torn copy after a
// power loss is simply rewritten by the next run, so fsync is not required
// here.
func writeRawAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return conduiterr.Wrap(conduiterr.CodeInternal, fmt.Sprintf("creating temp file in %s", dir), err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = tmp.Close()
		return conduiterr.Wrap(conduiterr.CodeInternal, "setting temp file mode", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return conduiterr.Wrap(conduiterr.CodeInternal, "writing temp file", err)
	}
	if err := tmp.Close(); err != nil {
		return conduiterr.Wrap(conduiterr.CodeInternal, "closing temp file", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return conduiterr.Wrap(conduiterr.CodeInternal, fmt.Sprintf("renaming temp file -> %s", path), err)
	}
	return nil
}

// errCode maps an error onto this CLI's stable, documented error code (see
// the package doc for the full contract). CLI-owned codes (cliError) are
// recognized first; conduit codes map one-to-one onto their ERR_* names;
// everything else — un-coded or unknown — gets the generic ERR_VERIFY. Every
// failure still exits non-zero regardless of the code.
func errCode(err error) string {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.code
	}
	cerr, ok := conduiterr.Get(err)
	if !ok {
		return "ERR_VERIFY"
	}
	switch cerr.Code.Reason() {
	case index.CodeSchemaTooNew.Reason():
		return "ERR_SCHEMA_TOO_NEW"
	case index.CodeIndexUnreachable.Reason():
		return "ERR_INDEX_UNREACHABLE"
	case index.CodeIndexTooLarge.Reason():
		return "ERR_INDEX_TOO_LARGE"
	case index.CodeIndexIntegrity.Reason():
		return "ERR_INDEX_INTEGRITY"
	case index.CodeTrustAnchorExpired.Reason():
		return "ERR_TRUST_ANCHOR_EXPIRED"
	case registry.CodeTrustAnchorsUnavailable.Reason():
		return "ERR_TRUST_ANCHORS_UNAVAILABLE"
	case index.CodeIndexRollback.Reason():
		return "ERR_INDEX_ROLLBACK"
	case index.CodeIndexStale.Reason():
		return "ERR_INDEX_STALE"
	default:
		return "ERR_VERIFY"
	}
}
