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
//     ERR_INDEX_INTEGRITY, never accepted.
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
// Failure behavior: every failure prints a stable ERR_* code to stderr and
// exits non-zero; success is a quiet exit 0.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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
)

// options are the verified pipeline's inputs. Anchors are injected so tests
// can run the pipeline against test keys; production always passes
// connectors.DefaultTrustAnchors().
type options struct {
	indexURL  string
	outPath   string
	statePath string
	anchors   index.TrustAnchors
	now       func() time.Time // injectable clock for the staleness window
}

func main() {
	indexURL := flag.String("index", registry.DefaultIndexURL,
		"URL of the signed registry index to verify")
	outPath := flag.String("out", defaultOutPath,
		"where to write the verified RAW index bytes (the build copies these into dist/)")
	statePath := flag.String("state", defaultStatePath,
		"path of the committed high-water state file (index.State JSON)")
	timeout := flag.Duration("timeout", defaultTimeout, "fetch timeout")
	flag.Parse()

	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "registry-verify: usage: --timeout must be positive\n")
		os.Exit(exitUsage)
	}

	// Anchors are compiled into the pinned conduit module (its production
	// PEMs are go:embed'd and parsed at package init) — never copied here.
	// A stripped/broken module must fail closed, mirroring the CLI's own
	// guardTrustAnchors discipline: a build with no anchors verifies nothing.
	if err := connectors.AnchorLoadErr(); err != nil {
		fail(conduiterr.Wrap(registry.CodeTrustAnchorsUnavailable,
			"this build has no usable registry trust anchors (defect in the pinned conduit module) — refusing to verify any index", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, options{
		indexURL:  *indexURL,
		outPath:   *outPath,
		statePath: *statePath,
		anchors:   connectors.DefaultTrustAnchors(),
		now:       time.Now,
	}); err != nil {
		fail(err)
	}
	// Success is quiet: exit 0 with no output.
}

// fail prints the stable error code + message and exits non-zero. Every
// verification failure funnels through here, so no failure mode can exit 0.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "registry-verify: %s: %v\n", errCode(err), err)
	os.Exit(exitFail)
}

// run executes the whole verify pipeline. It is separated from main so the
// round-trip tests can drive it against an httptest server and test keys.
func run(ctx context.Context, opts options) error {
	if opts.now == nil {
		opts.now = time.Now
	}

	// High-water mark from the committed state file; a missing file is the
	// zero State (no rollback protection on the very first fetch — the index
	// package's documented bootstrap gap, covered by staleness alone).
	state, err := index.LoadState(opts.statePath)
	if err != nil {
		return err
	}

	raw, err := index.Fetch(ctx, opts.indexURL)
	if err != nil {
		return err
	}

	// Verify the exact bytes we will ship: signatures against the compiled-in
	// anchors, with the persisted content-subtree hash so a freshness-only
	// signature can only ever extend timestamp/version over byte-identical
	// content — never authorize content on its own.
	verified, err := index.Verify(raw, opts.anchors, state.LastVerifiedContentHash)
	if err != nil {
		return err
	}

	if err := index.CheckRollback(verified.Payload.Index.Version, state.Version); err != nil {
		return err
	}
	if err := index.CheckStaleness(verified.Payload.Index.Timestamp, opts.now(), index.DefaultMaxStaleness); err != nil {
		return err
	}

	// Every check passed. Write the RAW bytes first (atomic, so a crash can
	// never leave a torn index the build might copy), then ratchet the
	// high-water mark — never on a rejected fetch, so an attacker can't push
	// the trusted floor forward with garbage.
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

// writeRawAtomic writes raw to path via temp + rename (Invariant 5: torn
// writes must be impossible).
func writeRawAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return conduiterr.Wrap(conduiterr.CodeInternal, fmt.Sprintf("writing %s", tmp), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return conduiterr.Wrap(conduiterr.CodeInternal, fmt.Sprintf("renaming %s -> %s", tmp, path), err)
	}
	return nil
}

// errCode maps a conduit error onto this CLI's stable, documented error code
// — the WS4 plan's five codes plus the two other codes the index package can
// actually raise. Unknown or un-coded errors get a generic code; every
// failure still exits non-zero.
func errCode(err error) string {
	ce, ok := conduiterr.Get(err)
	if !ok {
		return "ERR_VERIFY"
	}
	switch ce.Code.Reason() {
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
	case index.CodeIndexRollback.Reason():
		return "ERR_INDEX_ROLLBACK"
	case index.CodeIndexStale.Reason():
		return "ERR_INDEX_STALE"
	default:
		return "ERR_VERIFY"
	}
}
