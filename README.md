# conduit-registry-ui

The public web UI for the Conduit connector registry — a static site generated at build time
from the signed registry index. No backend, no client-side fetch-and-render of the catalog:
every connector fact on every page traces back to a field in the index, rendered as real,
crawlable HTML that's fully present with JavaScript disabled.

**This site is a convenience. The `conduit` CLI is the authority.** See "Trust model" below
before reading anything on this site as a security claim.

## Relocation

This repo's history starts life as `web/` inside `ConduitIO/conduit-connector-registry`
(commits `36f6b28` and `9c92e6c`, both by the original author, preserved via
`git filter-repo --path web/ --path-rename web/:` — a full history split, not a squashed
import). That repo now owns only the signed index (`index/`, served at
`registry.conduitdata.io/index.json`, which is `registry.DefaultIndexURL` compiled into every
shipped `conduit` binary). This repo owns the web UI that reads it. See WS4's plan
(`ws4-registry-ui-plan.md` §4, "Decouple the index from the site") for why: shipping the two
together meant an a11y or lint failure in the UI could block a security yank from reaching
users.

**This slice (S1) is scaffold-and-relocate only.** It does not change what
`registry.conduitdata.io/index.json` serves, does not deploy this site anywhere, and does not
touch the verified badge's logic. Those land in later slices — see "Trust model" below and
"What's not here yet".

## Stack

**Astro (static output) + React islands**, not a Vite CSR SPA. Astro ships zero client JS by
default and opts individual components into hydration explicitly; the two islands are the
search box (`src/components/SearchBox.tsx`) and the copy-install-command button
(`src/components/CopyInstallButton.tsx`). Every badge/tag/banner/compat-cell renders as plain
server-generated HTML with no hydration.

Shared visual language with `conduit-ui` (the in-engine built-in UI): `src/styles/tokens.css`
is a verbatim copy of that repo's token file (see `scripts/check-token-drift.ts`).

## Trust model

**This site is a convenience. The `conduit` CLI is the authority. If they disagree, believe the
CLI.**

Two distinct "verified" claims exist on this site. Say them separately:

- **The index is root-verified — REAL (S2).** The build runs the Go verifier CLI
  (`cmd/registry-verify`, WS4 S2), which imports the conduit CLI's own verifier and compiled-in
  trust anchors (`registry.DefaultTrustAnchors()` — no PEM is copied here, and this site can
  never claim more than the CLI would accept). With `--require-root`, the CLI checks the index's
  root signature, refuses a freshness-only acceptance outright, checks rollback against the
  committed high-water state (`verify/state.json`), and enforces the CLI's own 7-day staleness
  window. Any failure exits non-zero before `astro build` runs: **an index the conduit CLI
  would refuse cannot reach this site.** The verdict (exit 0) flows into the render model as
  `verified: true` (`src/lib/verifyViaCli.ts`).
- **The per-version badge — "Signature on file"** reflects exactly one fact: that version's
  entry in the verified index _references_ a signature and a SLSA provenance bundle, the
  version isn't yanked, and its publisher isn't revoked (`src/lib/deriveVerified.ts`). **It does
  not mean this site has cryptographically checked that version's artifact bytes.** No component
  in this repo re-runs `cosign verify`, checks Sigstore/Rekor inclusion, or validates SLSA
  provenance against a pinned identity.

The badge's original justification assumed an "index-CI" job in `conduit-connector-registry`
that re-fetches every artifact, recomputes its checksum, and runs `cosign verify` before merge.
**That job does not exist yet.** Until it does, or until this repo performs the check itself,
"Signature on file" means "the verified index says this version was signed," not "we checked
the bytes."

Remaining slices of this workstream:

- **S3** — per-artifact Sigstore/SLSA verification against the pinned publisher identity, a
  three-state badge (pass / fail-with-reason / not-attempted — never a bare presence check), a
  `/verify` page, and on-page copy naming exactly what was and wasn't checked, as-of timestamp
  included.

The only verification that actually protects an install is your own CLI:

```sh
conduit connectors install <name>
conduit connectors audit
```

`conduit connectors install` independently verifies the index envelope's signature, per-artifact
Sigstore signatures and SLSA provenance against pinned identities, staleness, and rollback —
unconditionally, on every install, regardless of what any web page says. See
`ws4-registry-ui-plan.md` §1 for the exact verification the CLI performs.

## What's not here yet

- Per-artifact Sigstore/SLSA verification at build time (three-state badge, `/verify` page) — S3.
- A production deploy of this site, or any DNS/hosting change. `registry.conduitdata.io` stays
  with `conduit-connector-registry` until S6.

## Build pipeline (`npm run build`, `scripts/build-site.ts`)

1. **Fetch + verify the live signed index with the Go verifier CLI** (`cmd/registry-verify`,
   `--require-root`; the CLI's compiled-in default is `registry.DefaultIndexURL` —
   `registry.conduitdata.io/index.json`). The CLI imports the conduit CLI's own verifier and
   compiled-in trust anchors: root-signature check, freshness-only acceptance refused outright,
   rollback against the committed high-water state (`verify/state.json`), and the CLI's own
   7-day staleness window. Any failure — `ERR_INDEX_UNREACHABLE`, `ERR_INDEX_INTEGRITY`,
   `ERR_INDEX_ROLLBACK`, `ERR_INDEX_STALE`, ... — exits non-zero here.
2. The CLI's exit 0 **is** the verification verdict; the verified RAW bytes it wrote to
   `verify/index.json` flow onward untouched (never re-parsed into a trust decision).
3. Derive the render model (every computed fact — verified, effective status, default version,
   compat matrix — computed once, here).
4. Fetch Scarf download stats, best-effort (never fails the build; no real data source is
   provisioned today, so this degrades to "unavailable" and the stats section is not rendered).
5. `astro build`.
6. Copy the verified index bytes byte-for-byte into `dist/` and verify the copy — never a
   re-serialization, since the detached signature is computed over exact bytes.

A failure at steps 1-4 exits non-zero **before** `astro build` ever runs — and `dist/` is
removed at pipeline start, so a failed build provably leaves no `dist/` at all. The deployed
site is untouched until a fully successful build's artifact is deployed.

### Build inputs (environment)

| Variable                       | Meaning                                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REGISTRY_INDEX_URL`           | `--index` to pass the CLI (URL or local path). Unset = the CLI's default, the **live** index. **Refused in GitHub Actions** (`ERR_BUILD_CONFIG`). |
| `REGISTRY_VERIFY_BIN`          | Path to a prebuilt `registry-verify` binary (CI builds one). Unset = `go run ./cmd/registry-verify` (requires Go — local dev).                    |
| `REGISTRY_VERIFY_ANCHORS_FILE` | `--anchors-file` to pass the CLI — the test/offline anchors facility. **Refused in GitHub Actions** (`ERR_BUILD_CONFIG`).                         |

`REGISTRY_INDEX_URL` and `REGISTRY_VERIFY_ANCHORS_FILE` together are the functional equivalent of
the deleted staleness override — they bypass the trust chain — so CI hard-fails on either instead
of trusting a comment: a GitHub Actions build always verifies the **live** index against the
**compiled-in** production anchors. Both remain fully available for local and offline builds.

The pre-S2 knobs `REGISTRY_INDEX_PATH` and `REGISTRY_MAX_STALENESS_MS` are **gone**: the build
no longer reads a fixture from disk by default, and the staleness window is the CLI's own 7 days
(`index.DefaultMaxStaleness`) — not a build knob at all. A genuinely stale live index fails the
build with `ERR_INDEX_STALE`, and that is the alarm, not a config problem (see the CI section
below).

### CI and the staleness alarm

`.github/workflows/ci.yml` runs the real verify against the **live** index on every build — PRs
included. A red build-and-test with no code change therefore means the live index is stale
(>7 days), tampered, or rolled back — a problem with the index, not with this repo's code.
That is a feature: the build is the alarm. The fix is a human action (refresh/re-sign the index,
or explicitly acknowledge the state), then re-dispatch — never a staleness override. The
`ratchet-state` job commits the updated `verify/state.json` back to `main` after a successful
main-branch build, so the rollback floor stays armed across CI runs; that job is
self-terminating (the rebuild it triggers finds the state unchanged and pushes nothing).

## Scripts

| Command                                 | Purpose                                                                                                                                        |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run dev`                           | Astro dev server                                                                                                                               |
| `npm run build`                         | The full pipeline above                                                                                                                        |
| `npm run typecheck`                     | `astro check` (TypeScript, strict)                                                                                                             |
| `npm run lint` / `npm run format:check` | ESLint (jsx-a11y on) / Prettier                                                                                                                |
| `npm test`                              | Vitest unit + component + build-pipeline-integration tests                                                                                     |
| `npm run axe`                           | Automated a11y scan (axe-core via real headless Chromium) against the built `dist/`                                                            |
| `npm run smoke:deployed`                | Post-deploy check: byte-compares the live `/index.json`, checks the list page (not run in this repo's CI yet — no deploy target here until S6) |
| `npm run check:tokens`                  | Diffs `tokens.css` against `conduit-ui`'s copy                                                                                                 |

## Known, flagged gaps (not silently deferred)

- Per-artifact verification at build time does not exist (see "Trust model" — S3). The index's
  root signature IS verified at build time by the conduit CLI's verifier (S2), but the artifact
  bytes themselves are only verified at install time, by your CLI.
- Scarf stats fetch targets a placeholder endpoint shape; no token is provisioned, so the section
  is removed rather than shown as permanently "unavailable" (an empty shelf would imply a data
  source exists when none does).
- No `deprecated` or `all-versions-yanked` connector exists in the current fixture data, so the
  a11y scan's status-variant coverage is active + revoked only for full-page scans; the
  `deprecated`/`yanked` component states are covered at the component level instead
  (`test/components.test.tsx`).

## License

Apache-2.0. See `LICENSE.md`.
