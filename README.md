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

Every "Verified" badge on this site today reflects exactly one fact: the signed registry index
_references_ a signature and a SLSA provenance bundle for that version, the version isn't
yanked, and its publisher isn't revoked (`src/lib/deriveVerified.ts`). **It does not mean this
site has cryptographically checked that signature, that provenance, or the index's own root
signature.** No component in this repo re-runs `cosign verify`, checks Sigstore/Rekor
inclusion, or validates SLSA provenance against a pinned identity — `src/lib/verifyIndex.ts`'s
root-signature check is an explicit, commented stub that validates envelope _shape_, never the
signature itself.

The badge's original justification assumed an "index-CI" job in `conduit-connector-registry`
that re-fetches every artifact, recomputes its checksum, and runs `cosign verify` before merge.
**That job does not exist yet.** Until it does, or until this repo performs the check itself,
"Verified" here means "the signed index says this version was signed," not "we checked."

Real, identity-pinned verification — importing the same verifier code and the same compiled-in
trust anchors the `conduit` CLI uses (`registry.DefaultTrustAnchors()`), so this site can never
claim more than the CLI would accept — is planned for later slices of this workstream:

- **S2** — the site verifies the index's own root signature itself (reject on tamper, rollback,
  or staleness beyond the CLI's own window), and the stub above is deleted.
- **S3** — per-artifact Sigstore/SLSA verification against the pinned publisher identity, a
  three-state badge (pass / fail-with-reason / not-attempted — never a bare presence check), a
  `/verify` page, and on-page copy naming exactly what was and wasn't checked, as-of timestamp
  included.

Until S2/S3 ship, the only verification that actually protects an install is your own CLI:

```sh
conduit connectors install <name>
conduit connectors audit
```

`conduit connectors install` independently verifies the index envelope's signature, per-artifact
Sigstore signatures and SLSA provenance against pinned identities, staleness, and rollback —
unconditionally, on every install, regardless of what any web page says. See
`ws4-registry-ui-plan.md` §1 for the exact verification the CLI performs.

## What's not here yet

- `cmd/registry-verify` (the Go CLI that will perform real index/artifact verification) — S2.
- Any change to the badge's derivation or to `deriveVerified.ts` — S2/S3.
- A production deploy of this site, or any DNS/hosting change. `registry.conduitdata.io` stays
  with `conduit-connector-registry` until S6.

## Build pipeline (`npm run build`, `scripts/build-site.ts`)

1. Read the signed index from disk (no network hop). **This repo no longer colocates `index/`**
   (see "Relocation" above) — the default source is a fixture synthesized fresh at build time
   (`scripts/generate-fixture.ts` stamps the current time onto the committed template
   `test/fixtures/sample-index.json`, writing the gitignored `.generated/sample-index.json`),
   so the fixture can never rot against the staleness gate; set `REGISTRY_INDEX_PATH` to point
   at a real index file instead (read byte-for-byte, unmodified, facing the same real window).
   A real fetch-and-verify pipeline against the live index lands in S2.
2. Verify the index's own root signature — **currently stubbed** (see "Trust model"). Structural
   integrity (malformed envelope, schema-too-new) still hard-fails the build today.
3. Freshness check against `REGISTRY_MAX_STALENESS_MS` (default 30 days, no CI override). A
   stale index — the frozen template passed via `REGISTRY_INDEX_PATH`, or any index older than
   the window — fails the build with `ERR_INDEX_STALE`.
4. Derive the render model (every computed fact — verified, effective status, default version,
   compat matrix — computed once, here).
5. Fetch Scarf download stats, best-effort (never fails the build; no real data source is
   provisioned today, so this degrades to "unavailable" and the stats section is not rendered).
6. `astro build`.
7. Copy `index.json` byte-for-byte into `dist/` and verify the copy — never a re-serialization,
   since a detached signature is computed over exact bytes.

A failure at steps 1-4 exits non-zero **before** `astro build` ever runs: no `dist/`.

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

- Index root-signature verification is structural-only (see "Trust model") until S2 ships a real
  verifier.
- Scarf stats fetch targets a placeholder endpoint shape; no token is provisioned, so the section
  is removed rather than shown as permanently "unavailable" (an empty shelf would imply a data
  source exists when none does).
- No `deprecated` or `all-versions-yanked` connector exists in the current fixture data, so the
  a11y scan's status-variant coverage is active + revoked only for full-page scans; the
  `deprecated`/`yanked` component states are covered at the component level instead
  (`test/components.test.tsx`).

## License

Apache-2.0. See `LICENSE.md`.
