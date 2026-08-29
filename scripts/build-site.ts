#!/usr/bin/env tsx
/**
 * The registry site's own build orchestrator (step6-web-ui.md §3). Each
 * numbered step is a hard gate for the ones after it unless marked
 * "best-effort" — a failure before step 6 must exit non-zero BEFORE
 * `astro build` ever runs, so there is never a partial/empty dist/ and never
 * a deploy from bad data. Steps:
 *
 *   1. Fetch + verify the signed index with the Go verifier CLI
 *      (cmd/registry-verify, WS4 S2): --require-root against the live index
 *      (registry.DefaultIndexURL, the CLI's compiled-in default) unless
 *      REGISTRY_INDEX_URL points elsewhere. The CLI imports the conduit
 *      CLI's own verifier + compiled-in trust anchors — root-signature
 *      check, rollback against the committed high-water state
 *      (verify/state.json), and the CLI's 7-day staleness window. Any
 *      failure (ERR_INDEX_UNREACHABLE / ERR_INDEX_INTEGRITY /
 *      ERR_INDEX_ROLLBACK / ERR_INDEX_STALE / ...) exits non-zero here: no
 *      dist/, no deploy, the previous site stays up.
 *   2. Read the verified RAW bytes the CLI wrote to --out (verify/index.json).
 *      The CLI's exit 0 IS the verification verdict: `verified: true` flows
 *      into the render model from here, never from a re-check.
 *   3. Derive the render model (every derived field computed once, here).
 *   4. Fetch Scarf stats — BEST-EFFORT, never fails the build.
 *   5. Write the generated render-model.json + public/search-manifest.json
 *      Astro's pages/build consume.
 *   6. Run `astro build`.
 *   7. Copy the verified RAW index bytes BYTE-FOR-BYTE into dist/ (never
 *      re-serialized — see the comment at COPY_INDEX below) and verify the
 *      copy.
 *
 * The a11y scan (scripts/axe-scan.ts), deploy, and post-deploy smoke check
 * (scripts/post-deploy-smoke.ts) are separate CI workflow steps, run in that
 * order AFTER this script exits 0 — see .github/workflows/ci.yml. They stay
 * separate scripts so each is independently testable and runnable locally
 * without needing a live deploy target.
 *
 * # Environment
 *
 *   REGISTRY_INDEX_URL          --index to pass the CLI (URL or local path);
 *                                unset = the CLI's default, the LIVE index
 *                                at registry.conduitdata.io/index.json.
 *                                REFUSED in GitHub Actions (ERR_BUILD_CONFIG):
 *                                CI must verify the live index.
 *   REGISTRY_VERIFY_BIN         path to a prebuilt registry-verify binary;
 *                                unset = `go run ./cmd/registry-verify`
 *                                (requires Go — used for local dev).
 *   REGISTRY_VERIFY_ANCHORS_FILE  --anchors-file to pass the CLI; the
 *                                test/offline anchors facility. REFUSED in
 *                                GitHub Actions (ERR_BUILD_CONFIG), same
 *                                reason: CI verifies against the compiled-in
 *                                production anchors, always.
 *   REGISTRY_VERIFY_TRUST_ROOT_FILE  --trust-root-file to pass the CLI;
 *                                replaces the embedded production Sigstore
 *                                root for the artifacts verdicts pass.
 *                                REFUSED in GitHub Actions, same reason.
 *
 * The pre-S2 knobs REGISTRY_INDEX_PATH and REGISTRY_MAX_STALENESS_MS are
 * GONE: the build no longer reads a fixture from disk by default, and the
 * staleness window is now the CLI's own 7 days (index.DefaultMaxStaleness) —
 * not a build knob at all. A genuinely stale live index fails the build with
 * ERR_INDEX_STALE, and that is the alarm, not a config problem.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyIndexViaCli } from '../src/lib/verifyViaCli';
import { buildRenderModel } from '../src/lib/renderModel';
import { mergeScarfStats } from '../src/lib/scarfStats';
import { fetchAllScarfStats } from './fetchScarfStats';
import { BuildError } from '../src/lib/errors';
import type { ArtifactReport } from '../src/lib/verdicts';

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, '..');

const GENERATED_DIR = path.join(webRoot, '.generated');
const RENDER_MODEL_PATH = path.join(GENERATED_DIR, 'render-model.json');
const PUBLIC_DIR = path.join(webRoot, 'public');
const SEARCH_MANIFEST_PATH = path.join(PUBLIC_DIR, 'search-manifest.json');
const DIST_DIR = path.join(webRoot, 'dist');

// The committed high-water state file: the CLI's rollback floor and its
// memory across ephemeral CI runners. The build ratchets it in the
// workspace; CI commits the ratcheted file back on main (see ci.yml's
// ratchet-state job) so the rollback alarm stays armed across runs.
const STATE_PATH = path.join(webRoot, 'verify', 'state.json');
// The CLI writes the verified RAW bytes here; step 7 copies them into dist/.
const VERIFIED_INDEX_PATH = path.join(webRoot, 'verify', 'index.json');
// The CLI writes the per-version artifact verdict report here (WS4 S3,
// --artifacts); step 3 merges it into the render model.
const ARTIFACTS_REPORT_PATH = path.join(webRoot, 'verify', 'artifacts.json');

async function main(): Promise<void> {
  // Step 0: never let a stale dist/ from a previous run be mistaken for this
  // build's output. A failure at any later step now provably leaves no
  // dist/ at all — and the deployed site is untouched until a fully
  // successful build's artifact is deployed.
  rmSync(DIST_DIR, { recursive: true, force: true });

  // Step 1: fetch + verify via the CLI. Throws BuildError carrying the CLI's
  // own stable error code (ERR_INDEX_UNREACHABLE, ERR_INDEX_INTEGRITY,
  // ERR_INDEX_ROLLBACK, ERR_INDEX_STALE, ...) — caught in run() below, which
  // exits non-zero before astro build is ever invoked.
  console.log(
    `[registry-web] verifying index with cmd/registry-verify --require-root` +
      (process.env['REGISTRY_INDEX_URL']
        ? ` (--index ${process.env['REGISTRY_INDEX_URL']})`
        : ` (live index, the CLI's compiled-in default)`)
  );
  const raw = verifyIndexViaCli({
    ...(process.env['REGISTRY_INDEX_URL'] ? { indexURL: process.env['REGISTRY_INDEX_URL'] } : {}),
    ...(process.env['REGISTRY_VERIFY_ANCHORS_FILE']
      ? { anchorsFile: process.env['REGISTRY_VERIFY_ANCHORS_FILE'] }
      : {}),
    ...(process.env['REGISTRY_VERIFY_TRUST_ROOT_FILE']
      ? { trustRootFile: process.env['REGISTRY_VERIFY_TRUST_ROOT_FILE'] }
      : {}),
    // The site build ALWAYS runs the artifacts pass: the per-version
    // verdicts (and the footer's verifier version) are build data, not an
    // option. Without --trust-root-file it verifies against the embedded
    // production Sigstore trust root — the real production path.
    artifactsOut: ARTIFACTS_REPORT_PATH,
    statePath: STATE_PATH,
    outPath: VERIFIED_INDEX_PATH,
    cwd: webRoot,
  });

  // Step 2: the CLI's exit 0 (--require-root) is the whole verification
  // verdict. The raw bytes are already trusted; this parse is for the render
  // model only, never a re-check. Refuse anything that isn't even an
  // envelope (defensive — the CLI would have refused it first).
  let payload: unknown;
  try {
    payload = JSON.parse(raw.toString('utf-8')).payload;
  } catch (err) {
    throw new BuildError(
      'ERR_INDEX_INTEGRITY',
      `verified index is not a parseable envelope: ${(err as Error).message}`
    );
  }
  if (typeof payload !== 'object' || payload === null) {
    throw new BuildError('ERR_INDEX_INTEGRITY', 'verified index has no payload object');
  }
  const typedPayload = payload as Parameters<typeof buildRenderModel>[0];
  const schemaVersion = (typedPayload as { schemaVersion?: unknown }).schemaVersion;
  console.log(
    `[registry-web] index OK: schemaVersion=${String(schemaVersion)} ` +
      `version=${String((typedPayload as { index?: { version?: unknown } }).index?.version)} ` +
      `connectors=${String((typedPayload as { connectors?: unknown[] }).connectors?.length)} ` +
      `(root-verified by the conduit verifier CLI)`
  );

  // Step 2.5: read the artifacts verdict report the CLI wrote in the same
  // run (WS4 S3). The CLI's exit 0 covered the index pipeline; the artifacts
  // pass runs after and never fails the build — but a MISSING report is a
  // build bug (the --artifacts flag is always passed) and fails closed.
  let artifactsReport: ArtifactReport | undefined;
  try {
    artifactsReport = JSON.parse(readFileSync(ARTIFACTS_REPORT_PATH, 'utf-8')) as ArtifactReport;
  } catch (err) {
    throw new BuildError(
      'ERR_ARTIFACTS_REPORT_MISMATCH',
      `verifier CLI exited 0 but wrote no artifacts report at ${ARTIFACTS_REPORT_PATH}: ` +
        `${(err as Error).message}`
    );
  }

  // Step 3: derive render model (throws BuildError on e.g. reserved-name
  // collision or a verdicts report that does not describe the verified
  // index). The CLI's exit 0 with --require-root IS the root-verified
  // verdict; the artifacts report carries the per-version verdicts.
  let model = buildRenderModel(typedPayload, {
    verified: true,
    artifacts: artifactsReport,
  });

  // Step 4: Scarf stats, best-effort — a Scarf-fetch failure never throws
  // past fetchAllScarfStats (it degrades to `unavailable: true` per connector).
  const stats = await fetchAllScarfStats(model.connectors.map((c) => c.name));
  model = mergeScarfStats(model, stats);

  // Step 5: write generated artifacts consumed by the Astro build.
  mkdirSync(GENERATED_DIR, { recursive: true });
  writeFileSync(RENDER_MODEL_PATH, JSON.stringify(model, null, 2));
  mkdirSync(PUBLIC_DIR, { recursive: true });
  writeFileSync(SEARCH_MANIFEST_PATH, JSON.stringify(model.searchManifest));
  console.log(
    `[registry-web] wrote render model (${model.connectors.length} connectors) + search manifest`
  );

  // Step 6: astro build.
  const astroResult = spawnSync('npx', ['astro', 'build'], {
    cwd: webRoot,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (astroResult.status !== 0) {
    throw new Error(`astro build failed with exit code ${astroResult.status ?? 'unknown'}`);
  }

  // Step 7: copy the verified index BYTE-FOR-BYTE into dist/ — this must
  // NEVER be a re-serialization (JSON.parse + JSON.stringify would reformat
  // whitespace and could reorder keys depending on the parser, silently
  // invalidating the detached signature, which is computed over the exact
  // JCS-canonicalized payload bytes). We copy the exact same bytes the CLI
  // verified and wrote to --out, untouched.
  mkdirSync(DIST_DIR, { recursive: true });
  const distIndexPath = path.join(DIST_DIR, 'index.json');
  writeFileSync(distIndexPath, raw);
  const writtenBack = readFileSync(distIndexPath);
  if (!writtenBack.equals(raw)) {
    throw new Error('dist/index.json does not byte-match the verified index — refusing to proceed');
  }
  console.log(`[registry-web] dist/index.json byte-verified against ${VERIFIED_INDEX_PATH}`);
  console.log('[registry-web] build complete.');
}

main().catch((err: unknown) => {
  if (err instanceof BuildError) {
    console.error(`[registry-web] BUILD FAILED [${err.code}]: ${err.message}`);
  } else {
    console.error('[registry-web] BUILD FAILED:', err);
  }
  process.exitCode = 1;
});
