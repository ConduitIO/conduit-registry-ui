import { afterAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildRenderModel, type RenderModel } from '../src/lib/renderModel';
import type { ArtifactReport } from '../src/lib/verdicts';
import {
  loadEmptyConnectorsPayload,
  loadEmptyProcessorsPayload,
  loadSampleIndex,
} from './fixtures/loadFixture';

/**
 * Catalogue-page integration tests (WS4 S4) — the repo's snapshot tooling is
 * vitest's committed-snapshot support (`toMatchSnapshot`, devDependency), run
 * against the REAL rendered page output: this suite writes a deterministic
 * fixture render model exactly where scripts/build-site.ts would (`.generated/
 * render-model.json` + `public/search-manifest.json`) and runs the real
 * `astro build`, then asserts on the actual `dist/` HTML.
 *
 * Covering the three amended ACs whose acceptance lives at the page level:
 *  - 4.3: the connector detail page's key sections exist (versions table,
 *    install command, platform compat) — committed snapshot + structural
 *    assertions. (The config-schema summary the original AC asked for is
 *    impossible: the frozen index schema carries no config schema — the
 *    amended AC ratifies this, and the README states it as out of scope.)
 *  - 4.6: a legitimately-empty connectors/processors catalogue renders a
 *    distinct explicit empty-state copy (two fixtures, different strings),
 *    never the failure-looking "0 connectors in the registry", and the build
 *    never crashes.
 *  - 4.7: no Downloads section — `grep -c "Downloads" dist/` = 0.
 *
 * Everything is deterministic: the fixture render model fixes generatedAt,
 * the artifacts report, and index age, so the committed snapshot is stable
 * across runs and machines — the one exception (astro-island chunk hashes
 * and uids, which Vite derives from the module graph and vary by checkout
 * path) is normalized to placeholders before the snapshot comparison, see
 * the 4.3 test. No network, no Go, no live index.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GENERATED_DIR = path.join(root, '.generated');
const RENDER_MODEL_PATH = path.join(GENERATED_DIR, 'render-model.json');
const PUBLIC_DIR = path.join(root, 'public');
const SEARCH_MANIFEST_PATH = path.join(PUBLIC_DIR, 'search-manifest.json');
const DIST_DIR = path.join(root, 'dist');

// 6 days minus 1h after the fixtures' index.timestamp: inside the verifier's
// 7-day window AND inside the staleness banner's warn threshold, so no banner
// renders and the snapshot is stable (banner state is itself deterministic,
// but keeping the page banner-free makes the snapshot read as the clean page).
const GENERATED_AT = '2026-07-20T08:00:00Z';
const FIXTURE_INDEX_TIMESTAMP = '2026-07-14T09:00:00Z';

/** An artifacts report coherent with every fixture here (all share index
 * version 42 + the same timestamp), with no crypto rows — every version
 * renders not_attempted, deterministic. */
const ARTIFACTS_REPORT: ArtifactReport = {
  schemaVersion: 1,
  generatedAt: GENERATED_AT,
  indexVersion: 42,
  indexTimestamp: FIXTURE_INDEX_TIMESTAMP,
  verifierVersion: 'v0.20.0-nightly',
  connectors: [],
  processors: [],
};

function writeModel(model: RenderModel): void {
  mkdirSync(GENERATED_DIR, { recursive: true });
  writeFileSync(RENDER_MODEL_PATH, JSON.stringify(model));
  mkdirSync(PUBLIC_DIR, { recursive: true });
  writeFileSync(SEARCH_MANIFEST_PATH, JSON.stringify(model.searchManifest));
}

/** The same `npx astro build` the real pipeline runs (scripts/build-site.ts
 * step 6), with the fixture model as input. */
function astroBuild(): void {
  const res = spawnSync('npx', ['astro', 'build'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 300_000,
  });
  expect(res.status, `astro build failed:\n${res.stderr}`).toBe(0);
}

function readDist(relPath: string): string {
  return readFileSync(path.join(DIST_DIR, relPath), 'utf-8');
}

/** Walks dist/ and counts occurrences of the literal string `needle` — the
 * amended-4.7 AC is literally `grep -c "Downloads" dist/` = 0. */
function countInDist(needle: string): number {
  let count = 0;
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = path.join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else {
        const hay = readFileSync(full, 'utf-8');
        count += hay.split(needle).length - 1;
      }
    }
  };
  if (statSync(DIST_DIR).isDirectory()) walk(DIST_DIR);
  return count;
}

describe('catalogue pages — real astro build from fixture render models (WS4 S4)', () => {
  it('4.3: the connector detail page renders its key sections — committed snapshot of the real page', () => {
    writeModel(
      buildRenderModel(loadSampleIndex().payload, {
        verified: true,
        generatedAt: GENERATED_AT,
        artifacts: ARTIFACTS_REPORT,
      })
    );
    astroBuild();

    const html = readDist('connectors/postgres/index.html');

    // The committed snapshot pins the whole rendered page byte-for-byte,
    // except two build-artifact tokens that vary with the machine the build
    // runs on (proven on CI: identical chunk bytes, different hashes — Vite
    // derives the island chunk hash from the module graph, which embeds the
    // absolute repo path; the astro-island uid is a hash of that URL). The
    // snapshot would otherwise mismatch on every machine with a different
    // checkout path. Normalize exactly those two tokens; everything else is
    // pinned byte-for-byte, and a NEW machine-dependent token fails loudly
    // with a visible diff.
    const normalized = html
      .replace(/(<astro-island uid=")[A-Za-z0-9_-]+(")/g, '$1[uid]$2')
      .replace(/(component-url="\/_astro\/[^."]+\.)[A-Za-z0-9_-]{8}(\.js")/g, '$1[hash]$2');
    expect(normalized).toMatchSnapshot();

    // Structural assertions pin the semantics the snapshot protects (the
    // snapshot is data, these are the AC): the key sections exist.
    expect(html).toMatch(/<h2[^>]*>Versions<\/h2>/); // versions table
    expect(html).toContain('conduit connectors install postgres'); // install command
    expect(html).toMatch(/Platform compatibility/); // OS/arch matrix
    for (const version of ['0.14.0', '0.14.1', '0.14.2']) {
      expect(html).toContain(version); // every published version renders a row
    }
    // The revoked sibling connector page also builds (getStaticPaths covers
    // every entry) with its install suppressed — no active install command.
    const revokedHtml = readDist('connectors/example-vector-sink/index.html');
    expect(revokedHtml).toContain('Install is disabled');
    expect(revokedHtml).not.toContain('conduit connectors install example-vector-sink');
  });

  it('4.7: no "Downloads" anywhere in dist/ (amended AC: grep -c "Downloads" dist/ = 0)', () => {
    expect(countInDist('Downloads')).toBe(0);
    // The page no longer renders the stats section in ANY of its states —
    // not the header, not the "unavailable" fallback.
    expect(countInDist('Download stats')).toBe(0);
  });

  it('4.6: an empty connectors catalogue renders the distinct empty copy, never a failure string, build exit 0', () => {
    writeModel(
      buildRenderModel(loadEmptyConnectorsPayload(), {
        verified: true,
        generatedAt: GENERATED_AT,
        artifacts: ARTIFACTS_REPORT,
      })
    );
    astroBuild(); // must exit 0 — an empty index never crashes the build

    const html = readDist('index.html');
    expect(html).toContain('No connectors have been published to the registry yet.');
    // The failure-reading string the old copy produced must be gone.
    expect(html).not.toContain('0 connectors in the registry');
    // The empty copy is scoped to the connectors section: the processors
    // section keeps its normal count line, not the empty copy.
    expect(html).not.toContain('No processors have been published to the registry yet.');
    expect(html).toContain('2 processors in the registry');
  });

  it('4.6: an empty processors catalogue renders ITS distinct empty copy, connectors side unaffected', () => {
    writeModel(
      buildRenderModel(loadEmptyProcessorsPayload(), {
        verified: true,
        generatedAt: GENERATED_AT,
        artifacts: ARTIFACTS_REPORT,
      })
    );
    astroBuild(); // must exit 0

    const html = readDist('index.html');
    expect(html).toContain('No processors have been published to the registry yet.');
    expect(html).not.toContain('0 processors in the registry');
    expect(html).not.toContain('No connectors have been published to the registry yet.');
    expect(html).toContain('2 connectors in the registry');
  });
});

afterAll(() => {
  // Leave no trace: the test's fixture-based dist/, render-model.json, and
  // search-manifest.json are build outputs (gitignored) — the real build
  // regenerates all three. Cleaning up keeps a post-test `npm run dev` from
  // serving fixture data.
  //
  // Only the render-model FILE is removed, never the whole .generated/ dir:
  // CI's workflow pre-builds the registry-verify binary to
  // .generated/registry-verify before `npm test` and the build step needs it
  // afterwards — deleting the dir there breaks the build with ENOENT.
  rmSync(DIST_DIR, { recursive: true, force: true });
  rmSync(RENDER_MODEL_PATH, { force: true });
  rmSync(SEARCH_MANIFEST_PATH, { force: true });
});
