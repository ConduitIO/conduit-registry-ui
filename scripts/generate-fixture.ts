/**
 * Synthesizes the build's fixture index with a fresh timestamp (WS4 S1).
 *
 * Why this exists: `test/fixtures/sample-index.json` is a committed template
 * whose `index.timestamp` is FROZEN (2026-07-14T09:00:00Z) so tests can reason
 * deterministically about it (they pass `now` explicitly — see
 * test/fixtures/loadFixture.ts's SAMPLE_INDEX_TIMESTAMP). But the build's
 * freshness gate (src/lib/verifyIndex.ts checkFreshness) compares against the
 * WALL CLOCK at the real `REGISTRY_MAX_STALENESS_MS` window (default 30 days),
 * so any fixed timestamp rots as calendar time passes — exactly what happened
 * to this template, and exactly what CI's 10-year REGISTRY_MAX_STALENESS_MS
 * override used to mask (deleted in WS4 S1: masking fixture rot with a wider
 * window is the "green over stale" pattern this project's trust model exists
 * to prevent).
 *
 * The build therefore never reads the committed template as-is. It calls
 * writeGeneratedFixture(), which stamps the current time onto the template and
 * writes `.generated/sample-index.json` (gitignored, alongside the render
 * model) — the fixture becomes "an index published just now," so the build
 * runs at the REAL staleness window with no override. A genuinely stale index
 * (e.g. an old fixture passed via REGISTRY_INDEX_PATH) still fails the build
 * with ERR_INDEX_STALE. Tests keep reading the committed template directly,
 * unchanged. Real index verification replaces this whole fixture path in S2.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { SignedIndex } from '../src/lib/schema';

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, '..');

/** The committed template — frozen timestamp, deterministic for tests. */
export const FIXTURE_TEMPLATE_PATH = path.join(webRoot, 'test', 'fixtures', 'sample-index.json');

/** Where the build consumes the fresh fixture (gitignored, like the render model). */
export const GENERATED_FIXTURE_PATH = path.join(webRoot, '.generated', 'sample-index.json');

/** The committed template with `payload.index.timestamp` stamped to `now`. The
 * only mutation is the timestamp — everything else is carried over verbatim so
 * the synthesized index exercises the exact same shape the tests pin down. */
export function generateFixtureIndex(now: Date = new Date()): SignedIndex {
  const template = JSON.parse(readFileSync(FIXTURE_TEMPLATE_PATH, 'utf-8')) as SignedIndex;
  template.payload.index.timestamp = now.toISOString();
  return template;
}

/** Writes the fresh fixture to `.generated/sample-index.json` and returns the
 * path — the default index source for scripts/build-site.ts. */
export function writeGeneratedFixture(now: Date = new Date()): string {
  const fixture = generateFixtureIndex(now);
  mkdirSync(path.dirname(GENERATED_FIXTURE_PATH), { recursive: true });
  writeFileSync(GENERATED_FIXTURE_PATH, JSON.stringify(fixture, null, 2));
  return GENERATED_FIXTURE_PATH;
}
