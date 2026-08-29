import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyAndParseIndex, DEFAULT_MAX_STALENESS_MS } from '../src/lib/verifyIndex';
import { BuildError } from '../src/lib/errors';
import {
  generateFixtureIndex,
  writeGeneratedFixture,
  GENERATED_FIXTURE_PATH,
} from '../scripts/generate-fixture';
import { loadSampleIndexRaw } from './fixtures/loadFixture';

/**
 * Regression tests for the fixture-freshness fix (WS4 S1). The rot this pins:
 * the committed template's timestamp is frozen (2026-07-14), so at the real
 * 30-day staleness window any wall-clock build eventually fails with
 * ERR_INDEX_STALE — which is what happened, and what CI's 10-year
 * REGISTRY_MAX_STALENESS_MS override used to mask. The build never reads the
 * template as-is; it synthesizes a fresh fixture. The first test below is the
 * one that would have caught the original bug: it runs the REAL freshness
 * path (wall-clock `now`, default window, no env override) against the
 * synthesized fixture.
 */
describe('generate-fixture — the build fixture never rots against the real staleness window', () => {
  it('passes the real build freshness check at wall-clock now, with no staleness override', () => {
    const raw = JSON.stringify(generateFixtureIndex());
    // Exactly what scripts/build-site.ts does with no REGISTRY_INDEX_PATH and
    // no REGISTRY_MAX_STALENESS_MS: verify + freshness at the 30-day default,
    // wall clock. The frozen template would have failed this as of 2026-08-13.
    const result = verifyAndParseIndex(raw, { maxStalenessMs: DEFAULT_MAX_STALENESS_MS });
    expect(result.payload.connectors.length).toBeGreaterThan(0);
  });

  it('is mechanical: differs from the committed template ONLY in index.timestamp', () => {
    const template = JSON.parse(loadSampleIndexRaw()) as {
      payload: { index: { timestamp: string } };
    };
    const now = new Date('2026-08-29T12:00:00Z');
    const generated = generateFixtureIndex(now);

    // toISOString() may carry ".000" millis; assert the instant, not the format.
    expect(Date.parse(generated.payload.index.timestamp)).toBe(now.getTime());
    // Swap the timestamp back — the rest must be byte-for-byte the template's shape.
    generated.payload.index.timestamp = template.payload.index.timestamp;
    expect(generated).toEqual(template);
  });

  it('writes a parseable .generated/sample-index.json that also passes the real freshness check', () => {
    const writtenPath = writeGeneratedFixture();
    expect(writtenPath).toBe(GENERATED_FIXTURE_PATH);
    const raw = readFileSync(writtenPath, 'utf-8');
    const result = verifyAndParseIndex(raw, { maxStalenessMs: DEFAULT_MAX_STALENESS_MS });
    expect(result.payload.connectors.length).toBeGreaterThan(0);
  });

  it('the committed template is (intentionally) stale at the real window — the reason the build synthesizes', () => {
    // If this ever stops throwing ERR_INDEX_STALE, someone re-froze the
    // template with a recent timestamp: the default build path does not read
    // it as-is, so it would rot again within 30 days and silently re-introduce
    // the original bug.
    try {
      verifyAndParseIndex(loadSampleIndexRaw(), { maxStalenessMs: DEFAULT_MAX_STALENESS_MS });
      expect.fail('expected the frozen template to be rejected as stale');
    } catch (err) {
      expect(err).toBeInstanceOf(BuildError);
      expect((err as BuildError).code).toBe('ERR_INDEX_STALE');
    }
  });
});
