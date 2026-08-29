import { describe, expect, it } from 'vitest';
import {
  mergeVerdicts,
  verdictForVersion,
  REASON_NO_VERDICT_IN_REPORT,
  REASON_PUBLISHER_REVOKED,
  type ArtifactReport,
  type VersionVerdict,
} from '../src/lib/verdicts';
import { BuildError } from '../src/lib/errors';
import { loadSampleIndex } from './fixtures/loadFixture';
import type { IndexPayload } from '../src/lib/schema';

/**
 * The verdict merge contract (WS4 S3): the Go verifier CLI's artifacts
 * report (cmd/registry-verify --artifacts) is merged into the render model
 * with three-state semantics — pass / fail(reason) / not_attempted(reason) —
 * never a presence-pass, and coherence-guarded so a report describing a
 * different index run is refused outright.
 *
 * The full crypto matrix lives in the Go suite (cmd/registry-verify
 * artifacts_test.go, real sigstore fixtures); here we test the merge and the
 * overlay on top of the real frozen sample index.
 */

function reportFor(payload: IndexPayload): ArtifactReport {
  return {
    schemaVersion: 1,
    generatedAt: '2026-08-29T12:00:00Z',
    indexVersion: payload.index.version,
    indexTimestamp: payload.index.timestamp,
    verifierVersion: 'v0.20.0-nightly.20260730.0.20260730153200-b55f9c42693c',
    connectors: payload.connectors.map((c) => ({
      name: c.name,
      versions: c.versions.map((v): VersionVerdict => {
        const reason = v.version === '0.14.2' ? 'no provenance in index' : undefined;
        return {
          version: v.version,
          verdict: reason ? 'not_attempted' : 'pass',
          ...(reason ? { reason } : {}),
          checkedAt: '2026-08-29T12:00:00Z',
          artifacts: v.artifacts.map((a) => ({
            os: a.os,
            arch: a.arch,
            kind: a.kind,
            verdict: (reason ? 'not_attempted' : 'pass') as 'pass' | 'not_attempted',
            ...(reason ? { reason } : {}),
          })),
        };
      }),
    })),
  };
}

describe('verdicts — merge contract against the frozen sample index', () => {
  it('merges the report onto the payload and looks up per-version verdicts', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    const lookup = mergeVerdicts(report, payload);
    const postgres = lookup.get('postgres')!;
    expect(postgres.get('0.14.1')!.verdict).toBe('pass');
    expect(postgres.get('0.14.2')!.verdict).toBe('not_attempted');
    expect(postgres.get('0.14.2')!.reason).toBe('no provenance in index');
    expect(postgres.get('0.14.1')!.checkedAt).toBe('2026-08-29T12:00:00Z');
  });

  it('passes through fail verdicts and their reasons verbatim', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    report.connectors[0]!.versions[0]!.verdict = 'fail';
    report.connectors[0]!.versions[0]!.reason =
      'signature is valid but does not match the identity pinned for this connector';
    const row = mergeVerdicts(report, payload).get('postgres')!.get('0.14.0')!;
    expect(row.verdict).toBe('fail');
    expect(row.reason).toContain('does not match the identity');
  });

  it('refuses a report whose index identity does not match the payload (ERR_ARTIFACTS_REPORT_MISMATCH)', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    report.indexVersion = 41;
    expect(() => mergeVerdicts(report, payload)).toThrowError(BuildError);
    try {
      mergeVerdicts(report, payload);
      expect.fail('expected mergeVerdicts to throw');
    } catch (err) {
      expect((err as BuildError).code).toBe('ERR_ARTIFACTS_REPORT_MISMATCH');
    }
  });

  it('refuses an unknown report schemaVersion', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    report.schemaVersion = 2;
    try {
      mergeVerdicts(report, payload);
      expect.fail('expected mergeVerdicts to throw');
    } catch (err) {
      expect((err as BuildError).code).toBe('ERR_ARTIFACTS_REPORT_MISMATCH');
    }
  });

  it('never presence-passes: a version missing from the report is not_attempted with an explicit reason', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    report.connectors[0]!.versions = report.connectors[0]!.versions.filter(
      (v) => v.version !== '0.14.1'
    );
    const verdict = verdictForVersion(report, payload, 'postgres', false, '0.14.1');
    expect(verdict.verdict).toBe('not_attempted');
    expect(verdict.reason).toBe(REASON_NO_VERDICT_IN_REPORT);
  });

  it('without a report at all, every version is not_attempted — never pass', () => {
    const { payload } = loadSampleIndex();
    const verdict = verdictForVersion(undefined, payload, 'postgres', false, '0.14.1');
    expect(verdict.verdict).toBe('not_attempted');
    expect(verdict.reason).toBe(REASON_NO_VERDICT_IN_REPORT);
  });

  it('a revoked publisher overrides even a passing crypto verdict to not_attempted', () => {
    const { payload } = loadSampleIndex();
    const verdict = verdictForVersion(
      reportFor(payload),
      payload,
      'example-vector-sink',
      true,
      '0.3.0'
    );
    expect(verdict.verdict).toBe('not_attempted');
    expect(verdict.reason).toBe(REASON_PUBLISHER_REVOKED);
  });
});
