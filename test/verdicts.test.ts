import { describe, expect, it } from 'vitest';
import {
  installGateFor,
  mergeVerdicts,
  verdictForProcessorVersion,
  verdictForVersion,
  REASON_NO_PROVENANCE,
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
    const { connectors } = mergeVerdicts(report, payload);
    const postgres = connectors.get('postgres')!;
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
    const row = mergeVerdicts(report, payload).connectors.get('postgres')!.get('0.14.0')!;
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
    const lookup = mergeVerdicts(report, payload).connectors;
    const verdict = verdictForVersion(lookup, 'postgres', false, '0.14.1');
    expect(verdict.verdict).toBe('not_attempted');
    expect(verdict.reason).toBe(REASON_NO_VERDICT_IN_REPORT);
  });

  it('without a report at all, every version is not_attempted — never pass', () => {
    const { payload } = loadSampleIndex();
    const verdict = verdictForVersion(undefined, 'postgres', false, '0.14.1');
    expect(verdict.verdict).toBe('not_attempted');
    expect(verdict.reason).toBe(REASON_NO_VERDICT_IN_REPORT);
  });

  it('a revoked publisher overrides even a passing crypto verdict to fail, keeping the crypto checkedAt', () => {
    const { payload } = loadSampleIndex();
    const verdict = verdictForVersion(
      mergeVerdicts(reportFor(payload), payload).connectors,
      'example-vector-sink',
      true,
      '0.3.0'
    );
    // The crypto row is a pass; the overlay is a trust failure, not an
    // abstention — and the badge stays dated.
    expect(verdict.verdict).toBe('fail');
    expect(verdict.reason).toBe(REASON_PUBLISHER_REVOKED);
    expect(verdict.checkedAt).toBe('2026-08-29T12:00:00Z');
  });

  it('a revoked publisher without a crypto row still renders fail, undated', () => {
    const { payload } = loadSampleIndex();
    const verdict = verdictForVersion(undefined, 'example-vector-sink', true, '0.3.0');
    expect(verdict.verdict).toBe('fail');
    expect(verdict.reason).toBe(REASON_PUBLISHER_REVOKED);
    expect(verdict.checkedAt).toBeUndefined();
  });

  it('processor verdicts merge from the report’s processors collection (WS4 S5 + S3)', () => {
    const { payload } = loadSampleIndex();
    const report = reportFor(payload);
    report.processors = [
      {
        name: 'ai.chunk',
        versions: [
          { version: '0.1.0', verdict: 'pass', checkedAt: '2026-08-29T12:00:00Z', artifacts: [] },
        ],
      },
    ];
    const { processors } = mergeVerdicts(report, payload);
    expect(processors.get('ai.chunk')!.get('0.1.0')!.verdict).toBe('pass');
    expect(
      verdictForProcessorVersion(processors, 'ai.embed', false, '0.1.0').verdict
    ).toBe('not_attempted');
    // No processors collection at all → honest not_attempted, never a pass.
    expect(verdictForProcessorVersion(undefined, 'ai.chunk', false, '0.1.0').verdict).toBe(
      'not_attempted'
    );
  });
});

describe('installGateFor — WS4 4.13 install-command gating', () => {
  it('entry-level suppression wins over everything', () => {
    expect(installGateFor({ suppressInstallCommand: true, verdict: 'fail' })).toEqual({
      gate: 'suppress',
    });
  });

  it('a failed verification verdict gates the install command with the reason', () => {
    expect(
      installGateFor({
        suppressInstallCommand: false,
        verdict: 'fail',
        verdictReason: 'signature bundle does not verify',
        version: '0.14.1',
      })
    ).toEqual({ gate: 'fail', version: '0.14.1', reason: 'signature bundle does not verify' });
  });

  it('a no-provenance not_attempted gates the install command (the CLI hard-refuses those)', () => {
    expect(
      installGateFor({
        suppressInstallCommand: false,
        verdict: 'not_attempted',
        verdictReason: REASON_NO_PROVENANCE,
        version: '0.14.2',
      })
    ).toEqual({ gate: 'no-provenance', version: '0.14.2' });
  });

  it('a not_attempted with any OTHER reason keeps the install command (transient failures must not permanently gate)', () => {
    expect(
      installGateFor({
        suppressInstallCommand: false,
        verdict: 'not_attempted',
        verdictReason: 'signature bundle could not be fetched: the bundle host is unreachable',
        version: '0.14.2',
      })
    ).toEqual({ gate: 'none' });
  });

  it('an absent default version never renders a gate', () => {
    expect(installGateFor({ suppressInstallCommand: false })).toEqual({ gate: 'none' });
  });
});
