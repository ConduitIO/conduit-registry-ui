import { describe, expect, it } from 'vitest';
import { buildRenderModel } from '../src/lib/renderModel';
import { BuildError } from '../src/lib/errors';
import { loadSampleIndex } from './fixtures/loadFixture';
import type { IndexPayload } from '../src/lib/schema';

describe('buildRenderModel — reserved-route-segment collision (§9 edge case)', () => {
  it('fails the whole build loudly if a connector name collides with a reserved route segment', () => {
    const { payload } = loadSampleIndex();
    payload.connectors[0]!.name = '404';
    try {
      buildRenderModel(payload);
      expect.fail('expected buildRenderModel to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(BuildError);
      expect((err as BuildError).code).toBe('ERR_RESERVED_ROUTE_COLLISION');
    }
  });

  it('fails on a duplicate connector name (index-CI is supposed to prevent this, but the site refuses too)', () => {
    const { payload } = loadSampleIndex();
    const dup = structuredClone(payload.connectors[0]!);
    payload.connectors.push(dup);
    expect(() => buildRenderModel(payload)).toThrow(BuildError);
  });
});

describe('buildRenderModel — install-command suppression', () => {
  it('suppresses install for a revoked-publisher connector', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);
    const revoked = model.connectors.find((c) => c.name === 'example-vector-sink')!;
    expect(revoked.suppressInstallCommand).toBe(true);
    expect(revoked.effectiveStatus).toBe('revoked');
  });

  it('does not suppress install for an active connector with a partially-yanked version history', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);
    const postgres = model.connectors.find((c) => c.name === 'postgres')!;
    expect(postgres.suppressInstallCommand).toBe(false);
  });

  it('suppresses install when every version of a connector is yanked', () => {
    const payload: IndexPayload = {
      schemaVersion: 1,
      index: { version: 1, timestamp: '2026-07-14T09:00:00Z' },
      connectors: [
        {
          name: 'all-yanked-connector',
          publisher: {
            expectedOIDCIssuer: 'https://token.actions.githubusercontent.com',
            expectedIdentityPattern:
              '^https://github\\.com/x/y/\\.github/workflows/publish\\.yml@refs/tags/v.*$',
          },
          versions: [
            {
              version: '1.0.0',
              minConduitVersion: '0.14.0',
              minProtocolVersion: '0.14.0',
              artifacts: [],
              yanked: { reason: 'bad build' },
            },
          ],
        },
      ],
    };
    const model = buildRenderModel(payload);
    const c = model.connectors[0]!;
    expect(c.effectiveStatus).toBe('yanked');
    expect(c.allVersionsYanked).toBe(true);
    expect(c.suppressInstallCommand).toBe(true);
  });
});

describe('buildRenderModel — compatibility matrix always renders both explicit states', () => {
  it('every OS x arch cell is present (available or not), never blank/omitted', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);
    const postgres = model.connectors.find((c) => c.name === 'postgres')!;
    const v0141 = postgres.versions.find((v) => v.version === '0.14.1')!;
    // schema enum: os in {linux,darwin,windows}, arch in {amd64,arm64} = 6 cells
    expect(v0141.compat).toHaveLength(6);
    // The sample index only ships linux/amd64 + darwin/arm64 for 0.14.1 — every
    // other combination (including windows entirely) must render explicitly
    // "not available", never be missing from the array.
    const windowsCells = v0141.compat.filter((c) => c.os === 'windows');
    expect(windowsCells).toHaveLength(2);
    expect(windowsCells.every((c) => c.available === false)).toBe(true);
    const linuxAmd64 = v0141.compat.find((c) => c.os === 'linux' && c.arch === 'amd64')!;
    expect(linuxAmd64.available).toBe(true);
  });
});

describe('buildRenderModel — search manifest carries only presentation fields', () => {
  it('never includes trust-relevant fields (signature/provenance/publisher)', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);
    const allowedKeys = new Set([
      'description',
      'displayName',
      'effectiveStatus',
      'name',
      'repository',
    ]);
    for (const entry of model.searchManifest) {
      for (const key of Object.keys(entry)) {
        expect(allowedKeys.has(key)).toBe(true);
      }
    }
  });
});

describe('buildRenderModel — per-version verdicts (WS4 S3)', () => {
  it('merges the artifacts report verdicts onto every version, with reason + checkedAt', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, {
      verified: true,
      generatedAt: '2026-08-29T12:00:00Z',
      artifacts: {
        schemaVersion: 1,
        generatedAt: '2026-08-29T12:00:00Z',
        indexVersion: 42,
        indexTimestamp: '2026-07-14T09:00:00Z',
        verifierVersion: 'v0.20.0-nightly',
        connectors: [
          {
            name: 'postgres',
            versions: [
              {
                version: '0.14.0',
                verdict: 'pass',
                checkedAt: '2026-08-29T12:00:00Z',
                artifacts: [],
              },
              {
                version: '0.14.1',
                verdict: 'fail',
                reason: 'signature bundle does not verify against the trust anchors',
                checkedAt: '2026-08-29T12:00:00Z',
                artifacts: [],
              },
              {
                version: '0.14.2',
                verdict: 'not_attempted',
                reason: 'no provenance in index',
                checkedAt: '2026-08-29T12:00:00Z',
                artifacts: [],
              },
            ],
          },
          { name: 'example-vector-sink', versions: [] },
        ],
      },
    });
    const postgres = model.connectors.find((c) => c.name === 'postgres')!;
    expect(postgres.versions.find((v) => v.version === '0.14.0')!.verdict).toBe('pass');
    const failV = postgres.versions.find((v) => v.version === '0.14.1')!;
    expect(failV.verdict).toBe('fail');
    expect(failV.verdictReason).toContain('does not verify');
    expect(failV.verdictCheckedAt).toBe('2026-08-29T12:00:00Z');
    const naV = postgres.versions.find((v) => v.version === '0.14.2')!;
    expect(naV.verdict).toBe('not_attempted');
    expect(naV.verdictReason).toBe('no provenance in index');
  });

  it('without a report, every version is not_attempted with the explicit reason — never pass', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, { verified: true });
    for (const c of model.connectors) {
      for (const v of c.versions) {
        expect(v.verdict).toBe('not_attempted');
        // The revoked publisher's versions carry the revocation overlay
        // reason instead of the missing-report reason — both are explicit,
        // neither is a pass.
        if (c.name === 'example-vector-sink') {
          expect(v.verdictReason).toMatch(/revoked/);
        } else {
          expect(v.verdictReason).toMatch(/no verdict/);
        }
      }
    }
  });

  it('a revoked publisher renders every version fail with the revocation reason, keeping the crypto row’s checkedAt', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, {
      verified: true,
      artifacts: {
        schemaVersion: 1,
        generatedAt: '2026-08-29T12:00:00Z',
        indexVersion: 42,
        indexTimestamp: '2026-07-14T09:00:00Z',
        verifierVersion: 'v0.20.0-nightly',
        connectors: [
          {
            name: 'example-vector-sink',
            versions: [
              {
                version: '0.3.0',
                verdict: 'pass',
                checkedAt: '2026-08-29T12:00:00Z',
                artifacts: [],
              },
            ],
          },
        ],
      },
    });
    const revoked = model.connectors.find((c) => c.name === 'example-vector-sink')!;
    const v = revoked.versions.find((x) => x.version === '0.3.0')!;
    // A crypto-VERIFIED signature under a revoked identity is a trust failure
    // (the reason says so) — the badge is fail, not an abstention, and stays
    // dated with the crypto row's checkedAt.
    expect(v.verdict).toBe('fail');
    expect(v.verdictReason).toMatch(/revoked/);
    expect(v.verdictCheckedAt).toBe('2026-08-29T12:00:00Z');
  });

  it('a revoked publisher without a crypto row still renders fail, undated', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, { verified: true });
    const revoked = model.connectors.find((c) => c.name === 'example-vector-sink')!;
    for (const v of revoked.versions) {
      expect(v.verdict).toBe('fail');
      expect(v.verdictReason).toMatch(/revoked/);
      expect(v.verdictCheckedAt).toBeUndefined();
    }
  });
});

describe('buildRenderModel — index staleness data + verifier version', () => {
  it('computes indexAgeMs from the build clock, and carries the verifier version', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, {
      verified: true,
      generatedAt: '2026-07-21T09:00:00Z',
      artifacts: {
        schemaVersion: 1,
        generatedAt: '2026-07-21T09:00:00Z',
        indexVersion: 42,
        indexTimestamp: '2026-07-14T09:00:00Z',
        verifierVersion: 'v0.20.0-nightly',
        connectors: [],
      },
    });
    expect(model.indexAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(model.verifierVersion).toBe('v0.20.0-nightly');
    expect(model.verified).toBe(true);
  });

  it('never reports a negative index age (clock skew), and omits verifierVersion without a report', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, { generatedAt: '2026-07-01T09:00:00Z' });
    expect(model.indexAgeMs).toBe(0);
    expect(model.verifierVersion).toBeUndefined();
  });
});

describe('buildRenderModel — processors (WS4 S5: rendered with the same verdict honesty as connectors)', () => {
  it('derives every processor with the same fields connectors get (badge, status, install suppression, default version)', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);

    expect(model.processors).toHaveLength(2);
    const chunk = model.processors.find((p) => p.name === 'ai.chunk')!;
    expect(chunk.displayName).toBe('Conduit AI Chunking Processor');
    expect(chunk.description.length).toBeGreaterThan(0);
    expect(chunk.repository).toBe('https://github.com/ConduitIO/conduit-processor-ai');
    expect(chunk.effectiveStatus).toBe('active');
    expect(chunk.allVersionsYanked).toBe(false);
    expect(chunk.suppressInstallCommand).toBe(false);
    expect(chunk.defaultVersion).toBe('0.1.0');

    const v = chunk.versions[0]!;
    expect(v.version).toBe('0.1.0');
    expect(v.minConduitVersion).toBe('0.20.0');
    expect(v.minProtocolVersion).toBe('0.14.0');
    expect(v.deprecated).toBe(false);
    expect(v.isDefault).toBe(true);
  });

  it('processor versions are not_attempted without a verdict row — presence earns no pass', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload);
    const chunk = model.processors.find((p) => p.name === 'ai.chunk')!;
    // The sample fixture's ai.chunk carries artifact.signature + version-level
    // slsaProvenance — exactly the shape S3's honesty floor refuses to
    // presence-pass: no crypto row, no green.
    expect(payload.processors![0]!.versions[0]!.artifact.signature).toBeDefined();
    expect(chunk.versions[0]!.verdict).toBe('not_attempted');
    expect(chunk.versions[0]!.verdictReason).toMatch(/no verdict/);
  });

  it('renders a pass verdict for a processor version with a verified crypto row', () => {
    const { payload } = loadSampleIndex();
    const model = buildRenderModel(payload, {
      verified: true,
      artifacts: {
        schemaVersion: 1,
        generatedAt: '2026-08-29T12:00:00Z',
        indexVersion: 42,
        indexTimestamp: '2026-07-14T09:00:00Z',
        verifierVersion: 'v0.20.0-nightly',
        connectors: [],
        processors: [
          {
            name: 'ai.chunk',
            versions: [
              { version: '0.1.0', verdict: 'pass', checkedAt: '2026-08-29T12:00:00Z', artifacts: [] },
            ],
          },
        ],
      },
    });
    const chunk = model.processors.find((p) => p.name === 'ai.chunk')!;
    expect(chunk.versions[0]!.verdict).toBe('pass');
    expect(chunk.versions[0]!.verdictCheckedAt).toBe('2026-08-29T12:00:00Z');
  });

  it('suppresses install and flags the status when every processor version is yanked', () => {
    const { payload } = loadSampleIndex();
    const processor = payload.processors![0]!;
    processor.versions = [
      { ...processor.versions[0]!, version: '1.0.0', yanked: { reason: 'bad build' } },
      { ...processor.versions[0]!, version: '0.9.0', yanked: { reason: 'worse build' } },
    ];
    const model = buildRenderModel(payload);
    const rendered = model.processors.find((p) => p.name === processor.name)!;
    expect(rendered.effectiveStatus).toBe('yanked');
    expect(rendered.allVersionsYanked).toBe(true);
    expect(rendered.suppressInstallCommand).toBe(true);
  });

  it('suppresses install for a revoked processor publisher (revoked overrides signed versions)', () => {
    const { payload } = loadSampleIndex();
    payload.processors![0]!.publisher.revoked = { reason: 'compromised identity' };
    const model = buildRenderModel(payload);
    const rendered = model.processors.find((p) => p.name === 'ai.chunk')!;
    expect(rendered.effectiveStatus).toBe('revoked');
    expect(rendered.suppressInstallCommand).toBe(true);
    expect(rendered.revoked?.reason).toBe('compromised identity');
  });

  it('fails the whole build loudly if a processor name collides with a reserved route segment', () => {
    const { payload } = loadSampleIndex();
    payload.processors![0]!.name = '404';
    try {
      buildRenderModel(payload);
      expect.fail('expected buildRenderModel to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(BuildError);
      expect((err as BuildError).code).toBe('ERR_RESERVED_ROUTE_COLLISION');
    }
  });

  it('fails on a duplicate processor name, same as connectors', () => {
    const { payload } = loadSampleIndex();
    const dup = structuredClone(payload.processors![0]!);
    payload.processors!.push(dup);
    expect(() => buildRenderModel(payload)).toThrow(BuildError);
  });

  it('renders an empty processor list for an index without a processors key (optional in schemaVersion 1)', () => {
    const { payload } = loadSampleIndex();
    delete (payload as { processors?: unknown }).processors;
    const model = buildRenderModel(payload);
    expect(model.processors).toEqual([]);
  });
});
