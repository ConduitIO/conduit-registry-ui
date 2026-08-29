import { describe, expect, it } from 'vitest';
import {
  deriveProcessorVerified,
  deriveVerified,
  hasProcessorProvenancePresent,
  hasProcessorSignaturePresent,
  hasSignaturePresent,
  hasProvenancePresent,
} from '../src/lib/deriveVerified';
import { VERIFIED_FIXTURE_CASES } from './fixtures/verifiedFixtures';
import { loadSampleIndex } from './fixtures/loadFixture';
import type { ConnectorVersion, Processor, ProcessorVersion } from '../src/lib/schema';

describe('deriveVerified — the shared fixture set (step6-web-ui.md §4/§10)', () => {
  for (const c of VERIFIED_FIXTURE_CASES) {
    it(c.name, () => {
      expect(deriveVerified(c.version, c.connector)).toBe(c.expectedVerified);
    });
  }
});

describe('deriveVerified — defensive behavior against malformed (off-schema) data', () => {
  it('treats a version with an artifact missing its signature as unverified, not as a crash', () => {
    const malformed = {
      version: '1.0.0',
      minConduitVersion: '0.14.0',
      minProtocolVersion: '0.14.0',
      artifacts: [
        {
          os: 'linux',
          arch: 'amd64',
          kind: 'standalone',
          url: 'x',
          sha256: 'a'.repeat(64),
          size: 1,
        },
      ],
    } as unknown as ConnectorVersion;
    expect(hasSignaturePresent(malformed)).toBe(false);
  });

  it('treats a version with zero artifacts as unsigned/unverified, not as vacuously true', () => {
    const noArtifacts = {
      version: '1.0.0',
      minConduitVersion: '0.14.0',
      minProtocolVersion: '0.14.0',
      artifacts: [],
    } as unknown as ConnectorVersion;
    expect(hasSignaturePresent(noArtifacts)).toBe(false);
    expect(hasProvenancePresent(noArtifacts)).toBe(false);
  });
});

describe('deriveVerified — against the real frozen sample index', () => {
  it('postgres 0.14.1 (signed, provenance, not yanked, publisher not revoked) is verified', () => {
    const { payload } = loadSampleIndex();
    const postgres = payload.connectors.find((c) => c.name === 'postgres')!;
    const v0141 = postgres.versions.find((v) => v.version === '0.14.1')!;
    expect(deriveVerified(v0141, postgres)).toBe(true);
  });

  it('postgres 0.14.0 (yanked, even though signed+provenance) is NOT verified', () => {
    const { payload } = loadSampleIndex();
    const postgres = payload.connectors.find((c) => c.name === 'postgres')!;
    const v0140 = postgres.versions.find((v) => v.version === '0.14.0')!;
    expect(v0140.yanked).toBeDefined();
    expect(deriveVerified(v0140, postgres)).toBe(false);
  });

  it('example-vector-sink 0.3.0 (individually signed, but publisher revoked) is NOT verified', () => {
    const { payload } = loadSampleIndex();
    const revokedConnector = payload.connectors.find((c) => c.name === 'example-vector-sink')!;
    expect(revokedConnector.publisher.revoked).toBeDefined();
    const v030 = revokedConnector.versions.find((v) => v.version === '0.3.0')!;
    // This version has its own valid signature+provenance references — verifies
    // the "revoked overrides even an individually well-signed version" rule
    // against real fixture data, not just a synthetic one.
    expect(hasSignaturePresent(v030)).toBe(true);
    expect(hasProvenancePresent(v030)).toBe(true);
    expect(deriveVerified(v030, revokedConnector)).toBe(false);
  });
});

describe('deriveProcessorVerified — processors render with the same two-layer trust rule (WS4 amended AC 4.9)', () => {
  function processorVersion(overrides: Partial<ProcessorVersion> = {}): ProcessorVersion {
    return {
      version: '0.1.0',
      minConduitVersion: '0.20.0',
      minProtocolVersion: '0.14.0',
      artifact: {
        os: 'wasip1',
        arch: 'wasm',
        kind: 'wasm-processor',
        url: 'https://example.test/processor.wasm.tar.gz',
        sha256: 'a'.repeat(64),
        size: 1,
        signature: { bundleURL: 'https://example.test/processor.wasm.sig' },
      },
      slsaProvenance: {
        bundleURL: 'https://example.test/processor.intoto.jsonl',
        predicateType: 'https://slsa.dev/provenance/v0.2',
      },
      ...overrides,
    };
  }

  const publisher = {
    expectedOIDCIssuer: 'https://token.actions.githubusercontent.com',
    expectedIdentityPattern:
      '^https://github\\.com/x/y/\\.github/workflows/publish\\.yml@refs/tags/v.*$',
  };

  it('verified: signature reference + provenance reference present, not yanked, publisher not revoked', () => {
    const processor: Processor = { name: 'ai.chunk', publisher, versions: [processorVersion()] };
    const version = processor.versions[0]!;
    expect(hasProcessorSignaturePresent(version)).toBe(true);
    expect(hasProcessorProvenancePresent(version)).toBe(true);
    expect(deriveProcessorVerified(version, processor)).toBe(true);
  });

  it('artifact-level provenance alone (no version-level) still verifies — the schema allows either shape', () => {
    const version = processorVersion();
    delete version.slsaProvenance;
    version.artifact.slsaProvenance = {
      bundleURL: 'https://example.test/processor.intoto.jsonl',
      predicateType: 'https://slsa.dev/provenance/v0.2',
    };
    expect(hasProcessorProvenancePresent(version)).toBe(true);
  });

  it('NOT verified when the single artifact lacks a signature reference — never verified-by-omission', () => {
    const version = processorVersion();
    (version.artifact as { signature?: unknown }).signature = undefined;
    expect(hasProcessorSignaturePresent(version)).toBe(false);
    expect(
      deriveProcessorVerified(version, {
        name: 'ai.chunk',
        publisher,
        versions: [version],
      })
    ).toBe(false);
  });

  it('NOT verified when provenance is absent entirely', () => {
    const version = processorVersion();
    delete version.slsaProvenance;
    expect(hasProcessorProvenancePresent(version)).toBe(false);
  });

  it('NOT verified when yanked, even with signature+provenance present (same rule as connectors)', () => {
    const version = processorVersion({ yanked: { reason: 'bad build' } });
    expect(
      deriveProcessorVerified(version, { name: 'ai.chunk', publisher, versions: [version] })
    ).toBe(false);
  });

  it('NOT verified when the publisher is revoked — revoked overrides even a well-signed version', () => {
    const version = processorVersion();
    const revoked: Processor = {
      name: 'ai.chunk',
      publisher: { ...publisher, revoked: { reason: 'compromised' } },
      versions: [version],
    };
    expect(deriveProcessorVerified(version, revoked)).toBe(false);
  });

  it('defensively treats a missing artifact as unverified, not as a crash', () => {
    const malformed = {
      version: '0.1.0',
      minConduitVersion: '0.20.0',
      minProtocolVersion: '0.14.0',
    } as unknown as ProcessorVersion;
    expect(hasProcessorSignaturePresent(malformed)).toBe(false);
    expect(hasProcessorProvenancePresent(malformed)).toBe(false);
  });

  it('against the real frozen sample index: ai.chunk 0.1.0 mirrors the live shape and is verified', () => {
    const { payload } = loadSampleIndex();
    const chunk = payload.processors!.find((p) => p.name === 'ai.chunk')!;
    const v010 = chunk.versions.find((v) => v.version === '0.1.0')!;
    expect(v010.artifact.os).toBe('wasip1');
    expect(v010.artifact.arch).toBe('wasm');
    expect(v010.artifact.kind).toBe('wasm-processor');
    expect(deriveProcessorVerified(v010, chunk)).toBe(true);
  });
});
