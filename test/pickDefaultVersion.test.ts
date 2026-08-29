import { describe, expect, it } from 'vitest';
import { pickDefaultVersion } from '../src/lib/pickDefaultVersion';
import { loadSampleIndex } from './fixtures/loadFixture';
import type { Connector } from '../src/lib/schema';

const publisher = {
  expectedOIDCIssuer: 'https://token.actions.githubusercontent.com',
  expectedIdentityPattern:
    '^https://github\\.com/x/y/\\.github/workflows/publish\\.yml@refs/tags/v.*$',
};

function version(v: string, yanked = false) {
  return {
    version: v,
    minConduitVersion: '0.14.0',
    minProtocolVersion: '0.14.0',
    artifacts: [],
    ...(yanked ? { yanked: { reason: 'test' } } : {}),
  };
}

describe('pickDefaultVersion', () => {
  it('picks the newest non-yanked version, re-sorting defensively regardless of input order', () => {
    const c: Connector = {
      name: 'x',
      publisher,
      versions: [version('0.9.0'), version('1.2.0'), version('1.0.0')],
    };
    expect(pickDefaultVersion(c)?.version).toBe('1.2.0');
  });

  it('skips a newer yanked version in favor of the newest non-yanked one', () => {
    const c: Connector = {
      name: 'x',
      publisher,
      versions: [version('1.0.0'), version('1.1.0', true)],
    };
    expect(pickDefaultVersion(c)?.version).toBe('1.0.0');
  });

  it('falls back to showing the newest anyway, transparently, when every version is yanked', () => {
    const c: Connector = {
      name: 'x',
      publisher,
      versions: [version('1.0.0', true), version('1.1.0', true)],
    };
    expect(pickDefaultVersion(c)?.version).toBe('1.1.0');
  });

  it('returns undefined for a connector with zero versions', () => {
    const c: Connector = { name: 'x', publisher, versions: [] };
    expect(pickDefaultVersion(c)).toBeUndefined();
  });

  it('matches expectations against the real sample index (postgres: 0.14.0 yanked, 0.14.2 newest non-yanked)', () => {
    const { payload } = loadSampleIndex();
    const postgres = payload.connectors.find((c) => c.name === 'postgres')!;
    // 0.14.2 (the WS4 S3 no-provenance honesty case) is the newest non-yanked
    // version, so it is the default — default selection is a lifecycle pick,
    // orthogonal to the signature verdict.
    expect(pickDefaultVersion(postgres)?.version).toBe('0.14.2');
  });
});
