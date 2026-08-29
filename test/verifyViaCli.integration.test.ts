import { beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyIndexViaCli } from '../src/lib/verifyViaCli';
import { BuildError } from '../src/lib/errors';

/**
 * Integration test: the REAL verifier binary against a REAL locally generated
 * signed fixture — no network, no production keys, no committed frozen bytes.
 *
 * The fixture is generated at test time by the Go suite's
 * TestGenerateSignedFixture (cmd/registry-verify/fixturegen_test.go), which
 * stamps `now` onto the committed template payload and root-signs it with a
 * fresh test key, writing signed-index.json + anchors.json. Because it signs
 * and verifies with the SAME imported index package, there is no JCS
 * canonicalization drift anywhere in this repo's tests — the fixture is
 * produced by the exact code that checks it.
 *
 * The binary comes from REGISTRY_VERIFY_BIN (CI prebuilds it) or is built
 * here with `go build`; the whole describe is skipped if Go is unavailable.
 * The success path needs the fixture to be fresh against the wall clock (the
 * CLI's own 7-day window), which the generator guarantees by stamping now.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = mkdtempSync(path.join(tmpdir(), 'registry-verify-cli-'));

let bin: string | undefined;
let goMissing = false;
let fixtureIndex = '';
let fixtureAnchors = '';
let fixtureTrustRoot = '';
let fixtureArtifacts = '';

beforeAll(() => {
  bin = process.env['REGISTRY_VERIFY_BIN'];
  if (!bin) {
    bin = path.join(tmp, 'registry-verify');
    const build = spawnSync('go', ['build', '-o', bin, './cmd/registry-verify'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 300_000,
    });
    if (build.status !== 0) {
      goMissing = true;
      return;
    }
  }
  fixtureIndex = path.join(tmp, 'signed-index.json');
  fixtureAnchors = path.join(tmp, 'anchors.json');
  fixtureTrustRoot = path.join(tmp, 'trust-root.json');
  fixtureArtifacts = path.join(tmp, 'artifacts.json');
  const gen = spawnSync(
    'go',
    ['test', './cmd/registry-verify', '-run', '^TestGenerateSignedFixture$', '-count=1'],
    {
      cwd: root,
      env: { ...process.env, FIXTURE_OUT_DIR: tmp },
      encoding: 'utf8',
      timeout: 300_000,
    }
  );
  if (gen.status !== 0) {
    throw new Error(
      `could not generate the signed fixture: ${gen.stderr}\n${gen.stdout}\n` +
        `run: FIXTURE_OUT_DIR=<dir> go test ./cmd/registry-verify -run '^TestGenerateSignedFixture$'`
    );
  }
}, 600_000);

// This suite's entire purpose is exercising the OFFLINE test facility (local
// fixture + anchors file) against the real binary — including when CI runs
// it. The GITHUB_ACTIONS guard in verifyViaCli refuses those knobs on
// purpose for the BUILD; strip the flag here so the suite can exercise the
// facility it exists for.
function runViaCli(statePath: string, outPath: string): () => Buffer {
  return () =>
    verifyIndexViaCli({
      indexURL: fixtureIndex,
      anchorsFile: fixtureAnchors,
      // The generated fixture carries REAL sigstore bundles signed by a
      // VirtualSigstore CA; the artifacts pass needs that CA's trust root
      // (--trust-root-file) to verify them offline.
      artifactsOut: fixtureArtifacts,
      trustRootFile: fixtureTrustRoot,
      statePath,
      outPath,
      cwd: root,
      env: { ...process.env, GITHUB_ACTIONS: undefined, REGISTRY_VERIFY_BIN: bin! },
    });
}

function expectCode(fn: () => unknown, code: string): void {
  let caught: BuildError | undefined;
  try {
    fn();
  } catch (err) {
    caught = err as BuildError;
  }
  expect(caught, `expected BuildError ${code}`).toBeInstanceOf(BuildError);
  expect(caught!.code).toBe(code);
}

describe.skipIf(goMissing)('real verifier CLI against a generated signed fixture', () => {
  it('verifies a root-signed local fixture with --require-root: exit-0 verdict, byte-identical raw, ratcheted state', () => {
    const statePath = path.join(tmp, 'state-success.json');
    const outPath = path.join(tmp, 'out-success.json');
    const raw = runViaCli(statePath, outPath)();

    const fixtureBytes = readFileSync(fixtureIndex);
    expect(raw.equals(fixtureBytes)).toBe(true);
    expect(raw.length).toBe(fixtureBytes.length);

    // The committed-state contract: the CLI ratcheted the high-water mark to
    // the fixture's version (42) — the state file the build passes next run.
    const state = JSON.parse(readFileSync(statePath, 'utf-8')) as {
      version: number;
      lastVerifiedContentHash: string;
    };
    expect(state.version).toBe(42);
    expect(state.lastVerifiedContentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('refuses a tampered payload with ERR_INDEX_INTEGRITY and never writes the out file or state', () => {
    const tampered = path.join(tmp, 'tampered.json');
    const parsed = JSON.parse(readFileSync(fixtureIndex, 'utf-8')) as {
      payload: { connectors: { name: string }[] };
    };
    parsed.payload.connectors[0]!.name = 'evil-connector';
    writeFileSync(tampered, JSON.stringify(parsed));

    const statePath = path.join(tmp, 'state-tampered.json');
    const outPath = path.join(tmp, 'out-tampered.json');
    expectCode(
      () =>
        verifyIndexViaCli({
          indexURL: tampered,
          anchorsFile: fixtureAnchors,
          statePath,
          outPath,
          cwd: root,
          env: { ...process.env, GITHUB_ACTIONS: undefined, REGISTRY_VERIFY_BIN: bin! },
        }),
      'ERR_INDEX_INTEGRITY'
    );
    // Fail-closed: no out file, and the state floor was NOT ratcheted by a
    // rejected index (an attacker must never be able to push the trusted
    // floor forward with garbage).
    expect(existsSync(outPath)).toBe(false);
    expect(existsSync(statePath)).toBe(false);
  });

  it('refuses a rollback below a pre-seeded high-water mark with ERR_INDEX_ROLLBACK', () => {
    const statePath = path.join(tmp, 'state-rollback.json');
    writeFileSync(statePath, JSON.stringify({ version: 999, lastVerifiedContentHash: '' }));
    expectCode(runViaCli(statePath, path.join(tmp, 'out-rollback.json')), 'ERR_INDEX_ROLLBACK');
  });

  it('fails closed with ERR_TRUST_ANCHORS_UNAVAILABLE when the anchors file trusts nothing', () => {
    const emptyAnchors = path.join(tmp, 'empty-anchors.json');
    writeFileSync(emptyAnchors, JSON.stringify({ roots: {}, freshness: {} }));
    expectCode(
      () =>
        verifyIndexViaCli({
          indexURL: fixtureIndex,
          anchorsFile: emptyAnchors,
          statePath: path.join(tmp, 'state-noanchors.json'),
          outPath: path.join(tmp, 'out-noanchors.json'),
          cwd: root,
          env: { ...process.env, GITHUB_ACTIONS: undefined, REGISTRY_VERIFY_BIN: bin! },
        }),
      'ERR_TRUST_ANCHORS_UNAVAILABLE'
    );
  });

  it('fails closed with ERR_INDEX_UNREACHABLE for a missing local index path', () => {
    expectCode(
      () =>
        verifyIndexViaCli({
          indexURL: path.join(tmp, 'does-not-exist.json'),
          anchorsFile: fixtureAnchors,
          statePath: path.join(tmp, 'state-missing.json'),
          outPath: path.join(tmp, 'out-missing.json'),
          cwd: root,
          env: { ...process.env, GITHUB_ACTIONS: undefined, REGISTRY_VERIFY_BIN: bin! },
        }),
      'ERR_INDEX_UNREACHABLE'
    );
  });

  it('writes the artifacts report with real crypto verdicts: well-signed versions pass, the provenance-less 0.14.2 is not_attempted("no provenance in index")', () => {
    const statePath = path.join(tmp, 'state-artifacts.json');
    const outPath = path.join(tmp, 'out-artifacts.json');
    runViaCli(statePath, outPath)();

    const report = JSON.parse(readFileSync(fixtureArtifacts, 'utf-8')) as {
      schemaVersion: number;
      generatedAt: string;
      indexVersion: number;
      indexTimestamp: string;
      verifierVersion: string;
      connectors: {
        name: string;
        versions: {
          version: string;
          verdict: string;
          reason?: string;
          checkedAt: string;
          artifacts: unknown[];
        }[];
      }[];
      processors: {
        name: string;
        versions: {
          version: string;
          verdict: string;
          reason?: string;
          checkedAt: string;
          artifacts: unknown[];
        }[];
      }[];
    };
    expect(report.schemaVersion).toBe(1);
    expect(report.indexVersion).toBe(42);
    // The generator stamps `now` onto the payload before signing, so the
    // report must describe the SAME stamped timestamp the signed index
    // carries — the coherence guard's data.
    const fixturePayload = JSON.parse(readFileSync(fixtureIndex, 'utf-8')) as {
      payload: { index: { timestamp: string } };
    };
    expect(report.indexTimestamp).toBe(fixturePayload.payload.index.timestamp);
    expect(report.verifierVersion).toMatch(/^v0\.20\.0-nightly/);
    expect(report.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const verdicts = new Map<string, { verdict: string; reason?: string; checkedAt: string }>();
    for (const c of report.connectors) {
      for (const v of c.versions) {
        verdicts.set(`${c.name}@${v.version}`, v);
        expect(v.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      }
    }
    for (const key of ['postgres@0.14.0', 'postgres@0.14.1', 'example-vector-sink@0.3.0']) {
      expect(verdicts.get(key)!.verdict).toBe('pass');
    }
    const na = verdicts.get('postgres@0.14.2')!;
    expect(na.verdict).toBe('not_attempted');
    expect(na.reason).toBe('no provenance in index');

    // WS4 S5: the processor entries carry the same real-crypto pass verdicts.
    const processorVerdicts = new Map<string, { verdict: string }>();
    for (const p of report.processors) {
      for (const v of p.versions) {
        processorVerdicts.set(`${p.name}@${v.version}`, v);
      }
    }
    for (const key of ['ai.chunk@0.1.0', 'ai.embed@0.1.0']) {
      expect(processorVerdicts.get(key)!.verdict).toBe('pass');
    }
  });

  it('does not fail the build when an artifact bundle is unfetchable — the verdict degrades to not_attempted, the site stays up', () => {
    // A second, self-contained fixture: delete one signature bundle file
    // AFTER generation, so the signed index is intact (its root signature
    // still verifies) but one bundle ref points at a missing file. The
    // artifacts pass must record not_attempted and exit 0 — a bundle-host
    // outage degrades badges, never the site.
    const dir = mkdtempSync(path.join(tmpdir(), 'registry-verify-cli-unfetchable-'));
    const gen = spawnSync(
      'go',
      ['test', './cmd/registry-verify', '-run', '^TestGenerateSignedFixture$', '-count=1'],
      {
        cwd: root,
        env: { ...process.env, FIXTURE_OUT_DIR: dir },
        encoding: 'utf8',
        timeout: 300_000,
      }
    );
    if (gen.status !== 0) {
      throw new Error(`could not generate the unfetchable-bundle fixture: ${gen.stderr}`);
    }
    rmSync(path.join(dir, 'sig-postgres-0.14.0-linux-amd64.json'));

    const statePath = path.join(tmp, 'state-unfetchable.json');
    const outPath = path.join(tmp, 'out-unfetchable.json');
    const artifactsOut = path.join(tmp, 'artifacts-unfetchable.json');
    verifyIndexViaCli({
      indexURL: path.join(dir, 'signed-index.json'),
      anchorsFile: path.join(dir, 'anchors.json'),
      artifactsOut,
      trustRootFile: path.join(dir, 'trust-root.json'),
      statePath,
      outPath,
      cwd: root,
      env: { ...process.env, GITHUB_ACTIONS: undefined, REGISTRY_VERIFY_BIN: bin! },
    });

    const report = JSON.parse(readFileSync(artifactsOut, 'utf-8')) as {
      connectors: {
        name: string;
        versions: { version: string; verdict: string; reason?: string }[];
      }[];
    };
    const postgres = report.connectors.find((c) => c.name === 'postgres')!.versions;
    const v0140 = postgres.find((v) => v.version === '0.14.0')!;
    expect(v0140.verdict).toBe('not_attempted');
    expect(v0140.reason).toContain('could not be fetched');
    // The OTHER artifact of the same version still verified — but the
    // version aggregates fail > not_attempted > pass, so the version is
    // not_attempted, not pass.
    const v0141 = postgres.find((v) => v.version === '0.14.1')!;
    expect(v0141.verdict).toBe('pass');
  });
});
