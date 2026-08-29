import { beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
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

function runViaCli(statePath: string, outPath: string): () => Buffer {
  return () =>
    verifyIndexViaCli({
      indexURL: fixtureIndex,
      anchorsFile: fixtureAnchors,
      statePath,
      outPath,
      cwd: root,
      env: { ...process.env, REGISTRY_VERIFY_BIN: bin! },
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
          env: { ...process.env, REGISTRY_VERIFY_BIN: bin! },
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
          env: { ...process.env, REGISTRY_VERIFY_BIN: bin! },
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
          env: { ...process.env, REGISTRY_VERIFY_BIN: bin! },
        }),
      'ERR_INDEX_UNREACHABLE'
    );
  });
});
