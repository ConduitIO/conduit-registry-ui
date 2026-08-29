import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  verifyIndexViaCli,
  resolveVerifierCmd,
  type VerifyCliOptions,
} from '../src/lib/verifyViaCli';
import { buildRenderModel } from '../src/lib/renderModel';
import { BuildError } from '../src/lib/errors';
import { loadSampleIndex } from './fixtures/loadFixture';

// The fake spawn writes the --out file, so the state/out paths the tests
// pass must be real writable temp paths.
const tmp = mkdtempSync(path.join(tmpdir(), 'build-pipeline-'));
const tmpState = path.join(tmp, 'state.json');
const tmpOut = path.join(tmp, 'index.json');

/**
 * Unit tests for the build's verifier interface (src/lib/verifyViaCli.ts) —
 * the same call scripts/build-site.ts makes, with a FAKE spawn so no Go or
 * network is needed here. The orchestration contract under test:
 *
 *   - the CLI is always invoked with --require-root, --state, --out, and the
 *     30s timeout (the build's trust core; a freshness-only acceptance would
 *     ratchet the state floor — see cmd/registry-verify's package doc);
 *   - --index / --anchors-file are passed exactly when configured;
 *   - exit 0 + a written out file is the whole verdict (bytes returned
 *     untouched, no re-parse, no re-check);
 *   - any non-zero exit throws BuildError carrying the CLI's own stable
 *     ERR_* code, and no bytes are returned.
 *
 * The REAL binary against a REAL locally-generated signed fixture is
 * exercised in test/verifyViaCli.integration.test.ts; the Go suite
 * (cmd/registry-verify) covers the crypto itself.
 */

const FAKE_RAW = Buffer.from('{"payload":{"index":{"version":42}}}');
const CWD = '/repo';

/** A fake spawn that records the invocation and behaves like the CLI:
 * exit 0 + write --out with the raw fixture bytes. */
function successSpawn(recorder: { args: string[] }) {
  return (_cmd: string, args: string[]) => {
    recorder.args = args;
    const outIdx = args.indexOf('--out');
    if (outIdx === -1) throw new Error('fake spawn: no --out flag');
    writeFileSync(args[outIdx + 1]!, FAKE_RAW);
    return { status: 0, stderr: '', stdout: '' } as never;
  };
}

function failingSpawn(stderr: string) {
  return () => ({ status: 1, stderr, stdout: '' }) as never;
}

describe('verifyViaCli — invocation contract', () => {
  it('always passes --require-root, --state, --out and a 30s timeout', () => {
    const recorder: { args: string[] } = { args: [] };
    const raw = verifyIndexViaCli({
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      spawn: successSpawn(recorder),
    });

    expect(raw.equals(FAKE_RAW)).toBe(true);
    expect(recorder.args).toContain('--require-root');
    expect(recorder.args).toContain('--state');
    expect(recorder.args).toContain(tmpState);
    expect(recorder.args).toContain('--out');
    expect(recorder.args).toContain(tmpOut);
    expect(recorder.args).toContain('--timeout');
    expect(recorder.args).toContain('30s');
  });

  it('passes --index and --anchors-file only when configured', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      indexURL: 'https://example.test/index.json',
      anchorsFile: '/tmp/anchors.json',
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      // The guard test below covers the CI refusal; here the guard must not
      // fire so the arg-forwarding contract is what's under test.
      env: { GITHUB_ACTIONS: undefined },
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).toContain('--index');
    expect(recorder.args).toContain('https://example.test/index.json');
    expect(recorder.args).toContain('--anchors-file');
    expect(recorder.args).toContain('/tmp/anchors.json');
  });

  it('omits --index when unset — the CLI uses its compiled-in live default', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).not.toContain('--index');
  });

  it('passes --artifacts always when configured, and --trust-root-file only when configured', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      artifactsOut: '/tmp/artifacts.json',
      trustRootFile: '/tmp/trust-root.json',
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      env: { GITHUB_ACTIONS: undefined },
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).toContain('--artifacts');
    expect(recorder.args).toContain('/tmp/artifacts.json');
    expect(recorder.args).toContain('--trust-root-file');
    expect(recorder.args).toContain('/tmp/trust-root.json');
  });

  it('omits --artifacts and --trust-root-file when not configured', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).not.toContain('--artifacts');
    expect(recorder.args).not.toContain('--trust-root-file');
  });

  it('resolves REGISTRY_VERIFY_BIN to a direct binary, otherwise go run', () => {
    expect(resolveVerifierCmd({ REGISTRY_VERIFY_BIN: '/tmp/registry-verify' })).toEqual({
      cmd: '/tmp/registry-verify',
      args: [],
    });
    expect(resolveVerifierCmd({})).toEqual({ cmd: 'go', args: ['run', './cmd/registry-verify'] });
  });
});

describe('verifyViaCli — fail-closed contract', () => {
  it('maps the CLI error code from stderr onto BuildError — no bytes returned', () => {
    const stderr =
      'registry-verify: ERR_INDEX_STALE: index.timestamp (2026-07-14T09:00:00Z) is 46 days old, ' +
      'exceeding the max staleness of 7 days';
    let caught: BuildError | undefined;
    try {
      verifyIndexViaCli({
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
        spawn: failingSpawn(stderr),
      });
    } catch (err) {
      caught = err as BuildError;
    }
    expect(caught).toBeInstanceOf(BuildError);
    expect(caught!.code).toBe('ERR_INDEX_STALE');
    expect(caught!.message).toContain('7 days');
  });

  it('makes a stale index actionable at the failure point: re-sign, do not re-run CI', () => {
    const stderr = 'registry-verify: ERR_INDEX_STALE: index.timestamp (...) exceeds max staleness';
    let caught: BuildError | undefined;
    try {
      verifyIndexViaCli({
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
        spawn: failingSpawn(stderr),
      });
    } catch (err) {
      caught = err as BuildError;
    }
    expect(caught!.code).toBe('ERR_INDEX_STALE');
    expect(caught!.message).toContain('Recovery:');
    expect(caught!.message).toContain('Re-sign/publish a fresh index');
    expect(caught!.message).toContain('Do NOT re-run CI');
  });

  it('refuses the trust-bypass knobs in a GitHub Actions build (ERR_BUILD_CONFIG)', () => {
    const cases: VerifyCliOptions[] = [
      {
        indexURL: 'https://example.test/index.json',
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
      },
      { anchorsFile: '/tmp/anchors.json', statePath: tmpState, outPath: tmpOut, cwd: CWD },
      {
        indexURL: 'https://example.test/index.json',
        anchorsFile: '/tmp/anchors.json',
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
      },
      {
        trustRootFile: '/tmp/trust-root.json',
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
      },
      {
        indexURL: 'https://example.test/index.json',
        trustRootFile: '/tmp/trust-root.json',
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
      },
      // A file path is still a trust-bypass even though it is "local" — only
      // the canonical production host may be named in CI.
      { indexURL: '/tmp/index.json', statePath: tmpState, outPath: tmpOut, cwd: CWD },
    ];
    for (const opts of cases) {
      let caught: BuildError | undefined;
      try {
        verifyIndexViaCli({
          ...opts,
          env: { GITHUB_ACTIONS: 'true' },
          spawn: () => {
            throw new Error('CLI must not be spawned when CI refuses the knobs');
          },
        });
      } catch (err) {
        caught = err as BuildError;
      }
      expect(caught, `case: ${JSON.stringify(opts)}`).toBeInstanceOf(BuildError);
      expect(caught!.code, `case: ${JSON.stringify(opts)}`).toBe('ERR_BUILD_CONFIG');
      expect(caught!.message, `case: ${JSON.stringify(opts)}`).toContain('CI refuses');
    }
  });

  it('allows the canonical index URL in a GitHub Actions build (S6 deploy)', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      indexURL: 'https://index.conduitdata.io/index.json',
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      env: { GITHUB_ACTIONS: 'true' },
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).toContain('--index');
    expect(recorder.args).toContain('https://index.conduitdata.io/index.json');
  });

  it('still allows the trust-bypass knobs outside CI (local/offline builds)', () => {
    const recorder: { args: string[] } = { args: [] };
    verifyIndexViaCli({
      indexURL: 'https://example.test/index.json',
      statePath: tmpState,
      outPath: tmpOut,
      cwd: CWD,
      env: { GITHUB_ACTIONS: undefined },
      spawn: successSpawn(recorder),
    });
    expect(recorder.args).toContain('--index');
    expect(recorder.args).toContain('https://example.test/index.json');
  });

  it('falls back to ERR_VERIFY when the CLI exits non-zero without a code', () => {
    let caught: BuildError | undefined;
    try {
      verifyIndexViaCli({
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
        spawn: failingSpawn('registry-verify: boom'),
      });
    } catch (err) {
      caught = err as BuildError;
    }
    expect(caught!.code).toBe('ERR_VERIFY');
  });

  it('fails with ERR_VERIFY when the CLI cannot even be spawned', () => {
    let caught: BuildError | undefined;
    try {
      verifyIndexViaCli({
        statePath: tmpState,
        outPath: tmpOut,
        cwd: CWD,
        spawn: () => ({ error: new Error('ENOENT') }) as never,
      });
    } catch (err) {
      caught = err as BuildError;
    }
    expect(caught!.code).toBe('ERR_VERIFY');
  });
});

describe('pipeline — verified payload through the render model', () => {
  it('passes the CLI verdict (verified: true) into the model with the fixture data', () => {
    const signed = loadSampleIndex();
    const model = buildRenderModel(signed.payload, { verified: true });

    expect(model.verified).toBe(true);
    expect(model.connectors).toHaveLength(2);
    const postgres = model.connectors.find((c) => c.name === 'postgres');
    expect(postgres).toBeDefined();
    expect(postgres!.displayName).toBe('PostgreSQL');

    // S5: the same verified payload carries the two live-shaped processors
    // (WS4 amended AC 4.9 — rendered, not stated-connectors-only).
    expect(model.processors).toHaveLength(2);
    const chunk = model.processors.find((p) => p.name === 'ai.chunk');
    expect(chunk).toBeDefined();
    expect(chunk!.defaultVersion).toBe('0.1.0');
  });

  it('fails the build when the artifacts report describes a different index run', () => {
    const signed = loadSampleIndex();
    let caught: BuildError | undefined;
    try {
      buildRenderModel(signed.payload, {
        verified: true,
        artifacts: {
          schemaVersion: 1,
          generatedAt: '2026-08-29T12:00:00Z',
          indexVersion: 41, // the payload's index.version is 42
          indexTimestamp: signed.payload.index.timestamp,
          verifierVersion: 'v0.20.0-nightly',
          connectors: [],
        },
      });
    } catch (err) {
      caught = err as BuildError;
    }
    expect(caught).toBeInstanceOf(BuildError);
    expect(caught!.code).toBe('ERR_ARTIFACTS_REPORT_MISMATCH');
  });
});
