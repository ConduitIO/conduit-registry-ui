/**
 * The build's interface to the Go verifier CLI (cmd/registry-verify, WS4 S2
 * PR-1). Import, don't reimplement: this module never parses or checks the
 * index itself — it runs the CLI, which imports the conduit CLI's own
 * verifier (pkg/registry/index.Verify) and compiled-in trust anchors
 * (cmd/conduit/root/connectors.DefaultTrustAnchors), and treats exit 0 with
 * --require-root as the ONLY verification verdict. This site can never
 * accept an index the conduit CLI would refuse, because the code that
 * decides is the conduit CLI's code.
 *
 * The CLI is the successor to src/lib/verifyIndex.ts, which was deleted in
 * S2 PR-2: its structural-only stub made no trust claim, and its
 * `verified: false` was a standing TODO marker. The CLI performs the real
 * checks the stub could not — JCS-canonicalized ed25519 root-signature
 * verification, rollback against the committed high-water state, and the
 * 7-day staleness window (index.DefaultMaxStaleness) — and fails the build
 * closed on any of them.
 *
 * # Verdict semantics
 *
 * Exit 0 + --require-root means the index's ROOT signature verified against
 * the compiled-in anchors, the version is not below the committed state
 * floor, and the timestamp is inside the CLI's own 7-day window. The build
 * passes that verdict into the render model as `verified: true`. A
 * freshness-only acceptance (no root signature) is refused outright by
 * --require-root before it can touch the state floor — see the ratchet-wedge
 * note in cmd/registry-verify's package doc.
 *
 * # Local-file mode
 *
 * The CLI's --index accepts a local path (index.FetchFile) as well as a
 * URL, so tests and offline builds can point it at a committed or generated
 * fixture without network access. A local path is no trust change: whoever
 * controls the build's arguments already controls the build.
 *
 * # --anchors-file
 *
 * The CLI's --anchors-file replaces the compiled-in anchors with a
 * TrustAnchors JSON file for test/offline runs against fixtures signed by
 * test keys. Production CI never sets it (see REGISTRY_VERIFY_ANCHORS_FILE
 * in scripts/build-site.ts).
 */
import { readFileSync } from 'node:fs';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { BuildError, type BuildErrorCode } from './errors';

export interface VerifyCliOptions {
  /** --index: URL or local path of the signed index. Omit to use the CLI's
   * compiled-in default (registry.DefaultIndexURL — the live index). */
  indexURL?: string;
  /** --anchors-file: TrustAnchors JSON ({roots, freshness} maps of keyId ->
   * base64 ed25519 public-key bytes). Test/offline runs only; see the
   * module doc. */
  anchorsFile?: string;
  /** --state: committed high-water state file the CLI loads, checks rollback
   * against, and ratchets after a successful verify. */
  statePath: string;
  /** --out: where the CLI writes the verified RAW index bytes — the exact
   * bytes the build copies into dist/. */
  outPath: string;
  /** Working directory for the CLI process (the repo root, so `go run
   * ./cmd/registry-verify` resolves the module). */
  cwd: string;
  env?: NodeJS.ProcessEnv;
  /** Injectable spawn for unit tests; defaults to spawnSync. */
  spawn?: (
    cmd: string,
    args: string[],
    opts: { cwd: string; env: NodeJS.ProcessEnv; encoding: 'utf8'; timeout: number }
  ) => SpawnSyncReturns<string>;
}

/** The verifier's argv prefix. REGISTRY_VERIFY_BIN names a prebuilt binary
 * (CI builds one so the workflow never compiles during the build step);
 * without it, `go run ./cmd/registry-verify` builds from this repo's module
 * (requires Go, used for local dev). */
export function resolveVerifierCmd(env: NodeJS.ProcessEnv = process.env): {
  cmd: string;
  args: string[];
} {
  const bin = env['REGISTRY_VERIFY_BIN'];
  if (bin) return { cmd: bin, args: [] };
  return { cmd: 'go', args: ['run', './cmd/registry-verify'] };
}

/**
 * Runs the CLI against the index and returns the verified RAW bytes, or
 * throws BuildError carrying the CLI's own stable error code (see
 * cmd/registry-verify's package doc for the code list) when verification or
 * the pipeline itself fails. A non-zero exit never produces a return value:
 * an unverified index never reaches the build.
 */
export function verifyIndexViaCli(opts: VerifyCliOptions): Buffer {
  const { cmd, args: prefixArgs } = resolveVerifierCmd(opts.env ?? process.env);
  const args = [
    ...prefixArgs,
    '--state',
    opts.statePath,
    '--out',
    opts.outPath,
    // The site build's trust core: a freshness-only acceptance is refused
    // outright so no freshness-signed index can ratchet the committed state
    // floor (the ratchet wedge — see cmd/registry-verify's package doc).
    '--require-root',
    '--timeout',
    '30s',
  ];
  if (opts.indexURL) args.push('--index', opts.indexURL);
  if (opts.anchorsFile) args.push('--anchors-file', opts.anchorsFile);

  const spawn = opts.spawn ?? ((cmd, args, opts) => spawnSync(cmd, args, opts));
  const result = spawn(cmd, args, {
    cwd: opts.cwd,
    env: opts.env ?? process.env,
    encoding: 'utf8',
    // Belt over the CLI's own 30s fetch timeout: a hung CLI must not hang
    // the build forever.
    timeout: 120_000,
  });

  if (result.error) {
    throw new BuildError(
      'ERR_VERIFY',
      `could not run the verifier CLI (${cmd}): ${result.error.message} — is Go installed, ` +
        `or is REGISTRY_VERIFY_BIN set to a built binary?`
    );
  }
  if (result.status !== 0) {
    const stderr = (result.stderr ?? '').trim();
    // The CLI prints its code as `registry-verify: ERR_*: message`; map it
    // onto BuildError so the whole build speaks one error-code language.
    // The CLI is the authority on its own code surface; the extracted code
    // (or the ERR_VERIFY fallback) may be any of them.
    const code = (stderr.match(/\b(ERR_[A-Z][A-Z_]*)\b/)?.[1] ?? 'ERR_VERIFY') as BuildErrorCode;
    throw new BuildError(code, stderr || `verifier CLI exited with status ${result.status}`);
  }

  try {
    return readFileSync(opts.outPath);
  } catch (err) {
    throw new BuildError(
      'ERR_VERIFY',
      `verifier CLI exited 0 but wrote no verified index at ${opts.outPath}: ` +
        `${(err as Error).message}`
    );
  }
}
