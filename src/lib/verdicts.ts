import type { IndexPayload } from './schema';
import { BuildError } from './errors';

/**
 * The per-version artifact verdict (WS4 S3): the Go verifier CLI
 * (cmd/registry-verify --artifacts) computes a three-state verdict per
 * version at BUILD time — pass / fail(reason) / not_attempted(reason) — by
 * fetching ONLY the small signature + SLSA provenance bundles the index
 * references (never the artifact binaries, bounded at the CLI's own 1 MiB
 * cap) and verifying them against the trust anchors, the connector's pinned
 * identity, and the index-declared sha256. The CLI writes the report JSON;
 * this module is the TypeScript side of that contract — the typed shape,
 * the merge into the render model, and the one overlay the site applies.
 *
 * Verdict semantics (see cmd/registry-verify/artifacts.go's package doc for
 * the authoritative statement):
 *
 *   - pass: EVERY artifact's signature bundle verifies against the trust
 *     anchors AND the connector's pinned identity, AND the applicable SLSA
 *     provenance bundle (artifact-level, else version-level) verifies AND
 *     its subject digest binds to the index-declared sha256 with the
 *     expected builder.
 *   - fail: a bundle verified-failed — tampered bytes, a valid signature by
 *     the wrong identity, or provenance that does not bind.
 *   - not_attempted: the verdict could not be reached — no provenance
 *     reference in the index, a bundle that could not be fetched, or a
 *     malformed index declaration. A missing reference is NEVER a pass:
 *     no bundle, no green.
 *
 * Version aggregation is fail > not_attempted > pass, carrying the first
 * failure's reason.
 *
 * Processors (WS4 S5) are verified by the SAME artifacts pass with the same
 * trust code — a processor version's single wasip1/wasm artifact goes
 * through the identical bundle verification and binding checks — and render
 * the identical three-state badge. There is no two-tier honesty: a presence
 * pass lives nowhere on this site.
 *
 * # The revocation overlay
 *
 * One overlay is applied at merge time, deliberately: when the publisher is
 * REVOKED, every version's badge renders **fail** with a revocation reason,
 * regardless of the crypto result, and keeps the crypto row's checkedAt so
 * the badge stays dated. This is not a crypto claim — it is a trust claim: a
 * revoked publisher identity can produce signatures that VERIFY (that is
 * exactly what a leaked signing token buys an attacker), so a green
 * "signatures verified" badge on a revoked connector would be misleading.
 * The verdict WAS reached and it is a trust failure — the reason text says
 * so ("...does not establish trust") — so the state is fail, not
 * not_attempted (which means "could not be reached", per the contract
 * above). The revocation itself stays the loud signal (RevocationBanner),
 * and the badge stops claiming the signature establishes trust. A yanked
 * version keeps its crypto verdict: yanking is a content defect, not a
 * signature defect, and the yanked status is rendered separately.
 *
 * # Coherence guards
 *
 * The report and the verified index come from the SAME CLI run. mergeVerdicts
 * refuses a report whose index identity (version + timestamp) does not match
 * the payload's — a mismatched pair would be incoherent data and fails the
 * whole build (ERR_ARTIFACTS_REPORT_MISMATCH), exactly like the reserved-name
 * collision: loud refusal, never silent partial rendering.
 */

export type ArtifactVerdict = 'pass' | 'fail' | 'not_attempted';

export interface ArtifactVerdictEntry {
  os: string;
  arch: string;
  kind: string;
  verdict: ArtifactVerdict;
  reason?: string;
}

export interface VersionVerdict {
  version: string;
  verdict: ArtifactVerdict;
  reason?: string;
  /** The CLI's wall clock at verdict time — the badge's as-of date. */
  checkedAt: string;
  artifacts: ArtifactVerdictEntry[];
}

/** One entry's (connector or processor) version verdicts. */
export interface EntryVerdict {
  name: string;
  versions: VersionVerdict[];
}

/** schemaVersion-1 report shape written by the CLI's --artifacts pass.
 * `processors` is additive (schemaVersion 1, landed with WS4 S5) — absent
 * until the CLI run that emits it, so the type is optional and the merge
 * treats an absent collection as "no verdicts" (never a pass). */
export interface ArtifactReport {
  schemaVersion: number;
  generatedAt: string;
  indexVersion: number;
  indexTimestamp: string;
  verifierVersion: string;
  connectors: EntryVerdict[];
  processors?: EntryVerdict[];
}

export const ARTIFACT_REPORT_SCHEMA_VERSION = 1;

/** The site's own reason when a version has no verdict row in the report —
 * reachable only in unit tests or a build bug (the build always passes the
 * report); never a presence-pass. */
export const REASON_NO_VERDICT_IN_REPORT =
  'no verdict for this version in the build-time artifacts report';

export const REASON_PUBLISHER_REVOKED =
  'publisher identity revoked — a verifying signature under this identity does not establish trust';

/** The CLI's own no-provenance refusal, mirrored verbatim: the install path
 * hard-refuses a version whose index entry has no SLSA provenance
 * (RequireProvenance), so the site never offers an active install command
 * for one — the command would be a guaranteed refusal. The string is part of
 * the report contract (cmd/registry-verify/artifacts.go's reasonNoProvenance);
 * the integration test pins the round-trip. */
export const REASON_NO_PROVENANCE = 'no provenance in index';

/** True iff the version carries a yank record (the default-version picker's
 * filter; a yanked version never wins default). */
export function isYanked(version: { yanked?: { reason?: string } }): boolean {
  return Boolean(version.yanked);
}

/** True iff the publisher's identity is revoked (the connector-status
 * classifier's most severe state, and the verdict overlay trigger). */
export function isPublisherRevoked(entry: { publisher: { revoked?: unknown } }): boolean {
  return Boolean(entry.publisher.revoked);
}

/** connector/processor name -> version -> verdict row, built once per merge
 * (the render model loops every version of every entry, so the lookup is
 * hoisted — never rebuilt per version). */
export type VerdictLookup = Map<string, Map<string, VersionVerdict>>;

/**
 * Builds the verdict lookups the render model consumes, from a report the
 * SAME CLI run produced as the verified index. Coherence-guarded: a report
 * whose index identity does not match the payload fails the build.
 */
export function mergeVerdicts(
  report: ArtifactReport,
  payload: IndexPayload
): { connectors: VerdictLookup; processors: VerdictLookup } {
  if (report.schemaVersion !== ARTIFACT_REPORT_SCHEMA_VERSION) {
    throw new BuildError(
      'ERR_ARTIFACTS_REPORT_MISMATCH',
      `artifacts report has schemaVersion ${report.schemaVersion}, expected ` +
        `${ARTIFACT_REPORT_SCHEMA_VERSION} — the verifier CLI and this build are out of sync`
    );
  }
  if (
    report.indexVersion !== payload.index.version ||
    report.indexTimestamp !== payload.index.timestamp
  ) {
    throw new BuildError(
      'ERR_ARTIFACTS_REPORT_MISMATCH',
      `artifacts report describes index version ${report.indexVersion} (${report.indexTimestamp}) ` +
        `but the verified payload is version ${payload.index.version} (${payload.index.timestamp}) — ` +
        `the report and the index are not from the same verification run; refusing to render`
    );
  }
  const connectors = lookupFor(report.connectors);
  const processors = lookupFor(report.processors ?? []);
  return { connectors, processors };
}

function lookupFor(entries: EntryVerdict[]): VerdictLookup {
  const byEntry = new Map<string, Map<string, VersionVerdict>>();
  for (const e of entries) {
    const byVersion = new Map<string, VersionVerdict>();
    for (const v of e.versions) {
      byVersion.set(v.version, v);
    }
    byEntry.set(e.name, byVersion);
  }
  return byEntry;
}

/**
 * The verdict for one connector version after merge + overlay. `lookup` is
 * the merge result of the SAME CLI run's report (undefined only in unit
 * tests, or a render model computed without the artifacts pass) — then every
 * version is not_attempted with the explicit reason above, never pass.
 */
export function verdictForVersion(
  lookup: VerdictLookup | undefined,
  connectorName: string,
  connectorRevoked: boolean,
  version: string
): { verdict: ArtifactVerdict; reason?: string; checkedAt?: string } {
  return overlayVerdict(lookup, connectorName, connectorRevoked, version);
}

/** The processor analogue of verdictForVersion — same trust semantics, same
 * overlay, same honesty floor (WS4 S5: processors are verified by the same
 * artifacts pass). */
export function verdictForProcessorVersion(
  lookup: VerdictLookup | undefined,
  processorName: string,
  processorRevoked: boolean,
  version: string
): { verdict: ArtifactVerdict; reason?: string; checkedAt?: string } {
  return overlayVerdict(lookup, processorName, processorRevoked, version);
}

function overlayVerdict(
  lookup: VerdictLookup | undefined,
  name: string,
  revoked: boolean,
  version: string
): { verdict: ArtifactVerdict; reason?: string; checkedAt?: string } {
  const row = lookup?.get(name)?.get(version);
  if (revoked) {
    // The crypto row (when present) is real and dated — keep its checkedAt.
    return {
      verdict: 'fail',
      reason: REASON_PUBLISHER_REVOKED,
      ...(row?.checkedAt !== undefined ? { checkedAt: row.checkedAt } : {}),
    };
  }
  if (!row) {
    return { verdict: 'not_attempted', reason: REASON_NO_VERDICT_IN_REPORT };
  }
  return {
    verdict: row.verdict,
    ...(row.reason !== undefined ? { reason: row.reason } : {}),
    ...(row.checkedAt !== undefined ? { checkedAt: row.checkedAt } : {}),
  };
}

/** The install-command gate for one entry's default version (WS4 4.13): a
 * version the CLI would refuse to install never gets an active install
 * command. Precedence: the entry-level suppression (revoked publisher or
 * every version yanked) wins; then a failed verification verdict; then a
 * no-provenance not_attempted (the CLI hard-refuses those — RequireProvenance
 * — so the command would be a guaranteed refusal). Every other state renders
 * the command. The gate is a pure function so the pages stay thin and the
 * states are unit-tested. */
export type InstallGate =
  | { gate: 'none' }
  | { gate: 'suppress' }
  | { gate: 'fail'; version: string; reason?: string }
  | { gate: 'no-provenance'; version: string };

export function installGateFor(args: {
  suppressInstallCommand: boolean;
  // The pages pass the default version's fields through directly, which may
  // be undefined when no version exists — the input bag explicitly admits
  // that (exactOptionalPropertyTypes); the gate output never carries it.
  verdict?: ArtifactVerdict | undefined;
  verdictReason?: string | undefined;
  version?: string | undefined;
}): InstallGate {
  if (args.suppressInstallCommand) return { gate: 'suppress' };
  if (args.verdict === 'fail' && args.version !== undefined) {
    return {
      gate: 'fail',
      version: args.version,
      ...(args.verdictReason !== undefined ? { reason: args.verdictReason } : {}),
    };
  }
  if (
    args.verdict === 'not_attempted' &&
    args.verdictReason === REASON_NO_PROVENANCE &&
    args.version !== undefined
  ) {
    return { gate: 'no-provenance', version: args.version };
  }
  return { gate: 'none' };
}
