import type { Connector, ConnectorVersion, IndexPayload } from './schema';
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
 * # The revocation overlay
 *
 * The crypto verdict is the raw result of bundle verification. One overlay
 * is applied at merge time, deliberately: when the connector's publisher is
 * REVOKED, every version's badge renders not_attempted with a revocation
 * reason, regardless of the crypto result. This is not a crypto claim — it
 * is a trust claim: a revoked publisher identity can produce signatures that
 * VERIFY (that is exactly what a leaked signing token buys an attacker), so
 * a green "signatures verified" badge on a revoked connector would be
 * misleading. The revocation itself is the loud signal (RevocationBanner),
 * and the badge stops claiming the signature establishes trust. A yanked
 * version keeps its crypto verdict: yanking is a content defect, not a
 * signature defect, and the yanked status is rendered separately in the
 * versions table.
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

export interface ConnectorVerdict {
  name: string;
  versions: VersionVerdict[];
}

/** schemaVersion-1 report shape written by the CLI's --artifacts pass. */
export interface ArtifactReport {
  schemaVersion: number;
  generatedAt: string;
  indexVersion: number;
  indexTimestamp: string;
  verifierVersion: string;
  connectors: ConnectorVerdict[];
}

export const ARTIFACT_REPORT_SCHEMA_VERSION = 1;

/** The site's own reason when a version has no verdict row in the report —
 * reachable only in unit tests or a build bug (the build always passes the
 * report); never a presence-pass. */
export const REASON_NO_VERDICT_IN_REPORT =
  'no verdict for this version in the build-time artifacts report';

export const REASON_PUBLISHER_REVOKED =
  'publisher identity revoked — a verifying signature under this identity does not establish trust';

/** True iff the version carries a yank record (the default-version picker's
 * filter; a yanked version never wins default). */
export function isYanked(version: ConnectorVersion): boolean {
  return Boolean(version.yanked);
}

/** True iff the publisher's identity is revoked (the connector-status
 * classifier's most severe state, and the verdict overlay trigger). */
export function isPublisherRevoked(connector: Connector): boolean {
  return Boolean(connector.publisher.revoked);
}

/**
 * Builds the verdict lookup the render model consumes: connector name ->
 * version -> verdict row, from a report the SAME CLI run produced as the
 * verified index. Coherence-guarded: a report whose index identity does not
 * match the payload fails the build.
 */
export function mergeVerdicts(
  report: ArtifactReport,
  payload: IndexPayload
): Map<string, Map<string, VersionVerdict>> {
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
  const byConnector = new Map<string, Map<string, VersionVerdict>>();
  for (const c of report.connectors) {
    const byVersion = new Map<string, VersionVerdict>();
    for (const v of c.versions) {
      byVersion.set(v.version, v);
    }
    byConnector.set(c.name, byVersion);
  }
  return byConnector;
}

/**
 * The verdict for one version after merge + overlay. `connectorRevoked` is
 * the publisher-revocation overlay; `report` may be absent entirely (unit
 * tests, or the render model computed without the artifacts pass) — then
 * every version is not_attempted with the explicit reason above, never pass.
 */
export function verdictForVersion(
  report: ArtifactReport | undefined,
  payload: IndexPayload,
  connectorName: string,
  connectorRevoked: boolean,
  version: string
): { verdict: ArtifactVerdict; reason?: string; checkedAt?: string } {
  if (connectorRevoked) {
    return { verdict: 'not_attempted', reason: REASON_PUBLISHER_REVOKED };
  }
  if (!report) {
    return { verdict: 'not_attempted', reason: REASON_NO_VERDICT_IN_REPORT };
  }
  const row = mergeVerdicts(report, payload).get(connectorName)?.get(version);
  if (!row) {
    return { verdict: 'not_attempted', reason: REASON_NO_VERDICT_IN_REPORT };
  }
  return {
    verdict: row.verdict,
    ...(row.reason !== undefined ? { reason: row.reason } : {}),
    ...(row.checkedAt !== undefined ? { checkedAt: row.checkedAt } : {}),
  };
}
