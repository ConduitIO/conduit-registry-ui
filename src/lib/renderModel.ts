import type {
  ArtifactArch,
  ArtifactOS,
  Connector,
  IndexPayload,
  Revocation,
  YankReason,
} from './schema';
import { ALL_ARCH, ALL_OS } from './schema';
import {
  effectiveConnectorStatus,
  effectiveProcessorStatus,
  type EffectiveStatus,
} from './effectiveStatus';
import { pickDefaultVersion } from './pickDefaultVersion';
import { isReservedRouteSegment } from './reserved';
import {
  mergeVerdicts,
  verdictForProcessorVersion,
  verdictForVersion,
  type ArtifactReport,
  type ArtifactVerdict,
  type VerdictLookup,
} from './verdicts';
import { BuildError } from './errors';

export interface CompatCellModel {
  os: ArtifactOS;
  arch: ArtifactArch;
  available: boolean;
}

export interface RenderedVersion {
  version: string;
  releasedAt?: string;
  minConduitVersion: string;
  minProtocolVersion: string;
  deprecated: boolean;
  yanked?: YankReason;
  /** The build-time signature verdict (WS4 S3): pass / fail(reason) /
   * not_attempted(reason). Three states, never a boolean — no presence-pass:
   * a version with no bundle references is not_attempted, not "verified". */
  verdict: ArtifactVerdict;
  verdictReason?: string;
  /** The verifier CLI's wall clock at verdict time — the badge's as-of date. */
  verdictCheckedAt?: string;
  isDefault: boolean;
  compat: CompatCellModel[];
}

/** Best-effort download-stats shape, merged in after the (independently
 * fault-tolerant) Scarf fetch step — see fetchScarfStats.mjs. Absent entirely
 * until that step runs; `unavailable: true` when Scarf couldn't be reached for
 * this connector specifically (never a bare 0 — see step6-web-ui.md §5 item 6). */
export interface ConnectorStats {
  unavailable: boolean;
  totalDownloads?: number;
  asOf: string;
}

export interface RenderedConnector {
  name: string;
  displayName: string;
  description: string;
  repository?: string;
  effectiveStatus: EffectiveStatus;
  revoked?: Revocation;
  allVersionsYanked: boolean;
  /** Suppresses the install-command copy-block whenever true — revoked publisher
   * OR every version yanked (step6-web-ui.md §5 item 2/3). */
  suppressInstallCommand: boolean;
  defaultVersion?: string;
  versions: RenderedVersion[];
  stats?: ConnectorStats;
}

/** The processor analogue of `RenderedVersion`. No `compat` matrix: a processor
 * ships a single arch-neutral (wasip1/wasm) artifact that runs on every
 * platform, so the per-(os,arch) matrix a connector needs has nothing to
 * express here (schema def `processorArtifact` — os/arch/kind are constants).
 * Verdict semantics are identical to connectors (WS4 S5 + S3): the same
 * artifacts pass verifies the processor's single artifact and its provenance,
 * and the badge renders the same three states — never a presence pass. */
export interface RenderedProcessorVersion {
  version: string;
  releasedAt?: string;
  minConduitVersion: string;
  minProtocolVersion: string;
  deprecated: boolean;
  yanked?: YankReason;
  verdict: ArtifactVerdict;
  verdictReason?: string;
  /** The verifier CLI's wall clock at verdict time — the badge's as-of date. */
  verdictCheckedAt?: string;
  isDefault: boolean;
}

/** The processor analogue of `RenderedConnector`, mirroring its honesty
 * properties: same effective-status semantics, same install-command
 * suppression, same verified-badge derivation (WS4 plan §1, amended AC 4.9). */
export interface RenderedProcessor {
  name: string;
  displayName: string;
  description: string;
  repository?: string;
  effectiveStatus: EffectiveStatus;
  revoked?: Revocation;
  allVersionsYanked: boolean;
  suppressInstallCommand: boolean;
  defaultVersion?: string;
  versions: RenderedProcessorVersion[];
}

export interface SearchManifestEntry {
  name: string;
  displayName: string;
  description: string;
  repository?: string;
  effectiveStatus: EffectiveStatus;
}

export interface RenderModel {
  generatedAt: string;
  indexVersion: number;
  indexTimestamp: string;
  /** The index's ROOT-signature verdict (the CLI's exit 0 with
   * --require-root) — distinct from per-version signature verdicts. */
  verified: boolean;
  /** The conduit module version the verifier CLI was built from (the footer's
   * "verifier version", WS4 4.14) — real value from the build, not
   * hardcoded. Absent when the artifacts pass did not run (unit tests). */
  verifierVersion?: string;
  /** Index age in ms at build time (generatedAt minus index.timestamp) — the
   * staleness banner's input. The build refuses an index older than the CLI's
   * 7-day window; the banner warns before that. */
  indexAgeMs: number;
  connectors: RenderedConnector[];
  processors: RenderedProcessor[];
  searchManifest: SearchManifestEntry[];
}

/** The verifier CLI's staleness window (index.DefaultMaxStaleness) and the
 * warning grace the banner lives in: a build succeeds inside the 7-day
 * window, but with less than a day left the site warns that the next build
 * will fail until a fresh index is published (WS4 4.14). */
export const STALENESS_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
export const STALENESS_WARN_GRACE_MS = 24 * 60 * 60 * 1000;
export const STALENESS_BANNER_THRESHOLD_MS = STALENESS_WINDOW_MS - STALENESS_WARN_GRACE_MS;

function buildCompatMatrix(
  connector: Connector,
  version: RenderedVersion['version']
): CompatCellModel[] {
  const found = connector.versions.find((v) => v.version === version);
  const artifacts = found?.artifacts ?? [];
  const cells: CompatCellModel[] = [];
  for (const os of ALL_OS) {
    for (const arch of ALL_ARCH) {
      cells.push({
        os,
        arch,
        available: artifacts.some((a) => a.os === os && a.arch === arch),
      });
    }
  }
  return cells;
}

/**
 * Guards a registry collection (connectors or processors) against names that
 * would collide with a route this generator itself uses, or with each other.
 * A collision fails the WHOLE build loudly rather than silently shadowing a
 * page (§9 edge case, extended to processors in S5).
 */
function assertUniqueNames(entries: { name: string }[], kind: 'connector' | 'processor'): void {
  const seenNames = new Set<string>();
  for (const entry of entries) {
    if (isReservedRouteSegment(entry.name)) {
      throw new BuildError(
        'ERR_RESERVED_ROUTE_COLLISION',
        `${kind} name "${entry.name}" collides with a reserved site route segment — ` +
          `refusing to generate (this would silently shadow a real page)`
      );
    }
    if (seenNames.has(entry.name)) {
      throw new BuildError(
        'ERR_RESERVED_ROUTE_COLLISION',
        `duplicate ${kind} name "${entry.name}" in index — index-CI is supposed to enforce ` +
          `uniqueness; refusing to generate two pages at the same URL`
      );
    }
    seenNames.add(entry.name);
  }
}

/**
 * Transforms the verified payload into exactly what the Astro pages consume,
 * computing every derived field once, in one place (step6-web-ui.md §3 step 5).
 * Connectors AND processors are derived here, with the same honesty properties
 * (verified badge, effective status, install-command suppression — WS4 plan §1,
 * amended ACs 4.5/4.9).
 */
export function buildRenderModel(
  payload: IndexPayload,
  opts: { verified?: boolean; generatedAt?: string; artifacts?: ArtifactReport } = {}
): RenderModel {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const indexAgeMs = Math.max(0, Date.parse(generatedAt) - Date.parse(payload.index.timestamp));
  // The verdict lookups are built ONCE per merge — the loop below reads them
  // for every version of every entry (never rebuilt per version).
  const verdicts = opts.artifacts !== undefined ? mergeVerdicts(opts.artifacts, payload) : undefined;
  assertUniqueNames(payload.connectors, 'connector');
  assertUniqueNames(payload.processors ?? [], 'processor');

  const connectors: RenderedConnector[] = payload.connectors.map((connector) => {
    const effectiveStatus = effectiveConnectorStatus(connector);
    const allVersionsYanked = effectiveStatus === 'yanked';
    const suppressInstallCommand = effectiveStatus === 'revoked' || allVersionsYanked;
    const defaultVersion = pickDefaultVersion(connector);

    const revoked = connector.publisher.revoked !== undefined;
    const versions: RenderedVersion[] = connector.versions.map((v) => {
      const verdict = verdictForVersion(
        verdicts?.connectors,
        connector.name,
        revoked,
        v.version
      );
      return {
        version: v.version,
        ...(v.releasedAt !== undefined ? { releasedAt: v.releasedAt } : {}),
        minConduitVersion: v.minConduitVersion,
        minProtocolVersion: v.minProtocolVersion,
        deprecated: Boolean(v.deprecated),
        ...(v.yanked !== undefined ? { yanked: v.yanked } : {}),
        verdict: verdict.verdict,
        ...(verdict.reason !== undefined ? { verdictReason: verdict.reason } : {}),
        ...(verdict.checkedAt !== undefined ? { verdictCheckedAt: verdict.checkedAt } : {}),
        isDefault: defaultVersion?.version === v.version,
        compat: buildCompatMatrix(connector, v.version),
      };
    });

    return {
      name: connector.name,
      displayName: connector.displayName ?? connector.name,
      description: connector.description ?? '',
      ...(connector.repository !== undefined ? { repository: connector.repository } : {}),
      effectiveStatus,
      ...(connector.publisher.revoked !== undefined
        ? { revoked: connector.publisher.revoked }
        : {}),
      allVersionsYanked,
      suppressInstallCommand,
      ...(defaultVersion !== undefined ? { defaultVersion: defaultVersion.version } : {}),
      versions,
    };
  });

  const processors: RenderedProcessor[] = (payload.processors ?? []).map((processor) => {
    const effectiveStatus = effectiveProcessorStatus(processor);
    const allVersionsYanked = effectiveStatus === 'yanked';
    const suppressInstallCommand = effectiveStatus === 'revoked' || allVersionsYanked;
    const defaultVersion = pickDefaultVersion(processor);

    const revoked = processor.publisher.revoked !== undefined;
    const versions: RenderedProcessorVersion[] = processor.versions.map((v) => {
      const verdict = verdictForProcessorVersion(
        verdicts?.processors,
        processor.name,
        revoked,
        v.version
      );
      return {
        version: v.version,
        ...(v.releasedAt !== undefined ? { releasedAt: v.releasedAt } : {}),
        minConduitVersion: v.minConduitVersion,
        minProtocolVersion: v.minProtocolVersion,
        deprecated: Boolean(v.deprecated),
        ...(v.yanked !== undefined ? { yanked: v.yanked } : {}),
        verdict: verdict.verdict,
        ...(verdict.reason !== undefined ? { verdictReason: verdict.reason } : {}),
        ...(verdict.checkedAt !== undefined ? { verdictCheckedAt: verdict.checkedAt } : {}),
        isDefault: defaultVersion?.version === v.version,
      };
    });

    return {
      name: processor.name,
      displayName: processor.displayName ?? processor.name,
      description: processor.description ?? '',
      ...(processor.repository !== undefined ? { repository: processor.repository } : {}),
      effectiveStatus,
      ...(processor.publisher.revoked !== undefined
        ? { revoked: processor.publisher.revoked }
        : {}),
      allVersionsYanked,
      suppressInstallCommand,
      ...(defaultVersion !== undefined ? { defaultVersion: defaultVersion.version } : {}),
      versions,
    };
  });

  const searchManifest: SearchManifestEntry[] = connectors.map((c) => ({
    name: c.name,
    displayName: c.displayName,
    description: c.description,
    ...(c.repository !== undefined ? { repository: c.repository } : {}),
    effectiveStatus: c.effectiveStatus,
  }));

  return {
    generatedAt,
    indexVersion: payload.index.version,
    indexTimestamp: payload.index.timestamp,
    verified: opts.verified ?? false,
    ...(opts.artifacts !== undefined ? { verifierVersion: opts.artifacts.verifierVersion } : {}),
    indexAgeMs,
    connectors,
    processors,
    searchManifest,
  };
}
