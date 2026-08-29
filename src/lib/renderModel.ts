import type {
  ArtifactArch,
  ArtifactOS,
  Connector,
  IndexPayload,
  Revocation,
  YankReason,
} from './schema';
import { ALL_ARCH, ALL_OS } from './schema';
import { effectiveConnectorStatus, type EffectiveStatus } from './effectiveStatus';
import { pickDefaultVersion } from './pickDefaultVersion';
import { isReservedRouteSegment } from './reserved';
import { verdictForVersion, type ArtifactReport, type ArtifactVerdict } from './verdicts';
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
 * Transforms the verified payload into exactly what the Astro pages consume,
 * computing every derived field once, in one place (step6-web-ui.md §3 step 5).
 * Also enforces the reserved-route-segment check (§9 edge case) — a connector
 * name colliding with a route this generator itself uses fails the WHOLE build
 * loudly, rather than silently shadowing a route for one connector.
 */
export function buildRenderModel(
  payload: IndexPayload,
  opts: { verified?: boolean; generatedAt?: string; artifacts?: ArtifactReport } = {}
): RenderModel {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const indexAgeMs = Math.max(0, Date.parse(generatedAt) - Date.parse(payload.index.timestamp));
  const seenNames = new Set<string>();
  const connectors: RenderedConnector[] = payload.connectors.map((connector) => {
    if (isReservedRouteSegment(connector.name)) {
      throw new BuildError(
        'ERR_RESERVED_ROUTE_COLLISION',
        `connector name "${connector.name}" collides with a reserved site route segment — ` +
          `refusing to generate (this would silently shadow a real page)`
      );
    }
    if (seenNames.has(connector.name)) {
      throw new BuildError(
        'ERR_RESERVED_ROUTE_COLLISION',
        `duplicate connector name "${connector.name}" in index — index-CI is supposed to enforce ` +
          `uniqueness; refusing to generate two pages at the same URL`
      );
    }
    seenNames.add(connector.name);

    const effectiveStatus = effectiveConnectorStatus(connector);
    const allVersionsYanked = effectiveStatus === 'yanked';
    const suppressInstallCommand = effectiveStatus === 'revoked' || allVersionsYanked;
    const defaultVersion = pickDefaultVersion(connector);

    const revoked = connector.publisher.revoked !== undefined;
    const versions: RenderedVersion[] = connector.versions.map((v) => {
      const verdict = verdictForVersion(
        opts.artifacts,
        payload,
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
    searchManifest,
  };
}
