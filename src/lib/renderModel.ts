import type {
  ArtifactArch,
  ArtifactOS,
  Connector,
  IndexPayload,
  Revocation,
  YankReason,
} from './schema';
import { ALL_ARCH, ALL_OS } from './schema';
import { deriveProcessorVerified, deriveVerified } from './deriveVerified';
import {
  effectiveConnectorStatus,
  effectiveProcessorStatus,
  type EffectiveStatus,
} from './effectiveStatus';
import { pickDefaultVersion } from './pickDefaultVersion';
import { isReservedRouteSegment } from './reserved';
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
  verified: boolean;
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
 * express here (schema def `processorArtifact` — os/arch/kind are constants). */
export interface RenderedProcessorVersion {
  version: string;
  releasedAt?: string;
  minConduitVersion: string;
  minProtocolVersion: string;
  deprecated: boolean;
  yanked?: YankReason;
  verified: boolean;
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
  verified: boolean;
  connectors: RenderedConnector[];
  processors: RenderedProcessor[];
  searchManifest: SearchManifestEntry[];
}

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
  opts: { verified?: boolean; generatedAt?: string } = {}
): RenderModel {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  assertUniqueNames(payload.connectors, 'connector');
  assertUniqueNames(payload.processors ?? [], 'processor');

  const connectors: RenderedConnector[] = payload.connectors.map((connector) => {
    const effectiveStatus = effectiveConnectorStatus(connector);
    const allVersionsYanked = effectiveStatus === 'yanked';
    const suppressInstallCommand = effectiveStatus === 'revoked' || allVersionsYanked;
    const defaultVersion = pickDefaultVersion(connector);

    const versions: RenderedVersion[] = connector.versions.map((v) => ({
      version: v.version,
      ...(v.releasedAt !== undefined ? { releasedAt: v.releasedAt } : {}),
      minConduitVersion: v.minConduitVersion,
      minProtocolVersion: v.minProtocolVersion,
      deprecated: Boolean(v.deprecated),
      ...(v.yanked !== undefined ? { yanked: v.yanked } : {}),
      verified: deriveVerified(v, connector),
      isDefault: defaultVersion?.version === v.version,
      compat: buildCompatMatrix(connector, v.version),
    }));

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

    const versions: RenderedProcessorVersion[] = processor.versions.map((v) => ({
      version: v.version,
      ...(v.releasedAt !== undefined ? { releasedAt: v.releasedAt } : {}),
      minConduitVersion: v.minConduitVersion,
      minProtocolVersion: v.minProtocolVersion,
      deprecated: Boolean(v.deprecated),
      ...(v.yanked !== undefined ? { yanked: v.yanked } : {}),
      verified: deriveProcessorVerified(v, processor),
      isDefault: defaultVersion?.version === v.version,
    }));

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
    connectors,
    processors,
    searchManifest,
  };
}
