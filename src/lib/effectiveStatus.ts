import type { Connector, Processor, Revocation, YankReason } from './schema';
import { isPublisherRevoked } from './deriveVerified';
import { pickDefaultVersion } from './pickDefaultVersion';

export type EffectiveStatus = 'active' | 'deprecated' | 'yanked' | 'revoked';

/**
 * Structural on purpose: connector and processor entries share the exact fields
 * this classification reads (`publisher.revoked`, `versions[].yanked`,
 * `versions[].deprecated`) — one core serves both (WS4 plan §1, amended AC 4.9).
 */
export interface EffectiveStatusEntry {
  publisher: { revoked?: Revocation };
  versions: { version: string; yanked?: YankReason; deprecated?: boolean }[];
}

/**
 * Classifies an entry's top-level status for the list row / detail-page header
 * tag (step6-web-ui.md §5 item 1, §10). Precedence, most severe first:
 *
 *   1. `revoked`    — `publisher.revoked` is set. Overrides everything else.
 *   2. `yanked`     — every published version carries `yanked`. An entry with
 *                     SOME (not all) versions yanked stays "active" at this level;
 *                     only the affected version rows in the detail-page table are
 *                     flagged (step6-web-ui.md §10's explicit test case).
 *   3. `deprecated` — not revoked, not all-yanked, and the version this site would
 *                     show by default (pickDefaultVersion — newest non-yanked)
 *                     carries `deprecated: true`. NOTE: the frozen schema only
 *                     defines `deprecated` per-version, not per-entry; this
 *                     function's choice to project the *default-shown* version's
 *                     deprecated flag up to the entry level is this site's own
 *                     interpretation (not spelled out in the schema/plan), made
 *                     explicit here rather than silently assumed.
 *   4. `active`     — none of the above.
 */
export function effectiveStatusOf(entry: EffectiveStatusEntry): EffectiveStatus {
  if (isPublisherRevoked(entry)) return 'revoked';

  if (entry.versions.length > 0 && entry.versions.every((v) => Boolean(v.yanked))) {
    return 'yanked';
  }

  const defaultVersion = pickDefaultVersion(entry);
  if (defaultVersion?.deprecated) return 'deprecated';

  return 'active';
}

export function effectiveConnectorStatus(connector: Connector): EffectiveStatus {
  return effectiveStatusOf(connector);
}

export function effectiveProcessorStatus(processor: Processor): EffectiveStatus {
  return effectiveStatusOf(processor);
}
