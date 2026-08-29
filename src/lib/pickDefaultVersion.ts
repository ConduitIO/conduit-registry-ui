import type { YankReason } from './schema';
import { isYanked } from './deriveVerified';
import { sortVersionsDescending } from './semver';

/**
 * Structural on purpose: connector and processor versions share the fields this
 * picks by (`version`, `yanked`) — one core serves both (WS4 plan §1, amended
 * AC 4.9: processors mirror connectors' derived fields).
 */
export interface DefaultVersionCandidate {
  version: string;
  yanked?: YankReason;
}

/**
 * Picks the version shown by default: the compat-matrix default and the
 * install-command's implicit target (no `@version` pin — mirrors the CLI's own
 * "newest compatible" resolution philosophy, step6-web-ui.md §5 item 3).
 *
 * The newest NON-yanked version, by convention the index already lists
 * newest-first but this re-sorts defensively (schema doesn't enforce order).
 *
 * If every version is yanked, this still returns the newest version anyway —
 * transparently, with its yank reason surfaced by the caller — rather than
 * returning undefined, per step6-web-ui.md §10's explicit test case ("falls back
 * to showing the newest anyway ... rather than picking nothing").
 */
export function pickDefaultVersion<T extends DefaultVersionCandidate>(entry: {
  versions: T[];
}): T | undefined {
  if (entry.versions.length === 0) return undefined;

  const nonYanked = entry.versions.filter((v) => !isYanked(v));
  const pool = nonYanked.length > 0 ? nonYanked : entry.versions;

  const sorted = sortVersionsDescending(pool, (v) => v.version);
  return sorted[0];
}
