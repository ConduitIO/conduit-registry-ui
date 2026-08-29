import type { CSSProperties } from 'react';
import type { ArtifactVerdict } from '../lib/verdicts';
import styles from './VerifiedBadge.module.css';

/**
 * Renders the build-time per-version signature verdict (WS4 S3,
 * src/lib/verdicts.ts) — the badge NEVER computes trust itself, it only
 * displays a three-state verdict its caller already merged from the Go
 * verifier CLI's artifacts report (cmd/registry-verify --artifacts):
 *
 *   pass          — every signature bundle verified against the trust anchors
 *                   and the connector's pinned identity, and the SLSA
 *                   provenance bound to the index-declared sha256.
 *   fail          — a bundle verified-failed (tampered bytes, wrong identity,
 *                   non-binding provenance). Reason in the label's title and
 *                   aria-label.
 *   not_attempted — the verdict could not be reached: no provenance reference
 *                   in the index, an unfetchable bundle, or a malformed
 *                   declaration. NEVER a pass — no bundle, no green.
 *
 * Reason strings come from the CLI verbatim (stable report contract) and
 * answer "what do I do about this" — see artifacts.go's reason constants.
 * `checkedAt` is the CLI's wall clock at verdict time: the badge's as-of date.
 *
 * The badge is deliberately neutral for not_attempted — a connector between
 * registration and its first signed release looks different from one that
 * actively failed a check (fail gets the red tone; yanked/revoked get their
 * own loud components — EffectiveStatusTag, RevocationBanner). Never a
 * tooltip: the reason travels in the accessible label and the visible title,
 * and the page renders SignatureNote's qualifying text next to the badge.
 */
export function VerifiedBadge({
  verdict,
  reason,
  checkedAt,
  descriptionId,
}: {
  verdict: ArtifactVerdict;
  /** The CLI's verdict reason, rendered in the title + aria-label. */
  reason?: string;
  /** The CLI's wall clock at verdict time (RFC3339), shown as the as-of
   * date. */
  checkedAt?: string;
  /** id of the page's `SignatureNote` paragraph (see SignatureNote.astro), wired
   * via `aria-describedby` so a screen-reader user who lands directly on this
   * badge — not just one who reads the page top-to-bottom — still gets the
   * "what this does/doesn't mean" caveat. Optional only so unit tests can render
   * the badge in isolation without a matching note element in the DOM. */
  descriptionId?: string;
}) {
  const asOf = checkedAt ? new Date(checkedAt).toISOString().slice(0, 10) : undefined;
  const title = [reason, asOf ? `as of ${asOf}` : null].filter(Boolean).join(' · ');
  const label = {
    pass: 'Signatures verified',
    fail: 'Signature check failed',
    not_attempted: 'Signature not verified',
  }[verdict];
  const glyph = { pass: '✓', fail: '✕', not_attempted: '–' }[verdict];
  const color = {
    pass: '--conduit-color-status-running',
    fail: '--conduit-color-status-degraded',
    not_attempted: '--conduit-color-status-unknown',
  }[verdict];

  return (
    <span
      className={styles.badge}
      data-tone={verdict}
      title={title || undefined}
      aria-label={title ? `${label}. ${title}` : label}
      style={{ ['--badge-color']: `var(${color})` } as CSSProperties}
      {...(descriptionId ? { 'aria-describedby': descriptionId } : {})}
    >
      <span className={styles.glyph} aria-hidden="true">
        {glyph}
      </span>
      <span className={styles.label}>{label}</span>
    </span>
  );
}
