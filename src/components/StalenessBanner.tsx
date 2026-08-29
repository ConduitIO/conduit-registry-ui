import { STALENESS_BANNER_THRESHOLD_MS, STALENESS_WINDOW_MS } from '../lib/renderModel';
import styles from './StalenessBanner.module.css';

/**
 * The index-staleness warning (WS4 4.14): the verifier refuses an index
 * older than its 7-day window, so a stale index takes the whole site down at
 * the next build. With less than a day of the window left, the site says so —
 * loudly, on every page — so the failure is never a surprise. The input is
 * the index's age at build time (render model `indexAgeMs`), computed by the
 * build, not the client.
 *
 * The threshold is the window minus a 24h grace; past it, this banner shows.
 * The build itself already failed-closed on anything older than the full
 * window, so the banner is always truthful: it appears while the site is
 * still being built from a verifiable index.
 */
export function StalenessBanner({ indexAgeMs }: { indexAgeMs: number }) {
  if (indexAgeMs <= STALENESS_BANNER_THRESHOLD_MS) return null;
  const daysLeft = Math.ceil((STALENESS_WINDOW_MS - indexAgeMs) / (24 * 60 * 60 * 1000));
  return (
    <p className={styles.banner} role="status">
      The registry index is {Math.floor(indexAgeMs / (24 * 60 * 60 * 1000))} days old. This site was
      built from it, but the verifier refuses an index older than 7 days — unless a fresh index is
      signed and published
      {daysLeft > 0 ? ` within the next ${daysLeft} day${daysLeft === 1 ? '' : 's'}` : ''}, the next
      build will fail and this site will go stale.
    </p>
  );
}
