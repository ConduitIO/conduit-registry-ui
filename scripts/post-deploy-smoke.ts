#!/usr/bin/env tsx
/**
 * Post-deploy smoke check (step6-web-ui.md §3 step 10, §9 edge case: "CDN/Pages
 * serving a stale cached index.json after deploy"). Run by the deploy workflow
 * AFTER the GitHub Pages deploy step completes. Three assertions:
 *
 *   1. The live list page contains an expected connector name string (proves
 *      the deploy actually served fresh content, not a 404/blank page).
 *   2. The deployed /index.json is BYTE-IDENTICAL to the index.json this build
 *      produced (dist/index.json) — catches a broken deploy or a CDN serving a
 *      stale cached copy, which a "does it parse as JSON" check would miss.
 *   3. The canonical index host (INDEX_URL, default
 *      https://index.conduitdata.io/index.json — the registry repo's build-free
 *      publication, WS4 S6) serves BYTE-IDENTICAL bytes to dist/index.json —
 *      catches the canonical host serving a stale index while this deploy is
 *      current, the freshness mismatch the whole S6 split exists to bound.
 *
 * Environment:
 *   SITE_URL  the deployed host (required, e.g. https://registry.conduitdata.io)
 *   INDEX_URL the canonical index host (optional, defaults to
 *             https://index.conduitdata.io/index.json)
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, '..');

const DEFAULT_INDEX_URL = 'https://index.conduitdata.io/index.json';

// S3 (adversarial review): every fetch below MUST time out. A host that
// accepts-and-never-responds would otherwise hang the smoke job to GitHub's
// 360-minute default (with concurrency cancel-in-progress: false, queuing
// every later deploy). AbortSignal.timeout also fires on a dead connection.
const FETCH_TIMEOUT_MS = 30_000;

async function main(): Promise<void> {
  const siteUrl = process.env['SITE_URL'];
  if (!siteUrl) {
    throw new Error('SITE_URL env var is required (e.g. https://registry.conduitdata.io)');
  }
  const indexUrl = process.env['INDEX_URL'] ?? DEFAULT_INDEX_URL;

  const distIndexPath = path.join(webRoot, 'dist', 'index.json');
  if (!existsSync(distIndexPath)) {
    throw new Error(`${distIndexPath} not found — run \`npm run build\` before the smoke check`);
  }
  const builtIndexBytes = readFileSync(distIndexPath);

  console.log(`[smoke] fetching ${siteUrl}/`);
  const listRes = await fetch(new URL('/', siteUrl), {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!listRes.ok) throw new Error(`list page fetch failed: HTTP ${listRes.status}`);
  const listHtml = await listRes.text();
  if (!listHtml.includes('Connectors')) {
    throw new Error('list page did not contain expected marker string "Connectors"');
  }
  console.log('[smoke] list page OK');

  console.log(`[smoke] fetching ${siteUrl}/index.json`);
  const indexRes = await fetch(new URL('/index.json', siteUrl), {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!indexRes.ok) throw new Error(`/index.json fetch failed: HTTP ${indexRes.status}`);
  const liveIndexBytes = Buffer.from(await indexRes.arrayBuffer());

  if (!liveIndexBytes.equals(builtIndexBytes)) {
    throw new Error(
      `deployed /index.json (${liveIndexBytes.length} bytes) does NOT byte-match the build's ` +
        `verified dist/index.json (${builtIndexBytes.length} bytes) — possible stale CDN cache or broken deploy`
    );
  }
  console.log('[smoke] deployed /index.json byte-matches the verified build output.');

  console.log(`[smoke] fetching ${indexUrl} (canonical index host)`);
  const canonicalRes = await fetch(indexUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!canonicalRes.ok) {
    throw new Error(
      `canonical index fetch failed: HTTP ${canonicalRes.status} — is the index.conduitdata.io ` +
        `DNS record (CNAME -> conduitio.github.io) and the registry repo's Pages custom domain configured?`
    );
  }
  const canonicalIndexBytes = Buffer.from(await canonicalRes.arrayBuffer());

  if (!canonicalIndexBytes.equals(builtIndexBytes)) {
    throw new Error(
      `canonical ${indexUrl} (${canonicalIndexBytes.length} bytes) does NOT byte-match this ` +
        `build's verified dist/index.json (${builtIndexBytes.length} bytes) — the canonical host ` +
        `is serving different index bytes than this build verified (stale index publication or CDN)`
    );
  }
  console.log('[smoke] canonical index byte-matches the verified build output. PASSED.');
}

main().catch((err: unknown) => {
  console.error('[smoke] FAILED:', err);
  process.exitCode = 1;
});
