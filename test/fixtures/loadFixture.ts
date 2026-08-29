import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IndexPayload, SignedIndex } from '../../src/lib/schema';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Loads the real frozen fixture this whole plan is grounded in
 * (a dedicated `sample-index.json` fixture — 2 connectors + 2 processors
 * since S5 — decoupled from the live `index/index.json` which is empty at
 * bootstrap; itself derived from `registry-index/sample-index.json`) as a
 * fresh deep clone every call, so tests can freely mutate their own copy
 * without cross-test interference. */
export function loadSampleIndex(): SignedIndex {
  const raw = readFileSync(path.join(here, 'sample-index.json'), 'utf-8');
  return JSON.parse(raw) as SignedIndex;
}

export function loadSampleIndexRaw(): string {
  return readFileSync(path.join(here, 'sample-index.json'), 'utf-8');
}

/** The amended-4.6 empty-catalogue fixtures (WS4 S4): one with zero
 * connectors (processors present) and one with zero processors (connectors
 * present), so a page test can prove the empty copy is scoped to the right
 * section — the non-empty side renders its normal count line. Payload-shaped
 * (buildRenderModel input), not full signed envelopes: the fixtures exist to
 * exercise the render + page, not the verifier. */
export function loadEmptyConnectorsPayload(): IndexPayload {
  return JSON.parse(readFileSync(path.join(here, 'empty-connectors.json'), 'utf-8'));
}

export function loadEmptyProcessorsPayload(): IndexPayload {
  return JSON.parse(readFileSync(path.join(here, 'empty-processors.json'), 'utf-8'));
}

/** The sample index's own frozen timestamp. Since S2 PR-2 the build never
 * reads this template directly: cmd/registry-verify's TestGenerateSignedFixture
 * (the Go fixture generator, driven by the vitest integration suite) stamps a
 * fresh timestamp onto this payload and ROOT-SIGNS it with a test key, because
 * the real verifier CLI enforces its own 7-day staleness window against the
 * wall clock. This template's own root signature is synthetic and must never
 * be trusted — TestCommittedTemplateIsNotTrusted asserts exactly that. */
export const SAMPLE_INDEX_TIMESTAMP = '2026-07-14T09:00:00Z';
