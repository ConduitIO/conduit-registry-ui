import { describe, expect, it, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SearchBox } from '../src/components/SearchBox';
import type { SearchManifestEntry } from '../src/lib/renderModel';

/**
 * Search-island tests (WS4 S4, amended AC 4.2): search covers the fields that
 * exist in the frozen schema — name, displayName, description, repository —
 * via `/search-manifest.json` (the same manifest `buildRenderModel` writes).
 * The manifest fetch is mocked; jsdom never touches the network.
 *
 * The missing-description degradation is the AC's hard requirement: live
 * registry entries carry no `description` (F7), so an entry with an empty
 * description must still be findable by name/displayName/repository — never
 * silently dropped from results.
 */

const MANIFEST: SearchManifestEntry[] = [
  {
    name: 'postgres',
    displayName: 'PostgreSQL',
    description: 'CDC source and batch/upsert destination for PostgreSQL.',
    repository: 'https://github.com/ConduitIO/conduit-connector-postgres',
    effectiveStatus: 'active',
  },
  {
    name: 'no-desc',
    displayName: 'No Description Connector',
    // The degradation case, shaped like today's live entries: no description.
    description: '',
    repository: 'https://github.com/example-org/conduit-connector-no-desc',
    effectiveStatus: 'active',
  },
  {
    name: 'kafka',
    displayName: 'Kafka',
    description: 'Message queue source and sink.',
    // No repository either — exercises the `?? ''` default in the matcher.
    effectiveStatus: 'active',
  },
];

/** Stub global fetch to serve `manifest` as /search-manifest.json. */
function mockManifestFetch(manifest: SearchManifestEntry[] | null) {
  const fetchMock = vi
    .fn()
    .mockResolvedValue(
      manifest === null ? { ok: false, status: 500 } : { ok: true, json: async () => manifest }
    );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function typeQuery(query: string) {
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: query } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('SearchBox — four-field search (amended AC 4.2)', () => {
  it('finds an entry by name (lowercase substring)', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('postgres');
    const link = await screen.findByRole('link', { name: /PostgreSQL/ });
    expect(link.getAttribute('href')).toBe('/connectors/postgres/');
  });

  it('finds an entry by displayName', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('postgresql');
    expect(await screen.findByRole('link', { name: /PostgreSQL/ })).toBeTruthy();
  });

  it('finds an entry by description', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('CDC');
    expect(await screen.findByRole('link', { name: /PostgreSQL/ })).toBeTruthy();
  });

  it('finds an entry by repository URL fragment', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('conduit-connector-postgres');
    expect(await screen.findByRole('link', { name: /PostgreSQL/ })).toBeTruthy();
  });

  it('does not match an entry without a repository on repository terms (?? "" default)', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('github.com');
    // Only the two entries WITH repositories match; kafka must not appear.
    expect(await screen.findByRole('link', { name: /PostgreSQL/ })).toBeTruthy();
    expect(await screen.findByRole('link', { name: /No Description Connector/ })).toBeTruthy();
    expect(screen.queryByRole('link', { name: /Kafka/ })).toBeNull();
  });

  it('matches case-insensitively across mixed-case queries', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('PostGrEs');
    expect(await screen.findByRole('link', { name: /PostgreSQL/ })).toBeTruthy();
  });
});

describe('SearchBox — missing-description degradation', () => {
  it('an entry with an empty description is still findable by name — never silently dropped', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('no-desc');
    const link = await screen.findByRole('link', { name: /No Description Connector/ });
    expect(link.getAttribute('href')).toBe('/connectors/no-desc/');
  });

  it('an entry with an empty description is still findable by displayName and repository', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('conduit-connector-no-desc');
    expect(await screen.findByRole('link', { name: /No Description Connector/ })).toBeTruthy();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Description Connector' } });
    expect(await screen.findByRole('link', { name: /No Description Connector/ })).toBeTruthy();
  });

  it('the empty description renders as an empty result paragraph — present, not dropped', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('no-desc');
    const link = await screen.findByRole('link', { name: /No Description Connector/ });
    const paragraph = link.parentElement!.querySelector('p');
    expect(paragraph).toBeTruthy();
    expect(paragraph!.textContent).toBe('');
  });
});

describe('SearchBox — result and degradation behavior', () => {
  it('renders the explicit no-match line for a query nothing matches', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('zzz-no-such-connector');
    expect(await screen.findByText(/No connectors match/)).toBeTruthy();
  });

  it('announces the match count politely for assistive tech', async () => {
    mockManifestFetch(MANIFEST);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('postgres');
    await screen.findByRole('link', { name: /PostgreSQL/ });
    expect(screen.getByRole('status').textContent).toContain('1 matching connector');
  });

  it('an empty manifest never crashes — every query simply finds nothing', async () => {
    mockManifestFetch([]);
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('postgres');
    expect(await screen.findByText(/No connectors match/)).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('a manifest fetch failure degrades to no results, never a crash — the static list underneath is unaffected', async () => {
    mockManifestFetch(null); // fetch resolves with !ok
    render(<SearchBox listContainerId="connector-list" />);
    typeQuery('postgres');
    expect(await screen.findByText(/No connectors match/)).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('hides the server-rendered list while a query is active and restores it when cleared', async () => {
    mockManifestFetch(MANIFEST);
    render(
      <>
        <ul id="connector-list" aria-label="Connectors">
          <li>server-rendered entry</li>
        </ul>
        <SearchBox listContainerId="connector-list" />
      </>
    );
    const list = document.getElementById('connector-list')!;
    expect(list.style.display).toBe('');
    typeQuery('postgres');
    await screen.findByRole('link', { name: /PostgreSQL/ });
    expect(list.style.display).toBe('none');
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } });
    expect(list.style.display).toBe('');
  });
});
