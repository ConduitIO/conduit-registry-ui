import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { VerifiedBadge } from '../src/components/VerifiedBadge';
import { EffectiveStatusTag } from '../src/components/EffectiveStatusTag';
import { RevocationBanner } from '../src/components/RevocationBanner';
import { CompatCell } from '../src/components/CompatCell';
import { StalenessBanner } from '../src/components/StalenessBanner';
import { STALENESS_BANNER_THRESHOLD_MS, STALENESS_WINDOW_MS } from '../src/lib/renderModel';

/**
 * Guards the never-color-only invariant at the component level (step6-web-ui.md
 * §10): every variant must expose a visible text label and the relevant
 * ARIA role/attribute, not just a color, so the assertions here check text
 * content and roles — never CSS custom property values.
 */

describe('VerifiedBadge', () => {
  /**
   * WS4 S3: the badge is now a three-state build-time crypto verdict —
   * pass / fail(reason) / not_attempted(reason) — computed by the Go
   * verifier CLI's --artifacts pass (never a boolean, never a presence-pass).
   * The assertions below pin the exact labels and the honest-reason
   * behavior: fail and not_attempted always expose their reason in the
   * accessible label and the visible title.
   */
  it('renders a visible "Signatures verified" label for pass — never the word "Verified" alone', () => {
    render(<VerifiedBadge verdict="pass" />);
    expect(screen.getByText('Signatures verified')).toBeTruthy();
    expect(screen.queryByText(/^Verified$/)).toBeNull();
  });

  it('renders a "Signature check failed" label for fail with the reason in the title + aria-label', () => {
    render(
      <VerifiedBadge
        verdict="fail"
        reason="signature bundle does not verify against the trust anchors"
      />
    );
    expect(screen.getByText('Signature check failed')).toBeTruthy();
    const badge = screen.getByText('Signature check failed').closest('span[data-tone]')!;
    expect(badge.getAttribute('data-tone')).toBe('fail');
    expect(badge.getAttribute('title')).toContain('does not verify');
    expect(badge.getAttribute('aria-label')).toContain('Signature check failed');
    expect(badge.getAttribute('aria-label')).toContain('does not verify');
  });

  it('renders a neutral "Signature not verified" label for not_attempted with its reason', () => {
    render(<VerifiedBadge verdict="not_attempted" reason="no provenance in index" />);
    expect(screen.getByText('Signature not verified')).toBeTruthy();
    const badge = screen.getByText('Signature not verified').closest('span[data-tone]')!;
    expect(badge.getAttribute('data-tone')).toBe('not_attempted');
    expect(badge.getAttribute('title')).toContain('no provenance in index');
  });

  it('shows the as-of date from checkedAt in the title', () => {
    render(<VerifiedBadge verdict="pass" checkedAt="2026-08-29T12:00:00Z" />);
    const badge = screen.getByText('Signatures verified').closest('span[data-tone]')!;
    expect(badge.getAttribute('title')).toContain('2026-08-29');
  });

  it('wires aria-describedby to the given descriptionId, so a screen reader landing on the badge gets the qualifying text — never a tooltip', () => {
    render(
      <>
        <VerifiedBadge verdict="pass" descriptionId="signature-note" />
        <p id="signature-note">What the badges mean.</p>
      </>
    );
    const badge = screen.getByText('Signatures verified').closest('span[data-tone]');
    expect(badge?.getAttribute('aria-describedby')).toBe('signature-note');
  });

  it('omits aria-describedby entirely when no descriptionId is given, rather than pointing at nothing', () => {
    render(<VerifiedBadge verdict="pass" />);
    const badge = screen.getByText('Signatures verified').closest('span[data-tone]');
    expect(badge).toBeTruthy();
    expect(badge?.hasAttribute('aria-describedby')).toBe(false);
  });
});

describe('EffectiveStatusTag', () => {
  it('renders nothing for "active"', () => {
    const { container } = render(<EffectiveStatusTag status="active" />);
    expect(container.textContent).toBe('');
  });

  it.each([
    ['deprecated', 'Deprecated'],
    ['yanked', 'All versions yanked'],
    ['revoked', 'Revoked'],
  ] as const)('renders a visible label for "%s"', (status, expectedLabel) => {
    render(<EffectiveStatusTag status={status} />);
    expect(screen.getByText(expectedLabel)).toBeTruthy();
  });
});

describe('RevocationBanner', () => {
  it('uses role="alert" (assertive) for revoked — the most severe state', () => {
    render(<RevocationBanner severity="revoked" reason="compromised identity" />);
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain('compromised identity');
    expect(alert.getAttribute('aria-live')).toBe('assertive');
  });

  it('uses role="status" (polite) for all-versions-yanked — a step down in severity', () => {
    render(<RevocationBanner severity="yanked" reason="all versions had a critical bug" />);
    const status = screen.getByRole('status');
    expect(status.textContent).toContain('all versions had a critical bug');
    expect(status.getAttribute('aria-live')).toBe('polite');
  });
});

describe('StalenessBanner', () => {
  const DAY = 24 * 60 * 60 * 1000;

  it('renders nothing while the index is inside the warn threshold', () => {
    const { container } = render(
      <StalenessBanner indexAgeMs={STALENESS_BANNER_THRESHOLD_MS - DAY} />
    );
    expect(container.textContent).toBe('');
  });

  it('warns past the threshold (7-day window minus 24h grace), naming the days left', () => {
    render(<StalenessBanner indexAgeMs={STALENESS_BANNER_THRESHOLD_MS + DAY} />);
    const status = screen.getByRole('status');
    expect(status.textContent).toContain('7 days old');
    expect(status.textContent).toContain('will fail');
  });

  it('renders the full-window message when the index is at the verifier edge', () => {
    // Exactly at the 7-day window: zero days left, so the "within the next
    // N day(s)" clause drops and the banner names the failing build outright.
    render(<StalenessBanner indexAgeMs={STALENESS_WINDOW_MS} />);
    expect(screen.getByRole('status').textContent).toContain('next build will fail');
    expect(screen.getByRole('status').textContent).not.toContain('within the next');
  });
});

describe('CompatCell', () => {
  it('renders an explicit "Available" state, never blank', () => {
    render(
      <table>
        <tbody>
          <tr>
            <CompatCell os="linux" arch="amd64" available={true} />
          </tr>
        </tbody>
      </table>
    );
    expect(screen.getByText(/Available/)).toBeTruthy();
  });

  it('renders an explicit "Not available" state with a request link, never blank', () => {
    render(
      <table>
        <tbody>
          <tr>
            <CompatCell
              os="windows"
              arch="arm64"
              available={false}
              requestUrl="https://example.test/issues"
            />
          </tr>
        </tbody>
      </table>
    );
    expect(screen.getByText(/Not available/)).toBeTruthy();
    const link = screen.getByRole('link');
    expect(link.getAttribute('href')).toBe('https://example.test/issues');
  });

  it('renders "Not available" without a link when there is no repository to request against', () => {
    render(
      <table>
        <tbody>
          <tr>
            <CompatCell os="windows" arch="arm64" available={false} />
          </tr>
        </tbody>
      </table>
    );
    expect(screen.getByText(/Not available/)).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });
});
