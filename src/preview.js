/**
 * The Gated Shifter — preview build.
 *
 * PREVIEW_MODE=true turns the deployment into a review copy:
 *
 *   1. A fixed bar across the bottom of every page saying the build is for
 *      review and not licensed for commercial use. Visible in any screenshot,
 *      so nobody can mistake a preview for a launched site, and nobody can
 *      quietly put it in front of real customers.
 *   2. Every application submitted while it is on is tagged campaign='preview'
 *      in the database, so test records are obvious in the export and can be
 *      cleared in one statement before launch:
 *
 *        delete from member_intake where campaign = 'preview';
 *
 * It changes nothing else. Forms, emails, the database, the admin portal and
 * the export all work exactly as they will on launch day, which is the point —
 * the client needs to test the real thing.
 *
 * Turn it off by setting PREVIEW_MODE=false, or deleting the variable.
 */

import { readFile } from 'node:fs/promises';
import { join, normalize } from 'node:path';

export const previewEnabled = String(process.env.PREVIEW_MODE || '').toLowerCase() === 'true';

const NOTICE =
  process.env.PREVIEW_NOTICE ||
  'Preview build — for review and testing only. Not licensed for commercial use.';

const BANNER = `
<div id="preview-bar" role="status" style="
  position:fixed;left:0;right:0;bottom:0;z-index:2147483647;
  background-color:#A8474B;color:#F5F3F0;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  font-size:10px;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;
  line-height:1.5;padding:10px 16px;text-align:center;
  box-shadow:0 -1px 0 rgba(0,0,0,0.35);">
  ${NOTICE}
</div>
<div style="height:38px;" aria-hidden="true"></div>
`;

/** Inserts the bar just before </body>. Leaves anything else alone. */
export function withBanner(html) {
  if (!previewEnabled) return html;
  const at = html.lastIndexOf('</body>');
  if (at === -1) return html + BANNER;
  return html.slice(0, at) + BANNER + html.slice(at);
}

/**
 * Serves the HTML pages with the banner injected. Mounted ahead of
 * express.static so the static handler never returns an un-bannered copy.
 * Only ever reads files inside publicDir.
 */
export function previewPages(publicDir) {
  return async function previewMiddleware(req, res, next) {
    if (!previewEnabled) return next();
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();

    // Which file would this path resolve to?
    const path = req.path === '/' ? '/index.html' : req.path;
    const candidate = path.endsWith('.html') ? path : `${path}.html`;
    const full = normalize(join(publicDir, candidate));
    if (!full.startsWith(normalize(publicDir))) return next();

    try {
      const html = await readFile(full, 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      return res.send(withBanner(html));
    } catch {
      return next(); // not a page — let the normal handlers deal with it
    }
  };
}

/** Tags anything submitted during the review period as test data. */
export function tagPreviewData(data) {
  if (!previewEnabled) return data;
  return { ...data, campaign: 'preview' };
}

export function describePreview() {
  return previewEnabled
    ? 'preview mode: ON — banner shown, submissions tagged campaign=preview'
    : 'preview mode: off';
}