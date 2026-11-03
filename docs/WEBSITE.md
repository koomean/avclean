# Project website

The public site at <https://avclean.koomean.com/> is a buildless HTML/CSS/JavaScript
page. GitHub Pages publishes the repository root on `main`. Keep the root `CNAME`
and `.nojekyll` files. No npm dependencies, separate hosting service or deployment
workflow are required.

## Edit and preview

```sh
python3 -m http.server 8765 --bind 127.0.0.1
```

Open <http://127.0.0.1:8765/>. Copy, language, demo tabs, installation tabs,
keyboard navigation and mobile navigation are implemented in `assets/site.js`.
The Thai HTML remains readable before JavaScript loads. English is available with
the language button or `?lang=en`; only the language preference is stored locally.
The site has no analytics, third-party JavaScript, or external font requests.

Keep product claims aligned with the CLI and README. The terminal screens and
coverage example are explicitly illustrative. Update the release link, version,
test count and structured metadata together when the packaged app changes.

## Assets and references

The vector logo, file illustrations and social card are original code assets.
`assets/social-card.svg` is the editable source for the 1200 × 630 JPEG used by
Open Graph previews. `assets/favicon.svg` is the site icon.

Outfit and IBM Plex Sans Thai are self-hosted under `assets/fonts/`. Their original
SIL Open Font License files and copyright notices are included in that directory.

Design references: [Ghostty](https://ghostty.org/) for a product-first terminal
presentation, [Linear](https://linear.app/) for spacing and information hierarchy,
and [Raycast](https://www.raycast.com/) for clear developer-tool onboarding. No
brand assets, product screenshots or copy from those sites are included.

## Before publication

- Run `node --check assets/site.js` and check local asset/anchor references.
- Inspect Thai and English at mobile, tablet and desktop widths, including long
  commands. Check for horizontal page overflow.
- Verify clipboard output by pasting the copied command, not just observing the
  success toast. Check both single- and multi-line commands.
- Exercise tab arrows/Home/End, mobile menu/Escape, language switching and FAQ.
- Verify the Pages build for the pushed commit and the public HTTPS page/assets.

Website changes do not require an application release or changes to Homebrew's
pinned source tag.
