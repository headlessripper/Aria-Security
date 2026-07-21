# Phase 5 — Swiss UI Redesign — Design

**Date:** 2026-07-21
**Status:** Design (user delegated: "continue") → implementation plan.
**Context:** Final phase of the Aria Security rebuild's UI work (origin/main tip `fedc2cc`). The app is a single-page Flask UI in `templates/index.html` (3,036 lines): ~200 lines of inline CSS design tokens + component classes (lines 10–214), ~1,050 lines of HTML (28 `.page` views + icon sidebar + menu overlay + topbar), and one ~1,770-line inline `<script>`. Current look is GitHub-dark (bg `#080c10`, blue `#2f81f7`, rounded cards, gradients). This phase reskins it to a Swiss / International Typographic Style system in true black/white. After Phase 5: deferred real EMBER training, then the C++ minifilter driver.

---

## 1. Goal & approach

Reskin the entire UI to a Swiss design system — strict grid, generous whitespace, strong typographic hierarchy, near-monochrome with reserved semantic color, Helvetica-family type, crisp rectangles, hairline borders, no gradients/glows.

**Approach: CSS-system restyle, not a rebuild.** Rewrite the centralized design tokens and component classes; **keep the HTML page structure and all Phase 1–4 JS logic intact.** HTML is edited only where the grid genuinely requires it (e.g. removing a decorative gradient element). This preserves every working feature and keeps the blast radius in the `<style>` block.

**Non-goals:** no behavior/logic changes; no new pages; no route changes; no dependency on any CDN (all assets self-hosted); no JS rewrite (only additive: theme-toggle handler).

---

## 2. Design language

### 2.1 Palette — true monochrome + reserved semantic color

The accent-vs-status conflict is resolved deliberately: in a security UI **red must mean danger**, so the decorative/interactive accent is NOT red.

- **Core is monochrome.** Dark theme: bg `#000000`. Light theme: bg `#FFFFFF`. Plus a precise neutral grey scale for surfaces, hairline borders, and dim/muted text. All structural chrome (sidebar, topbar, cards, tables, menu, buttons) is monochrome.
- **One interactive accent** — a flat International blue (`--accent`), used *only* for interactive affordances: active nav item, links, input focus ring, primary action button. Never decorative.
- **Semantic status colors, reserved for security state only** — green (protected / clean / module-up), amber (warning / degraded), red (threat / critical / module-down / block). Color always *means* something.

Token sets (both themes fully specified; light is not an afterthought):

```
DARK  (:root)                         LIGHT (:root[data-theme="light"])
--bg:        #000000                   #FFFFFF
--surface:   #0a0a0a                   #f5f5f5
--card:      #0f0f0f                   #ffffff
--border:    #262626 (hairline)        #e0e0e0
--text:      #f5f5f5                   #0a0a0a
--dim:       #a3a3a3                   #525252
--muted:     #666666                   #a3a3a3
--accent:    #1a56ff (flat blue, same or lightly tuned per theme for contrast)
--green:     #16a34a/#22c55e   --amber:#d97706/#f59e0b   --red:#dc2626/#ef4444
```
(Exact hex finalized during implementation against WCAG AA contrast on each theme; the *structure* — monochrome core + one blue accent + three reserved status hues — is fixed.)

### 2.2 Typography — the primary design device

- **Vendor Inter** self-hosted (woff2, weights 400/600/800) under `static/fonts/`; the CSS already names `Inter`. Fallback stack `"Inter", "Helvetica Neue", Arial, system-ui, sans-serif`. Honors the no-CDN rule.
- **Type scale** (8px-based rhythm): page title 28–32px/800 tight tracking; section label 11px/700 uppercase +letterspacing; body 13–14px/400; stat number 40px/800 tabular-nums; mono (console/log/textarea) `"JetBrains Mono","Consolas",monospace`.
- Flush-left, ragged-right. Tight negative tracking on large headings; positive tracking on small uppercase labels.

### 2.3 Form & spacing

- **Border-radius: 0** on structural surfaces (cards, buttons, inputs, nav items, badges) — crisp Swiss rectangles. (One small exception permitted: the circular status dots / gauge remain round.)
- **1px hairline borders** everywhere; no shadows except a single subtle toast elevation.
- **No gradients / glows** — the sidebar `.nav-logo` gradient becomes a flat monochrome mark; active-nav glow removed.
- **8px spacing grid** — paddings/gaps snap to multiples of 4/8.
- Motion restrained (≤120ms, opacity/position only).

---

## 3. Theme system

- `:root` holds the dark tokens (default). `:root[data-theme="light"]` overrides with the light set.
- A **topbar toggle** (small sun/moon icon button) flips `document.documentElement.dataset.theme` between `dark`/`light` and persists to `localStorage["aria-theme"]`; on load, the stored theme (default dark) is applied before first paint.
- All component colors reference tokens only (no hard-coded hex in component rules) so both themes work from one rule set.

---

## 4. Component treatments (the full inventory to restyle)

Every existing class keeps its **name and selector** (the JS toggles these classes); only the rules change.

- **Shell** — `#sidebar` (flat monochrome, hairline right border), `.nav-logo` (flat square mark, no gradient), `.nav-btn` (square, monochrome; `.active` = accent left-bar + accent icon, no glow), tooltip `::after` (square, hairline). `#topbar` (hairline bottom, add theme-toggle + keep title/badge/status-dot). `#topbar-badge` → squared, monochrome or accent outline.
- **Menu overlay** — `#menu-panel` flat surface, `.menu-item` square, `.active` = accent text + left bar; `.menu-section-lbl` uppercase muted.
- **Pages** — `.pg-title` big/800/tight; `.sec-label` uppercase muted; `.card` square, hairline, flat surface, grid padding.
- **Stats** — `.stat-num` 40px/800 tabular; `.stat-lbl` muted.
- **Badges/buttons** — `.badge` square; `.btn` square, 0 radius; `.btn-primary` accent bg; `.btn-ghost` hairline; `.btn-danger`/`.btn-green` use reserved status colors as outline/text (flat, no tint gradients).
- **Inputs** — `.inp` square, hairline, `:focus` accent border; `textarea.inp` mono.
- **Tables** — `.tbl` hairline rows, uppercase th, hover = faint neutral.
- **Feed / modules / country grid** — `.feed-row`, `.mod-card` (square; `.active` = green hairline/text, no tint bg), `.country-card` (square; `.blocked` = red hairline/text).
- **Argus chat** — `.chat-msg.user` (accent-outline or filled square bubble, minimal radius), `.chat-msg.aria` (surface, hairline). Keep readable line-height.
- **Progress / spinner / dots / gauge** — accent progress fill; spinner accent; status dots keep semantic colors + stay circular.
- **Toasts** — square, hairline, left-border in the semantic color (success=green, error=red, info=accent); single subtle shadow allowed.

---

## 5. Data flow & error handling

Pure presentation change. No API, socket, or JS-logic change beyond the additive theme-toggle handler. The theme toggle degrades safely (if `localStorage` is unavailable, defaults to dark). All 28 pages render from the same restyled component classes.

---

## 6. Testing & verification (visual — no unit tests for aesthetics)

This phase is verified in the **in-app browser preview**, not pytest:
- Boot the Flask dev server; load the app.
- **Console clean** (`read_console_messages` — no JS errors introduced).
- **Screenshot representative pages in BOTH themes:** dashboard, a data-table page (Task Manager / Connections), the Argus/Copilot chat, a form page (Whitelist / Scan), Console. Confirm Swiss look (monochrome, square, hairline, type hierarchy) and that nothing is unreadable/broken in light or dark.
- **Theme toggle** flips and persists across reload.
- **Regression gates:** headless boot HTTP 200; `scripts/verify_reachability.py` PASS (UI-only change → `EXPECTED_LIVE` unchanged at 45); existing `tests/services/` suite still green (untouched by UI work).

---

## 7. Deferred / future

- Real EMBER model training (mid-size → full 2018) and the C++ minifilter driver (final phase).
- Follow-ups carried forward: retire dead `cleanup/qt-ui/UsbAllowlistPage.py` and the stale `CopilotPage.py` Argus calls.
- Optional later: streaming Argus replies in the chat view.
