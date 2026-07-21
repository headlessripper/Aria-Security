# Phase 5 — Swiss UI Redesign Implementation Plan

> **For agentic workers:** This is a VISUAL phase executed INLINE with the in-app browser preview (superpowers:executing-plans style), not blind subagents — all edits land in one `<style>` block in `templates/index.html`, and each cluster is verified by a browser screenshot in both themes. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reskin the entire Aria Security UI (`templates/index.html`) to a Swiss / International Typographic Style system — true black (`#000`) dark theme + true white (`#FFF`) light theme, monochrome core with one blue interactive accent and reserved semantic status color, Inter type, crisp square forms, hairline borders, no gradients/glows — without changing any HTML structure or JS logic.

**Architecture:** Rewrite the centralized CSS tokens + component classes (lines ~10–214) and vendor Inter under `static/fonts/`. Add one additive theme-toggle handler to the inline JS. Every existing class keeps its name/selector (the JS toggles them); only the rules change. Values are tuned against live rendering.

**Tech Stack:** HTML/CSS (inline `<style>`), a few lines of vanilla JS, self-hosted Inter woff2, the in-app browser preview + Flask dev server.

## Global Constraints

- Self-hosted assets only — **no CDN** (vendor Inter woff2 locally).
- **No behavior/logic change** — HTML structure and the ~1,770-line inline `<script>` stay; JS change is limited to an additive theme-toggle handler.
- Every component class keeps its existing **name and selector**.
- All component rules reference CSS **tokens** (no hard-coded hex in component rules) so both themes work from one rule set.
- **Palette discipline:** monochrome core; ONE blue `--accent` for interactivity only; green/amber/red reserved for security status only (red never decorative).
- **Swiss form:** border-radius 0 on structural surfaces (dots/gauge stay round); 1px hairline borders; no gradients/glows; 8px spacing rhythm; motion ≤120ms.
- Contrast: text/interactive elements meet WCAG AA on both themes.
- Never `git add` any `.exe`/`.ips`/`.onnx`/PE binary; do not touch `.venv/`, `cleanup/`, `.superpowers/`, `Config/sentinel_whitelist.json` (checkout before commit if it shows modified). Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1: Foundation — vendor Inter, dark tokens, reset, typography

**Files:** `static/fonts/*` (add Inter woff2 + @font-face css), `templates/index.html` (tokens + reset).

- [ ] Vendor Inter: add `static/fonts/inter-400.woff2`, `inter-600.woff2`, `inter-800.woff2` (subset OK) and an `@font-face` block (in the inline `<style>` or a small `static/fonts/inter.css` linked like material-icons). If a clean Inter woff2 can't be obtained offline, fall back to the system stack `"Helvetica Neue", Arial, system-ui` and note it — the Swiss look must still hold.
- [ ] Rewrite `:root` dark tokens:
```css
:root{
  --bg:#000000; --surface:#0a0a0a; --card:#0f0f0f; --border:#262626;
  --accent:#2b6bff; --green:#22c55e; --amber:#f59e0b; --red:#ef4444;
  --text:#f5f5f5; --dim:#a3a3a3; --muted:#666666; --sw:64px;
  --font:"Inter","Helvetica Neue",Arial,system-ui,sans-serif;
  --mono:"JetBrains Mono","Consolas",monospace;
}
```
- [ ] Reset/base: `font-family:var(--font)`; keep overflow/scrollbar; set crisp rendering; ensure `border-radius:0` is the default for structural elements (apply per-component, not globally).
- [ ] **Verify:** start the dev server, load the app, `read_console_messages` (no errors), screenshot the dashboard — confirm black bg + Inter type render. Commit `Phase 5 Task 1: Swiss foundation — Inter + dark tokens + reset`.

### Task 2: Shell — sidebar, menu, topbar + theme toggle

**Files:** `templates/index.html` (shell CSS + topbar toggle button + JS handler).

- [ ] Restyle `#sidebar` (flat, hairline right border), `.nav-logo` (flat monochrome square mark — remove the gradient), `.nav-btn` (square; `.active` = accent left-bar + accent icon, remove glow), tooltip `::after` (square, hairline), `#nav-spacer`.
- [ ] Restyle `#menu-overlay`/`#menu-panel`/`.menu-item` (square; `.active` = accent text + left bar), `.menu-section-lbl` (uppercase muted).
- [ ] Restyle `#topbar` (hairline bottom), `#topbar-title`, `#topbar-badge` (squared, monochrome/accent outline), `#status-dot`/`#status-text`.
- [ ] Add a **theme toggle** button in the topbar (sun/moon material icon) + JS:
```js
(function(){
  var root=document.documentElement, KEY="aria-theme";
  function set(t){root.dataset.theme=t; try{localStorage.setItem(KEY,t)}catch(e){}}
  var saved="dark"; try{saved=localStorage.getItem(KEY)||"dark"}catch(e){}
  set(saved);
  window.__toggleTheme=function(){set(root.dataset.theme==="light"?"dark":"light")};
})();
```
Wire the button to `__toggleTheme()`.
- [ ] **Verify:** screenshot shell (nav + topbar + menu open) in dark; confirm toggle button present. Commit `Phase 5 Task 2: Swiss shell + theme toggle`.

### Task 3: Core components — titles, cards, stats, badges, buttons, inputs

**Files:** `templates/index.html` (component CSS).

- [ ] `.pg-title` (28–32px/800, tight tracking), `.sec-label` (11px/700 uppercase), `.card` (square, hairline, flat `--card`, grid padding), `.row`/`.col`.
- [ ] `.stat-num` (40px/800, `font-variant-numeric:tabular-nums`), `.stat-lbl`.
- [ ] `.badge` (square), `.btn` (square, 0 radius; keep hover/active subtle), `.btn-primary` (accent bg, white text), `.btn-ghost` (hairline), `.btn-danger`/`.btn-green` (status color as text + hairline, flat), `.btn-sm`, `:disabled`.
- [ ] `.inp` (square, hairline, `:focus` accent border), `textarea.inp` (`var(--mono)`).
- [ ] **Verify:** screenshot Dashboard + Scan pages (dark) — cards/stats/buttons/inputs Swiss. Commit `Phase 5 Task 3: Swiss core components`.

### Task 4: Data components — tables, feeds, cards, chat, feedback

**Files:** `templates/index.html` (component CSS).

- [ ] `.tbl` (hairline rows, uppercase th, faint neutral hover), `.feed-row`, `.dot` (round, semantic).
- [ ] `.mod-card` (square; `.active` = green hairline + green status text, no tint bg), `.country-grid`/`.country-card` (square; `.blocked` = red hairline + red text), `.gauge-wrap`.
- [ ] Argus `#chat-messages`, `.chat-msg.user` (accent-filled or accent-outline square bubble, small radius allowed for legibility), `.chat-msg.aria` (surface + hairline).
- [ ] `.progress-bar`/`-wrap` (accent fill), `.spinner` (accent), `#toast-container`/`.toast` (square, hairline, semantic left-border, single subtle shadow).
- [ ] **Verify:** screenshot Task Manager/Connections (table), Console, Argus chat (dark). Commit `Phase 5 Task 4: Swiss data components`.

### Task 5: Light theme

**Files:** `templates/index.html` (light token block).

- [ ] Add `:root[data-theme="light"]` overrides:
```css
:root[data-theme="light"]{
  --bg:#ffffff; --surface:#f5f5f5; --card:#ffffff; --border:#e0e0e0;
  --accent:#1a4fd6; --green:#16a34a; --amber:#d97706; --red:#dc2626;
  --text:#0a0a0a; --dim:#525252; --muted:#a3a3a3;
}
```
- [ ] Audit every component for hard-coded colors (e.g. `.btn-primary` white text on accent must stay readable; toast bg; chat bubbles) and convert any stray hex to tokens so light theme is correct.
- [ ] Tune hex for WCAG AA on white (accent, dim, muted, status).
- [ ] **Verify:** toggle to light; screenshot Dashboard, a table page, Argus, Console, a form — confirm nothing unreadable/broken; toggle persists across reload. Commit `Phase 5 Task 5: Swiss light theme`.

### Task 6: Full verification pass

- [ ] Screenshot the five representative pages (Dashboard, Task Manager/Connections, Argus, Whitelist/Scan, Console) in **both** themes; confirm consistent Swiss system.
- [ ] `read_console_messages` clean across navigation (no JS errors introduced).
- [ ] Headless boot → HTTP 200.
- [ ] `.venv/Scripts/python.exe scripts/verify_reachability.py` → PASS (UI-only; `EXPECTED_LIVE` unchanged at 45).
- [ ] `.venv/Scripts/python.exe -m pytest tests/services/ -q` → still green (UI untouched by tests).
- [ ] Commit any final polish `Phase 5 Task 6: Swiss UI verification + polish`.

---

## Self-Review

**Spec coverage:** palette/tokens+themes → T1/T5; typography/Inter → T1; theme toggle+persist → T2; shell → T2; all component classes in the spec's §4 inventory → T3 (titles/cards/stats/badges/buttons/inputs) + T4 (tables/feeds/mod/country/chat/progress/spinner/toast); light theme → T5; verification (browser screenshots both themes, console clean, boot 200, reachability, suite) → T6. No spec item unmapped.

**Placeholder scan:** token/JS/light CSS given as real code; exact hex explicitly "tuned live for WCAG AA" (a design activity, not a placeholder). Inter vendoring has a stated offline fallback.

**Consistency:** token names (`--bg/--surface/--card/--border/--accent/--green/--amber/--red/--text/--dim/--muted/--font/--mono`) are used identically across T1/T3/T4/T5; every component references tokens so the T5 light block flips the whole UI.
