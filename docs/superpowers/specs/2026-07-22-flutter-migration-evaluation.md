# Windows Client UI: WebView → Flutter — Evaluation & Migration Plan

**Date:** 2026-07-22
**Status:** Evaluation for a decision. **No implementation** — per the request, this is the feasibility/effort/approach analysis to review *before* any migration work.

---

## 1. What we have today (measured, not estimated)

| Layer | Detail |
|---|---|
| Shell | `pywebview` frameless native window hosting a local Flask server on `127.0.0.1:8765` |
| UI | **one** file, `templates/index.html` — 2,894 lines |
| ↳ inline JS | 77,869 chars / 1,731 lines · 78 functions · 23 page refreshers |
| ↳ inline CSS | 10,683 chars (Swiss design system, now a single light theme) |
| Pages | **23** SPA pages, client-side router (`navigate()` + `Refresher`) |
| Backend API | **83** REST routes + **24** socket.io emit sites |
| UI→API coupling | **69** `api()` calls + **13** `socket.on` handlers |
| Backend (stays as-is) | ~10,335 LOC Python: engine (ONNX/LightGBM/LIEF/YARA), 12 services, Argus, monitors |
| Vendored assets | `static/socket.io.min.js`, local fonts (no CDN) |

**The single most important architectural fact:** the UI is already a *pure client*. It touches the backend only over HTTP + WebSocket; the Flask layer contains no UI logic beyond serving one template. Nothing in `Engine/`, `Services/`, or `Argus/` knows a WebView exists.

**Consequence:** a Flutter client is a **client-side-only project**. The API it would consume already exists and is already the contract. That is what makes this feasible at all.

---

## 2. Feasibility: high — with one significant catch

**Feasible.** Flutter's Windows desktop target is stable, and every capability the UI needs has a mature Dart equivalent:

| Need | Dart/Flutter equivalent |
|---|---|
| 83 REST endpoints | `dio` / `http` + generated models |
| 13 socket.io events | `socket_io_client` (works against Flask-SocketIO) |
| Charts/gauges | `fl_chart` / custom painters |
| Native file/folder pickers | `file_selector` / `file_picker` — *better than today's server-side tkinter shim* |
| Tray, notifications, window chrome | `tray_manager`, `local_notifier`, `window_manager` |

**The catch: the Python backend cannot go away.** The detection engine is Python (ONNX Runtime, LightGBM, LIEF, YARA), as are all 12 services, Argus, and the minifilter bridge. Flutter cannot host them. So the migration converts a **one-process** app (Python serves UI + logic in one window) into a **two-process** app (Flutter UI ⟷ bundled Python backend).

That two-process shift — not the UI rewrite — is the real engineering burden:

- Bundle the Python runtime (PyInstaller; onnxruntime + lightgbm + lief make this a heavy, fiddly bundle).
- Spawn, supervise, health-check and shut down the backend from Flutter.
- Dynamic port selection + handshake (8765 may be taken).
- **Elevation**: an AV needs admin; today one elevated process covers everything. Split, you must decide who elevates and how the UI talks to an elevated backend.
- Single-instance enforcement, crash recovery, orphaned-process cleanup, first-run firewall prompts.

Migrations like this usually fail here, not in the widget code.

---

## 3. The three options

### Option A — Wrap the existing web app in a Flutter WebView
Flutter shell (`webview_windows`) pointing at the same Flask server.

- **Effort:** ~3–5 days.
- **Gains:** Flutter's shell ecosystem (tray, notifications, updater, native menus).
- **Reality check:** you are still shipping a WebView, now with a Flutter runtime *on top of* it. `pywebview` already provides a native frameless window. **The net gain over today is close to zero**, while adding a second runtime and the two-process problem.
- **Verdict:** not worth it as a goal in itself.

### Option B — Full native Flutter rewrite (recommended *if* migrating)
Rebuild all 23 pages as Flutter widgets against the existing API.

- **Gains:** no WebView2 runtime dependency; consistent native rendering; genuine native controls and pickers; better packaging/update story; real offline-installer story.
- **Costs:** rewrite 1,731 lines of JS + the CSS design system in Dart; re-implement the router, 23 refreshers, 13 socket handlers, 69 API calls; plus the two-process work above.

### Option C — Incremental hybrid (Flutter shell, pages migrated one at a time)
- **Verdict:** avoid. Two rendering models with shared nav/auth/socket state is more work than either endpoint, and the "temporary" WebView reliably becomes permanent.

---

## 4. Effort estimate for Option B (single focused developer)

| Workstream | Estimate | Notes |
|---|---|---|
| API client + models (83 routes, 69 call sites) | 1 week | Mechanical; can be partly generated |
| Socket.io layer + 13 event handlers | 2–3 days | `socket_io_client` against Flask-SocketIO |
| Design system → `ThemeData` + shell/nav | 1 week | Simplified now that dark theme is gone |
| **23 pages** | **3–5 weeks** | Tables/lists are ~½ day; Dashboard gauge, Argus chat, live Console, Sense data tree, USB guard are 2–3 days each |
| **Backend packaging + process supervision + elevation** | **1–2 weeks** | Highest-risk item; see §2 |
| Installer, signing, auto-update | 1 week | |
| Stabilization / QA across 23 pages | 1–2 weeks | |
| **Total** | **≈ 8–12 weeks** | Excludes new features; this buys parity with what already works |

Add meaningful risk buffer to the packaging line — it is the item most likely to double.

---

## 5. Recommendation

**Do not start a full Flutter rewrite now.** Reasoning:

1. **The UI is not the problem.** It was just rebuilt (Swiss redesign, 23 working pages, live-verified). A rewrite spends ~2–3 months to arrive back at today's functionality.
2. **It cannot remove Python**, so it does not simplify the stack — it *adds* a process boundary, packaging burden, and an elevation question that is currently solved for free.
3. **The concrete pains are individually addressable.** If the motivation is:
   - *native file dialogs* → **already done** (`/api/pick`, this session);
   - *tray/notifications/native chrome* → achievable from pywebview or a thin native shell;
   - *WebView2 runtime dependency* → the one genuine argument for Flutter;
   - *rendering inconsistency* → mostly resolved by the Swiss single-theme redesign.

**If the decision is to migrate anyway** (a legitimate long-term "own the native client" strategy), then:

- Choose **Option B**, not A or C.
- **Precondition — do a 1-week spike on §2 first**, before any widget work: bundle the Python backend with PyInstaller, launch/supervise it from a trivial Flutter window, prove elevation and dynamic-port handshake, and measure installer size and cold-start time. If that spike is ugly, the migration is not worth it and you will have spent one week, not eight.
- Freeze UI feature work during the migration, or you will build every feature twice.
- Migrate in dependency order: API/socket layer → shell/nav/theme → simple table pages → complex interactive pages.

**Suggested immediate next step:** none, unless you want the WebView2 dependency gone. If you do, authorize the 1-week packaging spike and decide based on its outcome.

---

## 6. What would need to change in this repo (for reference)

Nothing in `Engine/`, `Services/`, `Argus/`, or the minifilter — they are UI-agnostic. Only these are UI-coupled:

- `templates/index.html` (the entire client — replaced)
- `SentinelUI_Flask.py`: the `/` route, template serving, and the `pywebview` window bootstrap (`webview.create_window`) would go; **the 83 API routes and 24 socket emits stay exactly as they are** and become the Flutter app's contract.
- `static/` (socket.io + fonts) — no longer needed by a native client.
