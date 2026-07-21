# Phase 4 — Argus Assistant Rebuild — Design

**Date:** 2026-07-21
**Status:** Design (approved by user; 3 scope decisions + IsolationForest correction incorporated) → implementation plan.
**Context:** Phase 3 (all service layers) complete (origin/main tip `3e17c67`). Phase 4 rebuilds the **Argus assistant** — currently entangled inside the 1,006-line `Services/AVBrain.py` monolith and gated behind a local LLM. Master spec: `2026-07-17-zashiron-rebuild-design.md`. After Phase 4: Phase 5 (Swiss UI), then deferred real EMBER training + the C++ minifilter driver.

---

## 1. Problem — the current assistant's flaws

The assistant lives inside `AVBrain`, fused with an unrelated protection-**scoring** engine (IsolationForest anomaly scorer, protection-level recompute, LLM "assessment" loop, recovery loop). Concrete flaws:

1. **Entangled monolith** — the conversational assistant (soul/mind prompts, `chat()`, tool dispatch, chat history) is welded to the scoring engine in one giant class; two very different responsibilities.
2. **Duplicate chat history** — the Flask route keeps its own module-global `_ARIA_HISTORY`, *separate* from `AVBrain._chat_history` (the LLM uses one, `/api/aria/history` returns the other). Neither persists across restarts.
3. **Capability gated behind the LLM** — the deterministic tools (`get_threats`, `get_modules`, `block_ip`, …) only run if the local GGUF model emits an exact `[TOOL:name(arg)]` tag. With no model downloaded, Argus is a dead canned string — even though "show active threats" needs no model.
4. **Brittle** — regex tool parsing + two full inference passes; small local models format tags inconsistently.
5. **Persona/capability mismatch & dishonesty** — `soul.md` claims "I can run real scans" but there is no scan tool; `mind.md` advertises an **IsolationForest** anomaly model that is not a real/pre-trained model (it self-trains online only after ~50 minutes and fits on its own recent traffic). Argus would confidently tell users about a capability that effectively doesn't exist.

---

## 2. Decisions (user-approved)

- **Scope: assistant only.** Extract Argus into a clean standalone package; **leave AVBrain's scoring engine (IFEngine, `_recompute`, assessment/recovery loops, threat records) untouched.** Argus reads live state through existing public interfaces.
- **Capabilities: hybrid.** A tool registry usable **both** model-free (deterministic intent routing) **and** via the LLM. Real utility even without the GGUF model.
- **Action safety: read free, actions confirm.** Read/query tools run immediately; state-changing actions (block IP, whitelist, resolve threat) require an explicit in-chat confirmation first.
- **IsolationForest correction:** Argus will **not** claim or use the IsolationForest. Its context/tools never reference an IF anomaly score, and `mind.md` is corrected to describe the *actual* protection-level inputs. The `IFEngine`/AVBrain scoring code itself is **not** modified (out of scope).

---

## 3. Architecture

Extract the assistant into a new **`Argus/`** Python package (the folder already holds `soul.md`/`mind.md`). AVBrain keeps scoring; the assistant's chat/tool/prompt/history code is **removed** from AVBrain and rebuilt in `Argus/`.

**Shared LLM (no double model load):** the GGUF is already loaded once by `AVBrain` for its assessment loop. Add a minimal public accessor on `AVBrain` — `llm_chat(system, history, user_msg) -> str | None` (returns `None` when unavailable) and reuse the existing `is_llm_available()`. Argus calls these; it never constructs its own `Llama`, so the model loads exactly once.

**Data Argus reads (all already public):** `get_brain()` getters (`get_module_statuses`, `get_recent_events`, `get_threat_counts`, `get_blocked_count`, `get_total_threats`, `emit_block`); `get_avbrain()` getters (`get_active_threats`, `get_all_threats`, `resolve_threat`, `get_protection_level`, `is_llm_available`, new `llm_chat`). New tool dependencies: the shared `VirusScanner` (scan a file), `SentinelWhitelist` (whitelist), `SentinelCloudAnalysis`/`ThreatIntelStore` (hash/IP lookup).

### 3.1 Package layout — `Argus/` (5 modules + `__init__`)

| Module | Responsibility |
|--------|----------------|
| `Argus/__init__.py` | `get_argus()` singleton accessor (thread-safe). |
| `Argus/history.py` | `ConversationStore` — the single persisted conversation history (`~/.AriaSecurity/argus_history.json`): `append(role, content)`, `recent(n)`, `pairs(n)` (→ `[(user, assistant)]` for LLM), `clear()`. Atomic write. |
| `Argus/intents.py` | `parse_intent(msg) -> ToolCall \| None` — the **model-free** command grammar. Pure function. |
| `Argus/tools.py` | Tool registry. `Tool(name, description, kind: "read"\|"action", handler)`. `run(name, arg) -> str`. Read handlers query brain/scanner/cloud; action handlers perform the effect. Registry is the single source of truth for both intent routing and LLM tool-calling. |
| `Argus/context.py` | `build_context() -> str` — the live-state block (protection level, active-threat summary, module up/down) from real data. **No IsolationForest reference.** |
| `Argus/assistant.py` | `Argus` orchestrator: `chat(message) -> str`, system-prompt assembly (soul + mind + context), pending-action confirm state, LLM tool-call routing, graceful no-model path, `clear()`, `reload_prompts()`. |

### 3.2 Tool registry (initial set)

**Read (run immediately):**
`get_threats`, `get_modules`, `get_protection_level`, `get_recent_events[n]`, `get_stats`, `read_log <name>`, **`scan_file <path>`** (new — via `VirusScanner.scan_file`), **`lookup_ip <ip>`** (new — ThreatIntel/AbuseIPDB), **`lookup_hash <sha256>`** (new — CloudAnalysis/VirusTotal).

**Action (confirmation required):**
`block_ip <ip>` (→ `brain.emit_block`), `resolve_threat <id>` (→ `avbrain.resolve_threat`), **`whitelist_ip <ip>` / `whitelist_hash <sha256>`** (new — `SentinelWhitelist`).

Each tool carries `kind`. The orchestrator executes `kind=="read"` immediately and defers `kind=="action"` to the confirm flow. Handlers fail safe (missing dep / error → a clear string, never a crash). Read tools that need optional services (scanner, cloud) return "unavailable" if the service isn't loaded, mirroring the rest of the app.

### 3.3 Chat flow — `Argus.chat(message)`

1. **Pending-action resolution:** if a pending action exists → if the message is affirmative (`yes`/`y`/`confirm`/`do it`/`go ahead`) execute the pending tool and clear it; otherwise cancel it and continue treating the message as new input.
2. **Intent routing** (`parse_intent`):
   - **read** tool → run now; return the formatted result directly (deterministic — no LLM involved, so it works identically with or without the model).
   - **action** tool → set `_pending = (name, arg)`; return a confirmation prompt ("This will block 1.2.3.4 in the firewall. Confirm? (yes/no)").
3. **No intent match:**
   - **LLM available** → `avbrain.llm_chat(system, pairs, message)` where `system = soul + mind + context`. If the reply contains a validated tool call, route it through step 2's read/confirm logic (single, bounded second pass for read-tool results). Unknown/malformed tool tags are ignored (reply passed through).
   - **LLM unavailable** → a grounded deterministic reply: a one-line live-state summary (level, active-threat count, modules up) + "I can run these without the AI model: scan <path>, show threats, block <ip>, lookup <ip|hash>, read <log>. Download the AI model in Settings for full conversation."
4. **Persist:** append `user` then `assistant` turn to the `ConversationStore`.

### 3.4 Persona corrections (`Argus/soul.md`, `Argus/mind.md`)

- `mind.md`: remove the IsolationForest / ML-anomaly claims (Brain-Pipeline line, the "IsolationForest (IF)" section, the `IF_anomaly_score` input, the "IF anomaly + HIGH events" pattern). Replace with the **actual** protection-level model: `module_online_ratio − active_threat_penalties − mitigated_penalties (fading) + LLM_delta`. Update the tool list to the real registry (incl. `scan_file`, `lookup_*`, `whitelist_*`) and note action tools require confirmation.
- `soul.md`: keep the persona; ensure the "real tools / real actions" claims match the actual registry (they now will, once `scan_file` etc. exist).

---

## 4. Flask integration

- `/api/aria/chat` (POST) → background thread → `get_argus().chat(msg)` → `socketio.emit("aria_reply", {"reply": reply})`. **Remove `_ARIA_HISTORY`.**
- `/api/aria/history` (GET) → `get_argus().history.recent(40)` (list of `{role, content}`).
- `/api/aria/clear` (POST) → `get_argus().clear()` (kept — the Copilot UI has a clear action; preserves parity with the old `clear_chat_history`).

Keep the async fire-and-emit pattern (no streaming — that's Phase 5 UI territory).

---

## 5. AVBrain changes (minimal, justified)

- **Add** public `llm_chat(system, history, user_msg) -> str | None` delegating to the already-loaded `self._llm.chat(...)` (returns `None` if no engine). This lets Argus reuse the single model.
- **Remove** the assistant-only members that move to `Argus/`: `chat()`, `_build_aria_system()`, `_execute_tool()`, `_load_aria_prompts()`/`reload_aria_prompts()`, `clear_chat_history()`, `_chat_history`/`_chat_lock`, `_soul`/`_mind`, and the `_TOOL_RE` constant. Keep everything scoring-related (IFEngine, `_recompute`, `_llm_loop`, `_recovery_loop`, threat records, `get_active_threats`/`get_all_threats`/`resolve_threat`/`get_protection_level`, the `LLMEngine` wrapper it still uses for assessment).
- No change to `IFEngine` or the scoring math.

---

## 6. Error handling & data flow

**Flow:** UI → `/api/aria/chat` → `Argus.chat` → (intent | LLM) → tool registry → brain/scanner/cloud/whitelist → reply → socketio + persisted history. **Errors:** every tool handler fails safe (missing service → "unavailable"; exception → clear error string). No model → deterministic grounded reply, never a dead end. `ConversationStore` uses atomic writes so a crash can't corrupt history. Argus is a passive on-demand assistant — no background loop, no `BaseService`.

---

## 7. Testing (synthetic — LLM and services mocked; no real inference)

- `intents.parse_intent` — pure: each command form (`scan C:\x`, `show/active threats`, `block 1.2.3.4`, `lookup <hash>`/`<ip>`, `read psds log`, `whitelist ...`), plus no-match → `None`, and confirm words are NOT intents.
- `history.ConversationStore` — append/recent/pairs/clear round-trip + atomic persist against a `tmp_path` file; single source (no duplicate).
- `tools` — a read tool executes with a mocked brain/scanner and returns the expected string; an action tool's registration is `kind=="action"`; handler error → safe string; missing service → "unavailable".
- `context.build_context` — mocked brain/avbrain → contains level + threat count + module states; asserts **no** "IsolationForest"/"anomaly" text.
- `assistant.Argus.chat` — model-free path: read intent → executes tool; action intent → returns confirmation and does NOT execute; affirmative follow-up → executes pending; negative → cancels; no-model no-intent → grounded reply listing commands; LLM path with a mocked `llm_chat` → returns/narrates; a mocked LLM tool-call for an action → still requires confirm.
- Flask: `/api/aria/history` and `/api/aria/clear` delegate to the store; `_ARIA_HISTORY` removed.

## 8. Verification

- `.venv/Scripts/python.exe -m pytest tests/ -q` → green (existing 125 + new Argus tests).
- `scripts/verify_reachability.py` → the new `Argus/*` modules become LIVE (imported by the entry file via `Argus/__init__`); bump `EXPECTED_LIVE` to the printed value; PASS. No live module under `cleanup/`.
- Headless boot → HTTP 200; `/api/aria/chat` returns a grounded reply with the model absent.

## 9. Deferred / future

- Phase 5 (Swiss #000/#FFF UI) — may add streaming replies.
- Real EMBER training (mid-size → full 2018) + the C++ minifilter driver (final phase).
- Follow-up carried forward: retire the now-dead `UsbAllowlistPage.py`.
- Possible future: extend the action registry (quarantine, kill process via `process_monitor.kill`) behind the same confirm flow.
