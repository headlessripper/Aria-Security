import types
import Argus.assistant as A
from Argus.history import ConversationStore
from Argus.intents import ToolCall


def _make(tmp_path, llm_fn=None, monkeypatch=None):
    store = ConversationStore(tmp_path / "h.json")
    return A.Argus(store=store, llm_fn=llm_fn or (lambda s, p, m: None))


def test_read_intent_runs_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("get_threats", ""))
    monkeypatch.setattr(A.tools, "run", lambda n, a: "TOOL_OUTPUT")
    ag = _make(tmp_path)
    assert ag.chat("show threats") == "TOOL_OUTPUT"


def test_action_intent_asks_confirmation_and_does_not_execute(tmp_path, monkeypatch):
    ran = {"n": 0}
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("block_ip", "1.2.3.4"))
    monkeypatch.setattr(A.tools, "run", lambda n, a: ran.update(n=ran["n"] + 1) or "BLOCKED")
    ag = _make(tmp_path)
    reply = ag.chat("block 1.2.3.4")
    assert "confirm" in reply.lower() and ran["n"] == 0


def test_confirmation_executes_pending(tmp_path, monkeypatch):
    seq = iter([ToolCall("block_ip", "1.2.3.4"), None])
    monkeypatch.setattr(A, "parse_intent", lambda m: next(seq))
    monkeypatch.setattr(A.tools, "run", lambda n, a: "BLOCKED " + a)
    ag = _make(tmp_path)
    ag.chat("block 1.2.3.4")            # arms pending
    out = ag.chat("yes")                # confirms
    assert out == "BLOCKED 1.2.3.4"


def test_negative_cancels_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("block_ip", "1.2.3.4") if "block" in m else None)
    monkeypatch.setattr(A.tools, "run", lambda n, a: "SHOULD_NOT_RUN")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: None)
    ag.chat("block 1.2.3.4")
    out = ag.chat("no")
    assert "SHOULD_NOT_RUN" not in out and "cancel" in out.lower()


def test_no_model_no_intent_gives_grounded_reply(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "Protection level: 88%")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: None)   # no model
    out = ag.chat("how are things?")
    assert "88%" in out and "scan" in out.lower()       # grounded + lists commands


def test_llm_path_returns_conversational_reply(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "ctx")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: "Here is my analysis.")
    assert ag.chat("what do you think?") == "Here is my analysis."


def test_history_is_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "ctx")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: "reply")
    ag.chat("hi")
    assert ag.history.recent(10)[-1] == {"role": "assistant", "content": "reply"}


def test_concurrent_chats_do_not_corrupt_history(tmp_path, monkeypatch):
    """The per-instance lock serializes the threaded /api/aria/chat route so
    concurrent turns can't drop or interleave history writes."""
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "ctx")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: "r")
    import threading as _T
    threads = [_T.Thread(target=ag.chat, args=(f"m{i}",)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 20 chats × (user + assistant) = 40 turns, none lost to a race
    assert len(ag.history.recent(100)) == 40
