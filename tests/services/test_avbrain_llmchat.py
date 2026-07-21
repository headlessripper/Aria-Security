from Services.AVBrain import AVBrain


def test_llm_chat_none_when_no_engine():
    av = AVBrain.__new__(AVBrain)   # bypass __init__/model load
    av._llm = None
    assert av.llm_chat("sys", [], "hi") is None


def test_llm_chat_delegates_when_engine_present():
    av = AVBrain.__new__(AVBrain)
    class _Eng:
        available = True
        def chat(self, system, history, user_msg, **k):
            return f"reply:{user_msg}"
    av._llm = _Eng()
    assert av.llm_chat("sys", [], "ping") == "reply:ping"


def test_assistant_members_removed():
    # the assistant code moved to Argus/ — these must no longer exist on AVBrain
    for gone in ("_build_aria_system", "_execute_tool", "_load_aria_prompts",
                 "clear_chat_history", "reload_aria_prompts"):
        assert not hasattr(AVBrain, gone), f"{gone} should have moved to Argus/"
