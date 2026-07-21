from Argus.history import ConversationStore


def test_append_and_recent_roundtrip(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "hi")
    s.append("assistant", "hello")
    r = s.recent(10)
    assert r == [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]


def test_persists_across_instances(tmp_path):
    p = tmp_path / "h.json"
    ConversationStore(p).append("user", "remember me")
    assert ConversationStore(p).recent(10) == [{"role": "user", "content": "remember me"}]


def test_recent_limit(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    for i in range(50):
        s.append("user", str(i))
    assert len(s.recent(5)) == 5
    assert s.recent(5)[-1]["content"] == "49"


def test_pairs_builds_user_assistant_tuples(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "q1"); s.append("assistant", "a1")
    s.append("user", "q2"); s.append("assistant", "a2")
    assert s.pairs(8) == [("q1", "a1"), ("q2", "a2")]


def test_clear(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "x")
    s.clear()
    assert s.recent(10) == []


def test_corrupt_file_starts_empty(tmp_path):
    p = tmp_path / "h.json"
    p.write_text("{ not json", encoding="utf-8")
    assert ConversationStore(p).recent(10) == []
