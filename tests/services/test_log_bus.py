"""Phase 6 — in-app console log bus."""
import io

from Services.log_bus import LogBus, _Tee


def test_emit_and_read_lines():
    bus = LogBus()
    bus.emit("hello world", source="Engine")
    assert bus.lines() == ["[Engine] hello world"]


def test_bracketed_prefix_becomes_source():
    bus = LogBus()
    bus.emit("[MLScanner] score error: boom")
    rec = bus.records()[-1]
    assert rec["source"] == "MLScanner"
    assert rec["text"] == "score error: boom"


def test_blank_lines_ignored():
    bus = LogBus()
    bus.emit("")
    bus.emit("   \n")
    bus.emit(None)
    assert len(bus) == 0


def test_ring_buffer_is_bounded():
    bus = LogBus(max_lines=10)
    for i in range(50):
        bus.emit(f"line {i}", source="x")
    assert len(bus) == 10
    assert bus.lines()[-1] == "[x] line 49"


def test_lines_limit_and_module_filter():
    bus = LogBus()
    bus.emit("a", source="NetPro")
    bus.emit("b", source="Ransom")
    bus.emit("c", source="NetPro")
    assert bus.lines(module="netpro") == ["[NetPro] a", "[NetPro] c"]
    assert bus.lines(n=1) == ["[Ransom] c"] or bus.lines(n=1) == ["[NetPro] c"]


def test_sources_listing():
    bus = LogBus()
    bus.emit("x", source="A")
    bus.emit("y", source="B")
    assert bus.sources() == ["A", "B"]


def test_clear_returns_count():
    bus = LogBus()
    bus.emit("x", source="A")
    bus.emit("y", source="A")
    assert bus.clear() == 2
    assert bus.lines() == []


def test_subscriber_receives_records():
    bus = LogBus()
    got = []
    bus.subscribe(got.append)
    bus.emit("hi", source="S")
    assert got and got[0]["text"] == "hi" and got[0]["source"] == "S"


def test_failing_subscriber_does_not_break_emit():
    bus = LogBus()
    bus.subscribe(lambda rec: (_ for _ in ()).throw(RuntimeError("bad")))
    bus.emit("still recorded", source="S")
    assert bus.lines() == ["[S] still recorded"]


# ── stdout tee ───────────────────────────────────────────────────────────────

def test_tee_forwards_to_stream_and_bus():
    bus = LogBus()
    sink = io.StringIO()
    tee = _Tee(sink, bus, "app")
    tee.write("captured line\n")
    assert sink.getvalue() == "captured line\n"      # terminal still gets it
    assert bus.lines() == ["[app] captured line"]    # ...and the console does too


def test_tee_buffers_partial_lines_until_newline():
    bus = LogBus()
    tee = _Tee(io.StringIO(), bus, "app")
    tee.write("half ")
    assert len(bus) == 0            # nothing emitted yet
    tee.write("a line\n")
    assert bus.lines() == ["[app] half a line"]


def test_tee_captures_print_source_prefix():
    bus = LogBus()
    tee = _Tee(io.StringIO(), bus, "app")
    tee.write("[VirusScanner] scanning C:\\x.exe\n")
    rec = bus.records()[-1]
    assert rec["source"] == "VirusScanner"
