"""
Tests for the dynamic-analysis subsystem.

These drive every detector through the MockBackend with a scripted event
stream, so they need no native emulator (Unicorn/Qiling) and validate the
backend-agnostic logic end to end. Run with pytest, or directly:

    python tests/test_dynamic.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from emberscan.dynamic import EmulationRunner, MockBackend, RunOutcome
from emberscan.dynamic.detectors import DetectorPipeline
from emberscan.dynamic.detectors.base import Detector, RunContext
from emberscan.dynamic.detectors.info_leak import InfoLeakDetector
from emberscan.dynamic.detectors.memory_safety import MemorySafetyDetector
from emberscan.dynamic.detectors.taint import TaintDetector
from emberscan.dynamic.detectors.weak_code import WeakCodeDetector
from emberscan.dynamic.events import (
    READ,
    WRITE,
    BlockEvent,
    CallEvent,
    MemEvent,
    RetEvent,
    TaintSourceEvent,
)


def _run(detectors, events, memory=None, outcome=None, **mb):
    backend = MockBackend(events=events, memory=memory or {}, outcome=outcome, **mb)
    ctx = RunContext(
        backend=backend,
        binary_path="t",
        arch=backend.arch,
        endian=backend.endian,
        pointer_size=backend.pointer_size,
    )
    return DetectorPipeline(detectors).run_on(backend, ctx)


def _cats(findings):
    return {f.vuln_type for f in findings}


# ---------------------------------------------------------------------------
# memory safety
# ---------------------------------------------------------------------------


def test_heap_overflow_and_uaf_and_double_free():
    events = [
        CallEvent(pc=0x100, name="malloc", args=[64]),
        RetEvent(pc=0x104, name="malloc", retval=0x10000),
        # write one word past the 64-byte allocation -> red-zone overflow
        MemEvent(pc=0x200, access=WRITE, addr=0x10040, size=4, mapped=True),
        CallEvent(pc=0x300, name="free", args=[0x10000]),
        RetEvent(pc=0x304, name="free", retval=0),
        # read the freed block -> use-after-free
        MemEvent(pc=0x400, access=READ, addr=0x10000, size=4, mapped=True),
        CallEvent(pc=0x500, name="free", args=[0x10000]),  # double free
    ]
    f = _run([MemorySafetyDetector()], events)
    titles = " ".join(x.title for x in f)
    assert "Heap overflow" in titles, titles
    assert "Use-after-free" in titles, titles
    assert "Double free" in titles, titles


def test_allocator_internals_and_adjacent_blocks_are_clean():
    # Real glibc heaps: chunks are adjacent (B sits inside A's red zone), and
    # malloc/free touch chunk headers and freed blocks while they run.
    events = [
        CallEvent(pc=0x100, name="malloc", args=[40]),
        RetEvent(pc=0x104, name="malloc", retval=0x10000),
        CallEvent(pc=0x100, name="malloc", args=[40]),
        # malloc writing B's chunk header, right after A's 40 bytes
        MemEvent(pc=0x900, access=WRITE, addr=0x10028, size=8, mapped=True),
        RetEvent(pc=0x104, name="malloc", retval=0x10030),
        # program writes the start of B: inside B, though in A's red zone
        MemEvent(pc=0x200, access=WRITE, addr=0x10030, size=8, mapped=True),
        CallEvent(pc=0x300, name="free", args=[0x10000]),
        # free() storing its tcache link in the block it is freeing
        MemEvent(pc=0x910, access=WRITE, addr=0x10000, size=8, mapped=True),
        # glibc's first free() re-enters free() on the same pointer
        CallEvent(pc=0x300, name="free", args=[0x10000]),
        RetEvent(pc=0x304, name="free", retval=0),
        RetEvent(pc=0x304, name="free", retval=0),
    ]
    f = _run([MemorySafetyDetector()], events)
    assert not f, [x.title for x in f]


def test_unmapped_write_is_oob_write():
    events = [MemEvent(pc=0xABC, access=WRITE, addr=0x41414141, size=4, mapped=False)]
    f = _run([MemorySafetyDetector()], events)
    assert any(x.vuln_type == "buffer_overflow" and x.severity == "critical" for x in f), f


def test_null_deref():
    events = [MemEvent(pc=0xABC, access=READ, addr=0x0, size=4, mapped=False)]
    f = _run([MemorySafetyDetector()], events)
    assert any("NULL" in x.title for x in f), f


# ---------------------------------------------------------------------------
# taint
# ---------------------------------------------------------------------------


def test_command_injection_through_strcpy():
    mem = {0x2000: b"; reboot\x00", 0x3000: b"; reboot\x00"}
    events = [
        CallEvent(pc=0x10, name="recv", args=[0, 0x2000, 32]),  # source
        CallEvent(pc=0x20, name="strcpy", args=[0x3000, 0x2000]),  # propagate
        CallEvent(pc=0x30, name="system", args=[0x3000]),  # sink
    ]
    f = _run([TaintDetector()], events, mem)
    assert "command_injection" in _cats(f), f
    assert any(x.severity == "critical" for x in f)


def test_tainted_into_strcpy_is_overflow():
    mem = {0x2000: b"AAAAAAAAAAForm\x00"}
    events = [
        CallEvent(pc=0x10, name="recv", args=[0, 0x2000, 64]),
        CallEvent(pc=0x20, name="strcpy", args=[0x9000, 0x2000]),
    ]
    f = _run([TaintDetector()], events, mem)
    assert "buffer_overflow" in _cats(f), f


def test_gets_is_flagged():
    events = [CallEvent(pc=0x10, name="gets", args=[0x8000])]
    f = _run([TaintDetector()], events)
    assert any("gets" in x.title for x in f), f


def test_untainted_system_is_clean():
    mem = {0x3000: b"/bin/ls\x00"}
    events = [CallEvent(pc=0x30, name="system", args=[0x3000])]
    f = _run([TaintDetector()], events, mem)
    assert "command_injection" not in _cats(f), f


# ---------------------------------------------------------------------------
# info leak
# ---------------------------------------------------------------------------


def test_tainted_format_string():
    mem = {0x2000: b"%x%x%n\x00", 0x4000: b"count=%n\x00"}
    events = [
        CallEvent(pc=0x10, name="recv", args=[0, 0x2000, 16]),
        CallEvent(pc=0x20, name="printf", args=[0x2000]),  # tainted fmt -> HIGH
        CallEvent(pc=0x40, name="printf", args=[0x4000]),  # %n literal  -> MEDIUM
    ]
    f = _run([InfoLeakDetector()], events, mem)
    sev = {x.severity for x in f if x.vuln_type == "format_string"}
    assert "high" in sev and "medium" in sev, f


def test_secret_egress():
    mem = {0x5000: b"KEYMATERIAL\x00"}
    events = [
        TaintSourceEvent(pc=0, addr=0x5000, size=16, label="secret:key"),
        CallEvent(pc=0x20, name="send", args=[3, 0x5000, 16]),
    ]
    f = _run([InfoLeakDetector()], events, mem)
    assert "info_disclosure" in _cats(f), f


# ---------------------------------------------------------------------------
# weak code
# ---------------------------------------------------------------------------


def test_weak_crypto():
    events = [
        CallEvent(pc=0x10, name="MD5_Init", args=[]),
        CallEvent(pc=0x20, name="DES_set_key", args=[]),
    ]
    f = _run([WeakCodeDetector()], events)
    algos = {x.severity for x in f if x.vuln_type == "weak_crypto"}
    assert "weak_crypto" in _cats(f)
    assert "high" in algos  # DES is HIGH


def test_predictable_seed_and_insecure_rng():
    events = [
        CallEvent(pc=0x10, name="time", args=[0]),
        CallEvent(pc=0x14, name="srand", args=[123]),
        CallEvent(pc=0x20, name="rand", args=[]),
    ]
    f = _run([WeakCodeDetector()], events)
    assert "weak_rng" in _cats(f)
    assert any("Predictable" in x.title for x in f), f


def test_weak_auth_compare():
    mem = {0x2000: b"guess\x00", 0x6000: b"admin123\x00"}
    events = [
        CallEvent(pc=0x10, name="recv", args=[0, 0x2000, 16]),
        CallEvent(pc=0x20, name="strcmp", args=[0x2000, 0x6000]),
    ]
    f = _run([WeakCodeDetector()], events, mem)
    assert "auth_bypass" in _cats(f), f


# ---------------------------------------------------------------------------
# pipeline + runner
# ---------------------------------------------------------------------------


def test_pipeline_dedupes_identical_findings():
    class Dup(Detector):
        category = "x"

        def on_block(self, ev):
            self._add(title="same", description="d", severity="low")

    f = _run([Dup()], [BlockEvent(pc=1), BlockEvent(pc=2)])
    assert len(f) == 1, f


def test_runner_synthesizes_crash_finding():
    backend = MockBackend(
        events=[],
        outcome=RunOutcome(crashed=True, reason="unmapped write @ 0x41414141", crash_pc=0x1234),
    )
    runner = EmulationRunner(detector_names=["memory_safety"])
    res = runner.run_binary(backend, "dummy")
    assert res.outcome.crashed
    assert any(x.category == "memory_safety" for x in res.findings), res.findings


# ---------------------------------------------------------------------------
# scanner mapping assumptions (validated against the real models module)
# ---------------------------------------------------------------------------


def test_model_enums_cover_finding_types():
    from emberscan.core.models import Severity, VulnerabilityType

    for s in ("critical", "high", "medium", "low", "info"):
        assert Severity(s)
    for n in (
        "FORMAT_STRING",
        "WEAK_RNG",
        "MEMORY_CORRUPTION",
        "USE_AFTER_FREE",
        "COMMAND_INJECTION",
        "BUFFER_OVERFLOW",
        "INFORMATION_DISCLOSURE",
        "WEAK_CRYPTO",
        "AUTHENTICATION_BYPASS",
        "OTHER",
    ):
        assert hasattr(VulnerabilityType, n), n


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"  PASS {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed")
