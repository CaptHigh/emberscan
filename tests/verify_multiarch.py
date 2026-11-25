#!/usr/bin/env python3
"""
Multi-architecture verification of the EmberScan dynamic-analysis engine.

Unlike tests/test_dynamic.py (which uses the MockBackend), this runs the REAL
UnicornBackend across every supported architecture. For each arch it assembles
a tiny program with Keystone, loads it as a raw blob, and runs it through the
full detector pipeline, asserting that:

  * the call detector fires  — the program's entry is mapped to the symbol
    `gets`, so entering it must produce a CallEvent -> "Reachable gets()" finding;
  * the memory-safety detector fires — the program stores to address 0, an
    unmapped write, which must be caught as a fault.

Passing across ARM / ARM64 / MIPS / MIPSel / x86 / x86_64 demonstrates that the
emulator bring-up, hooks, call/return resolution, memory fault handling and the
detector pipeline all work per architecture.

Requires the emulation extras:  pip install 'emberscan[emulation]'
Run:                            python tests/verify_multiarch.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# -- dependency check -------------------------------------------------------
try:
    from keystone import (
        Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_X86,
        KS_MODE_ARM, KS_MODE_LITTLE_ENDIAN, KS_MODE_BIG_ENDIAN,
        KS_MODE_MIPS32, KS_MODE_32, KS_MODE_64,
    )
except Exception:
    print("Keystone is required for this harness: pip install keystone-engine")
    print("(it is included in: pip install 'emberscan[emulation]')")
    sys.exit(2)

from emberscan.dynamic import UnicornBackend
from emberscan.dynamic.detectors import DetectorPipeline, build_detectors
from emberscan.dynamic.detectors.base import RunContext

BASE = 0x100000

# arch tag -> (keystone arch, keystone mode, asm storing to NULL)
PROGRAMS = {
    "arm":    (KS_ARCH_ARM,   KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN,
               "mov r0, #0; str r1, [r0]"),
    "arm64":  (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN,
               "mov x0, #0; str x1, [x0]"),
    "mips":   (KS_ARCH_MIPS,  KS_MODE_MIPS32 | KS_MODE_BIG_ENDIAN,
               "sw $t1, 0($0)"),
    "mipsel": (KS_ARCH_MIPS,  KS_MODE_MIPS32 | KS_MODE_LITTLE_ENDIAN,
               "sw $t1, 0($0)"),
    "x86":    (KS_ARCH_X86,   KS_MODE_32,
               "xor eax, eax; mov dword ptr [eax], ebx"),
    "x86_64": (KS_ARCH_X86,   KS_MODE_64,
               "xor rax, rax; mov qword ptr [rax], rbx"),
}


def run_one(tag: str, ks_arch: int, ks_mode: int, asm: str):
    code, _ = Ks(ks_arch, ks_mode).asm(asm, BASE)
    blob = bytes(code)

    with tempfile.NamedTemporaryFile(suffix=f"_{tag}.bin", delete=False) as fh:
        fh.write(blob)
        path = fh.name

    backend = UnicornBackend()
    backend.load(path, arch=tag, base=BASE, entry=BASE, symbols={BASE: "gets"})
    ctx = RunContext(
        backend=backend, binary_path=path, arch=backend.arch,
        endian=backend.endian, pointer_size=backend.pointer_size,
        entrypoint=backend.entrypoint,
    )
    findings = DetectorPipeline(build_detectors(["memory_safety", "taint"])).run_on(
        backend, ctx, max_instructions=100, timeout_s=10,
    )
    backend.close()

    has_call = any("gets" in (f.title or "") for f in findings)
    has_mem = any(f.category == "memory_safety" for f in findings)
    return blob, findings, has_call, has_mem


def main() -> int:
    print("EmberScan multi-architecture verification (real UnicornBackend)\n")
    rows = []
    all_ok = True
    for tag, (ka, km, asm) in PROGRAMS.items():
        try:
            blob, findings, has_call, has_mem = run_one(tag, ka, km, asm)
            ok = has_call and has_mem
            rows.append((tag, len(blob), has_call, has_mem, ok, findings))
            all_ok = all_ok and ok
        except Exception as exc:
            rows.append((tag, 0, False, False, False, [f"ERROR: {exc}"]))
            all_ok = False

    print(f"{'arch':8} {'bytes':6} {'call':5} {'mem':5} result")
    print("-" * 40)
    for tag, nbytes, has_call, has_mem, ok, _ in rows:
        print(f"{tag:8} {nbytes:<6} "
              f"{'yes' if has_call else 'no':5} "
              f"{'yes' if has_mem else 'no':5} "
              f"{'PASS' if ok else 'FAIL'}")

    print("\nfindings per architecture:")
    for tag, _, _, _, _, findings in rows:
        print(f"\n[{tag}]")
        for f in findings:
            if isinstance(f, str):
                print(f"  {f}")
            else:
                print(f"  [{f.severity.upper()}] {f.category}: {f.title}")

    n_pass = sum(1 for r in rows if r[4])
    print(f"\n{n_pass}/{len(rows)} architectures passed")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
