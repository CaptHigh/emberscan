# EmberScan — Claude Code working notes

Firmware security framework (SPI/flash extraction, QEMU full-system emulation,
static scanners, reporting) plus a new **dynamic emulation-analysis** subsystem.
Python 3.9+. CLI entry point: `emberscan` (see `pyproject.toml [project.scripts]`).

## Current task in this VM: verify the dynamic-emulation subsystem

A new subsystem was added that **loads individual binaries, emulates their code
(Unicorn/Qiling), and runs runtime detectors** for vulnerabilities, info leaks,
and weak code. It was validated with a mock backend but has **not** been run
against a real emulator yet (the dev sandbox had no PyPI access). Your job here:
install deps, verify across architectures and on real binaries, fix what breaks,
then report. **Do not push — branch and let the user review.**

## Setup (Kali/Debian)

```bash
./scripts/install_linux.sh                            # venv + Python libs + binwalk/qemu via apt; self-verifies
# equivalently: pip install -e ".[emulation,dev]"
emberscan check-deps                                  # unicorn/capstone/keystone/qiling must be ✓
```

## Tests — run in this order

1. **Logic, no native deps:** `python tests/test_dynamic.py` → expect `15/15 tests passed`.
2. **Multi-arch engine, real Unicorn:** `python tests/verify_multiarch.py` →
   expect `6/6 architectures passed` (arm, arm64, mips, mipsel, x86, x86_64);
   each row needs both `call` and `mem` = `yes`.
3. **Existing suite:** `pytest -q`. Some pre-existing failures unrelated to this
   work may exist; the two steps above are the acceptance gate for this subsystem.
4. **Real cross-arch binaries (strongest check):**
   ```bash
   bash tests/build_test_binaries.sh          # cross-compiles tests/vuln.c -> tests/samples/
   for b in tests/samples/*/vuln*; do emberscan analyze "$b" --backend qiling; done
   ```
   `tests/vuln.c` is the ground truth — its comments map each line to the finding
   it must produce: command injection (CWE-78), buffer overflow (CWE-120),
   format string (CWE-134), predictable seed (CWE-337), insecure PRNG (CWE-338).
   Run both the dynamic and the `_static` binaries.

## Known-unvalidated — concentrate testing here

Passed on the mock backend; expect to debug/tune on a real emulator:

- **Qiling call resolution.** `QilingBackend` resolves calls via `ql.os.set_api`
  name interception. This varies across Qiling versions and **misses
  statically-linked binaries** (no dynamic symbols). If the `vuln_static`
  samples produce no taint/weak-code findings, add a `.symtab`/`.dynsym`-based
  symbol map + `hook_block` call/return detection as a fallback (mirror the
  approach in `UnicornBackend._hook_block`). File: `emberscan/dynamic/qiling_backend.py`.
- **MIPS big-endian** under both backends.
- **Heap tracking** in `memory_safety` depends on malloc/free call+return events
  firing — same `set_api` caveat.
- **Calling-convention arg reads** (`_read_args`), especially x86 stack args and
  MIPS o32.

If a `verify_multiarch.py` row fails, look first at `_uc_arch_mode` / `_reg_const`
for that arch in `emberscan/dynamic/unicorn_backend.py`, or the Keystone asm in
`tests/verify_multiarch.py`.

## Architecture — keep these seams intact

```
emberscan/dynamic/
  events.py            TraceEvent stream + Finding (no emulator/model imports)
  backend.py           ExecutionBackend ABC; MockBackend; HardwareBackend (stub)
  unicorn_backend.py   bare-metal / raw blobs + minimal ELF loader
  qiling_backend.py    Linux user-space ELF, rootfs as sysroot
  harness.py           target selection + EmulationRunner
  detectors/
    base.py            Detector + DetectorPipeline
    _shadow.py         shared taint map + tracker
    memory_safety.py  taint.py  info_leak.py  weak_code.py
emberscan/scanners/emulation_scanner.py   Finding -> Vulnerability; registered "emulation"
```

- Detectors are **backend-agnostic**: they consume the event stream only, so the
  same detectors run over Unicorn, Qiling, or the future hardware harness.
- `HardwareBackend` is the integration point for the **Raspberry-Pi hardware
  side** (JTAG/SWD or serial agent emitting the same events). Do not change the
  `ExecutionBackend` interface without updating all three backends and the
  detectors.
- `EmulationScanner` is wired into `core/scanner.py` (Phase 3b) and gated by
  `config.emulation`; it also runs inside `emberscan scan` unless `--static-only`.

## Conventions

- Python 3.9-compatible. `from __future__ import annotations` is used; avoid
  runtime `X | Y` unions.
- `black` line-length 100, `isort` profile black.
- **unicorn / qiling / keystone are optional** (the `emulation` extra). Never
  import them at module top level — keep the lazy-import / `available`-property
  pattern so the package imports fine without them.
- New finding types: add the `vuln_type` mapping in `emulation_scanner._VT` and
  the enum member in `core/models.py:VulnerabilityType`.

## Safety

`emberscan analyze` / `scan` **executes code from the target firmware**. This VM
is the sandbox. Only assess firmware you are authorised to test.
