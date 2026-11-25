#!/usr/bin/env python3
"""
EmberScan installer (Linux / macOS / Windows).

One command, safe to re-run. It:

  1. creates (or repairs) a private virtualenv at ./venv, pinned to a specific
     Python version so a distro Python upgrade cannot silently break it;
  2. installs EmberScan + the emulation libraries into that venv;
  3. optionally installs the OS-level tools (binwalk, qemu, ...) via apt/brew;
  4. puts an ``emberscan`` command on your PATH;
  5. VERIFIES the result by actually running ``emberscan`` -- and exits non-zero
     with a red FAILED banner and the exact fix if anything required is broken.

Usage:
    python3 scripts/install.py                  # venv + EmberScan + emulation libs
    python3 scripts/install.py --with-external  # ... plus OS tools (uses sudo/brew)
    python3 scripts/install.py --check          # verify only, change nothing
    python3 scripts/install.py --dev            # also install dev/test extras
    python3 scripts/install.py --strict         # treat missing optional tools as failure
    python3 scripts/install.py --recreate-venv  # throw away ./venv and rebuild it

Exit codes: 0 = working (possibly with listed warnings), 1 = installation failed.

This file intentionally uses only the standard library and runs on Python 3.9+.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
WINDOWS = platform.system() == "Windows"
MIN_PY = (3, 9)

# import-name -> pip requirement (must match pyproject's [emulation] extra)
EMULATION_LIBS = {
    "unicorn": "unicorn>=2.0.0",
    "capstone": "capstone>=5.0.0",
    "keystone": "keystone-engine>=0.9.2",
    "qiling": "qiling>=1.4.6",
}

# pip-installed helper tools: pip requirement -> command it provides
PIP_TOOLS = {"jefferson": "jefferson", "ubi_reader": "ubireader_extract_files"}

# command -> (apt package, brew package or None, what EmberScan uses it for)
EXTERNAL_TOOLS: Dict[str, Tuple[str, Optional[str], str]] = {
    "binwalk": ("binwalk", "binwalk", "firmware extraction"),
    "unsquashfs": ("squashfs-tools", "squashfs", "SquashFS extraction"),
    "sasquatch": ("sasquatch", None, "vendor-modified SquashFS"),
    "7z": ("p7zip-full", "p7zip", "archive extraction"),
    "cpio": ("cpio", "cpio", "initramfs extraction"),
    "ubinize": ("mtd-utils", None, "UBI/JFFS2 images"),
    "qemu-system-arm": ("qemu-system-arm", "qemu", "ARM full-system emulation"),
    "qemu-system-mips": ("qemu-system-mips", "qemu", "MIPS full-system emulation"),
    "qemu-system-x86_64": ("qemu-system-x86", "qemu", "x86 full-system emulation"),
    "qemu-arm-static": ("qemu-user-static", None, "user-mode emulation"),
    "readelf": ("binutils", "binutils", "ELF analysis"),
    "file": ("file", None, "file type detection"),
    "nmap": ("nmap", "nmap", "network scanning"),
    "nikto": ("nikto", "nikto", "web scanning"),
    "flashrom": ("flashrom", "flashrom", "SPI flash reading"),
    "gdb-multiarch": ("gdb-multiarch", None, "debugging"),
}
# extra apt packages with no single command to verify (libraries for building/extracting)
APT_EXTRA = ["liblzo2-dev", "liblzma-dev", "zlib1g-dev", "libmagic1", "lzop", "unzip"]

G, R, Y, C, B, E = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
if WINDOWS and not os.environ.get("WT_SESSION") and not os.environ.get("ANSICON"):
    G = R = Y = C = B = E = ""


# --------------------------------------------------------------------------- results
class Results:
    """Collects the outcome of every step so the summary can't lie."""

    def __init__(self) -> None:
        self.failures: List[Tuple[str, str]] = []  # (problem, how to fix)
        self.warnings: List[Tuple[str, str]] = []

    def fail(self, problem: str, fix: str = "") -> None:
        print(f"  {R}✗ {problem}{E}")
        self.failures.append((problem, fix))

    def warn(self, problem: str, fix: str = "") -> None:
        print(f"  {Y}! {problem}{E}")
        self.warnings.append((problem, fix))

    @staticmethod
    def ok(msg: str) -> None:
        print(f"  {G}✓ {msg}{E}")


def step(title: str) -> None:
    print(f"\n{C}{B}==> {title}{E}")


def run(cmd: List[str], quiet: bool = False, **kw) -> int:
    if not quiet:
        print(f"{C}  $ {' '.join(str(c) for c in cmd)}{E}")
    try:
        if quiet:
            return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        return subprocess.call(cmd, **kw)
    except (OSError, FileNotFoundError):
        return 127


def capture(cmd: List[str], **kw) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)
        return p.returncode, p.stdout.strip()
    except (OSError, FileNotFoundError) as exc:
        return 127, str(exc)


# --------------------------------------------------------------------------- python / venv
def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if WINDOWS else "bin/python")


def venv_bin(venv: Path) -> Path:
    return venv / ("Scripts" if WINDOWS else "bin")


def py_version(py: str) -> Optional[Tuple[int, int]]:
    rc, out = capture([py, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"])
    if rc != 0:
        return None
    try:
        major, minor = out.splitlines()[-1].split(".")
        return int(major), int(minor)
    except ValueError:
        return None


def candidate_pythons() -> List[str]:
    """Interpreters to build the venv with, best first, as *versioned* real paths.

    Using the resolved, versioned binary (e.g. /usr/bin/python3.13 rather than
    /usr/bin/python3) is what keeps the venv working after the distro moves the
    ``python3`` symlink to a newer version.
    """
    seen, out = set(), []

    def add(p: Optional[str]) -> None:
        if not p:
            return
        real = os.path.realpath(p)
        if real in seen or not os.path.exists(real):
            return
        v = py_version(real)
        if v and v >= MIN_PY:
            seen.add(real)
            out.append(real)

    base = getattr(sys, "_base_executable", None) or sys.executable
    add(base)
    add(sys.executable)
    for minor in (13, 12, 11, 10, 9, 14):
        add(shutil.which(f"python3.{minor}"))
    add(shutil.which("python3"))
    return out


def venv_health(venv: Path) -> Optional[str]:
    """None if the venv is usable, otherwise a human-readable reason it is not."""
    py = venv_python(venv)
    if not py.exists():
        return "its Python executable is missing"
    v = py_version(str(py))
    if v is None:
        return "its Python executable no longer runs (the interpreter it points to was removed)"
    cfg = venv / "pyvenv.cfg"
    if cfg.exists():
        for line in cfg.read_text(errors="replace").splitlines():
            key, _, val = line.partition("=")
            if key.strip() in ("version", "version_info"):
                built = tuple(int(x) for x in val.strip().split(".")[:2])
                if built != v:
                    return (
                        f"it was built for Python {built[0]}.{built[1]} but now runs "
                        f"Python {v[0]}.{v[1]} (system Python was upgraded)"
                    )
    rc, _ = capture([str(py), "-m", "pip", "--version"])
    if rc != 0:
        return "pip inside it is broken"
    return None


def create_venv(venv: Path, py: str, res: Results) -> bool:
    rc, out = capture([py, "-m", "venv", str(venv)])
    if rc == 0 and venv_python(venv).exists():
        return True
    shutil.rmtree(venv, ignore_errors=True)
    if "ensurepip" in out or "venv" in out:
        v = py_version(py)
        ver = f"{v[0]}.{v[1]}" if v else "3"
        print(f"  {Y}! {py} cannot create virtualenvs (python{ver}-venv not installed){E}")
    else:
        print(f"  {Y}! creating venv with {py} failed:{E}\n{out[-800:]}")
    return False


def pip(py: Path, args: List[str], quiet: bool = False) -> int:
    return run([str(py), "-m", "pip", "--disable-pip-version-check"] + args, quiet=quiet)


def install_package(py: Path, dev: bool) -> bool:
    extras = "[emulation,dev]" if dev else "[emulation]"
    pip(py, ["install", "--upgrade", "pip", "setuptools", "wheel"], quiet=True)
    return pip(py, ["install", "-e", f"{REPO}{extras}"]) == 0


def setup_venv(venv: Path, args, res: Results) -> Optional[Path]:
    """Create/repair the venv and install EmberScan into it. Returns its python."""
    step(f"Python environment ({venv})")

    if venv.exists():
        problem = "forced rebuild (--recreate-venv)" if args.recreate_venv else venv_health(venv)
        if problem is None:
            res.ok(f"existing venv is healthy (Python {'.'.join(map(str, py_version(str(venv_python(venv)))))})")
            py = venv_python(venv)
            print("  installing / updating EmberScan in it ...")
            if install_package(py, args.dev):
                res.ok("EmberScan + emulation libraries installed")
                return py
            res.warn("install into existing venv failed; rebuilding the venv from scratch")
        else:
            print(f"  {Y}! existing venv is broken: {problem}{E}")
            print(f"  {Y}  rebuilding it automatically ...{E}")
        shutil.rmtree(venv, ignore_errors=True)

    candidates = candidate_pythons()
    if not candidates:
        res.fail(
            f"no Python >= {MIN_PY[0]}.{MIN_PY[1]} found",
            "sudo apt-get install -y python3 python3-venv python3-pip",
        )
        return None

    tried = []
    for cand in candidates:
        v = py_version(cand)
        label = f"Python {v[0]}.{v[1]} ({cand})"
        print(f"  creating venv with {label} ...")
        if not create_venv(venv, cand, res):
            tried.append(f"{label}: could not create venv")
            continue
        py = venv_python(venv)
        if install_package(py, args.dev):
            res.ok(f"EmberScan + emulation libraries installed with {label}")
            return py
        tried.append(f"{label}: pip install failed (see output above)")
        print(f"  {Y}! install failed with {label} -- usually a dependency with no prebuilt "
              f"package for this Python version yet; trying the next Python version{E}")
        shutil.rmtree(venv, ignore_errors=True)

    res.fail(
        "could not install EmberScan with any available Python:\n      - " + "\n      - ".join(tried),
        "check your internet connection (pip must reach pypi.org); if a package failed "
        "to build, run: sudo apt-get install -y python3-venv python3-dev build-essential "
        "-- then re-run the installer",
    )
    return None


# --------------------------------------------------------------------------- external tools
def have_tool(cmd: str, extra_path: Optional[Path] = None) -> bool:
    path = os.environ.get("PATH", "")
    if extra_path:
        path = f"{extra_path}{os.pathsep}{path}"
    return shutil.which(cmd, path=path) is not None


def sudo_prefix() -> Optional[List[str]]:
    if WINDOWS:
        return None
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    return None


def install_external_apt(res: Results) -> None:
    pre = sudo_prefix()
    if pre is None:
        res.warn("cannot install OS tools: not root and sudo is not available",
                 "run the installer as a user with sudo rights")
        return
    if pre:
        print("  (you may be asked for your sudo password)")
    if run(pre + ["apt-get", "update"]) != 0:
        res.warn("'apt-get update' failed; package lists may be stale",
                 "check your network / /etc/apt/sources.list, then re-run the installer")

    wanted = sorted({pkg for (pkg, _, _) in EXTERNAL_TOOLS.values()} | set(APT_EXTRA))
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if run(pre + ["apt-get", "install", "-y"] + wanted, env=env) != 0:
        # one unavailable package makes apt refuse the whole batch; go one by one
        print(f"  {Y}! batch install failed; installing packages individually ...{E}")
        for pkg in wanted:
            if run(pre + ["apt-get", "install", "-y", pkg], quiet=True, env=env) != 0:
                print(f"    {Y}- {pkg}: not installable on this system{E}")


def install_external_brew(res: Results) -> None:
    pkgs = sorted({b for (_, b, _) in EXTERNAL_TOOLS.values() if b})
    if run(["brew", "install"] + pkgs) != 0:
        res.warn("some Homebrew packages failed to install (see output above)")


def install_external(res: Results) -> None:
    step("OS tools (extraction / full-system emulation / scanning)")
    sysname = platform.system()
    if sysname == "Linux" and shutil.which("apt-get"):
        install_external_apt(res)
    elif sysname == "Darwin" and shutil.which("brew"):
        install_external_brew(res)
    elif WINDOWS:
        print("  On Windows these tools run under WSL2:  wsl --install, then run")
        print("  scripts/install_linux.sh inside WSL. The 'analyze' command works without them.")
    else:
        res.warn(f"no supported package manager on {sysname}; install the tools manually")


def install_pip_tools(py: Path, res: Results) -> None:
    for req in PIP_TOOLS:
        if pip(py, ["install", req], quiet=True) != 0:
            print(f"  {Y}- pip install {req} failed{E}")


# --------------------------------------------------------------------------- launcher
LAUNCHER = """#!/bin/sh
# EmberScan launcher -- generated by scripts/install.py. Re-run the installer to update.
VENV="{venv}"
if ! "$VENV/bin/python" -I -c "import importlib.util as u, sys; \\
sys.exit(u.find_spec('emberscan') is None)" >/dev/null 2>&1; then
    echo "emberscan: the installation in $VENV is broken" >&2
    echo "           (this usually happens after a system Python upgrade)." >&2
    echo "           Repair it by running:  {repair}" >&2
    exit 1
fi
PATH="$VENV/bin:$PATH" exec "$VENV/bin/emberscan" "$@"
"""


def on_path(d: Path) -> bool:
    return any(
        os.path.realpath(p) == os.path.realpath(d)
        for p in os.environ.get("PATH", "").split(os.pathsep)
        if p
    )


def install_launcher(venv: Path, res: Results) -> Optional[Path]:
    step("emberscan command")
    if WINDOWS:
        exe = venv_bin(venv) / "emberscan.exe"
        res.ok(f"run EmberScan with: {exe}")
        print(f"     (or activate the venv first:  {venv}\\Scripts\\activate)")
        return exe

    body = LAUNCHER.format(venv=venv, repair=_repair_cmd())

    targets = [Path("/usr/local/bin")] if os.geteuid() == 0 else []
    targets.append(Path.home() / ".local" / "bin")
    for d in targets:
        try:
            d.mkdir(parents=True, exist_ok=True)
            dest = d / "emberscan"
            if dest.is_symlink() or (dest.exists() and "generated by scripts/install.py"
                                     not in dest.read_text(errors="replace")):
                backup = dest.with_name("emberscan.old")
                dest.replace(backup)
                print(f"  {Y}! moved an older emberscan command aside to {backup}{E}")
            dest.write_text(body)
            dest.chmod(0o755)
        except OSError as exc:
            print(f"  {Y}! cannot write {d}/emberscan: {exc}{E}")
            continue
        res.ok(f"installed {dest}")
        if not on_path(d):
            res.warn(
                f"{d} is not on your PATH, so typing 'emberscan' won't find it yet",
                f"echo 'export PATH=\"{d}:$PATH\"' >> ~/.{_shell_rc()} && exec $SHELL   "
                f"# or run {dest} directly",
            )
        else:
            found = shutil.which("emberscan")
            if found and os.path.realpath(found) != os.path.realpath(dest):
                res.warn(
                    f"another 'emberscan' ({found}) comes first on your PATH and shadows this one",
                    f"remove it:  rm {found}",
                )
        return dest

    res.fail("could not install the emberscan command anywhere",
             f"run EmberScan via {venv_bin(venv) / 'emberscan'}")
    return None


def _repair_cmd(*extra: str) -> str:
    base = (f"{REPO}/scripts/install_linux.sh" if platform.system() == "Linux"
            else f"python3 {REPO}/scripts/install.py")
    return " ".join([base, *extra])


def _shell_rc() -> str:
    sh = os.path.basename(os.environ.get("SHELL", "bash"))
    return "zshrc" if sh == "zsh" else "bashrc"


# --------------------------------------------------------------------------- verification
SMOKE = r"""
import importlib, sys
missing = []
for m in %r:
    try:
        importlib.import_module(m)
    except Exception as e:
        missing.append('%%s (%%s)' %% (m, e))
if missing:
    print('MISSING: ' + '; '.join(missing)); sys.exit(1)
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, b'\x48\xc7\xc0\x2a\x00\x00\x00')  # mov rax, 42
uc.emu_start(0x1000, 0x1007)
from unicorn.x86_const import UC_X86_REG_RAX
assert uc.reg_read(UC_X86_REG_RAX) == 42, 'unicorn produced the wrong result'
import emberscan
print('OK emberscan %%s' %% getattr(emberscan, '__version__', '?'))
"""


def verify(py: Path, launcher: Optional[Path], strict: bool, res: Results) -> None:
    step("Verifying the installation")
    venv = py.parent.parent
    # run from a neutral directory so the repo checkout can't mask a broken install
    with tempfile.TemporaryDirectory() as neutral:
        rc, out = capture([str(py), "-c", SMOKE % (list(EMULATION_LIBS),)], cwd=neutral)
        if rc == 0:
            res.ok(f"Python imports + Unicorn emulation self-test passed ({out.splitlines()[-1]})")
        else:
            res.fail(
                "EmberScan or an emulation library does not import/run: "
                + (out.splitlines()[-1] if out else f"exit {rc}"),
                _repair_cmd("--recreate-venv"),
            )

        cmd = [str(launcher)] if launcher else [str(venv_bin(venv) / "emberscan")]
        rc, out = capture(cmd + ["--version"], cwd=neutral)
        if rc == 0 and "EmberScan" in out:
            res.ok(f"'{cmd[0]} --version' -> {out.splitlines()[-1]}")
        else:
            res.fail(f"the emberscan command does not run: {out[-300:] or f'exit {rc}'}",
                     _repair_cmd("--recreate-venv"))

    missing = [
        (cmd, pkg, why)
        for cmd, (pkg, _, why) in EXTERNAL_TOOLS.items()
        if not have_tool(cmd, venv_bin(venv))
    ]
    missing += [
        (cmd, f"pip:{req}", "JFFS2/UBI extraction")
        for req, cmd in PIP_TOOLS.items()
        if not have_tool(cmd, venv_bin(venv))
    ]
    if not missing:
        res.ok("all optional OS tools present")
        return
    apt_pkgs = sorted({p for _, p, _ in missing if not p.startswith("pip:")})
    pip_pkgs = sorted({p[4:] for _, p, _ in missing if p.startswith("pip:")})
    fixes = []
    if apt_pkgs:
        fixes.append("sudo apt-get install -y " + " ".join(apt_pkgs)
                     if platform.system() == "Linux" else "install: " + " ".join(apt_pkgs))
    if pip_pkgs:
        fixes.append(f"{py} -m pip install " + " ".join(pip_pkgs))
    msg = "optional tools missing (these features will be unavailable): " + ", ".join(
        f"{c} [{w}]" for c, _, w in missing
    )
    (res.fail if strict else res.warn)(msg, "\n           ".join(fixes))


# --------------------------------------------------------------------------- summary
def summary(res: Results, launcher: Optional[Path]) -> int:
    print()
    if res.failures:
        print(f"{R}{B}╔══════════════════════════════════════════════════════════════╗")
        print("║   INSTALLATION FAILED -- EmberScan is NOT ready to use        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{E}")
        for problem, fix in res.failures:
            print(f"  {R}✗ {problem}{E}")
            if fix:
                print(f"      fix: {fix}")
        if res.warnings:
            print(f"\n  {Y}also:{E}")
            for problem, fix in res.warnings:
                print(f"  {Y}! {problem}{E}")
        return 1

    if res.warnings:
        print(f"{Y}{B}╔══════════════════════════════════════════════════════════════╗")
        print("║   EmberScan installed and working -- with warnings            ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{E}")
        for problem, fix in res.warnings:
            print(f"  {Y}! {problem}{E}")
            if fix:
                print(f"      fix: {fix}")
    else:
        print(f"{G}{B}╔══════════════════════════════════════════════════════════════╗")
        print("║   EmberScan installed and verified                            ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{E}")

    exe = "emberscan" if launcher and on_path(launcher.parent) else str(launcher or "emberscan")
    print(f"\n  Try it:\n    {C}{exe} check-deps{E}\n    {C}{exe} scan firmware.bin{E}"
          f"\n    {C}{exe} analyze path/to/binary{E}\n")
    return 0


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="EmberScan installer")
    ap.add_argument("--check", action="store_true", help="verify only, change nothing")
    ap.add_argument("--dev", action="store_true", help="also install dev/test extras")
    ap.add_argument("--with-external", action="store_true",
                    help="install OS tools (binwalk, qemu, ...) via apt/brew")
    ap.add_argument("--strict", action="store_true",
                    help="fail if any optional OS tool is missing")
    ap.add_argument("--recreate-venv", action="store_true", help="rebuild ./venv from scratch")
    ap.add_argument("--venv", default=str(REPO / "venv"), help="virtualenv location")
    ap.add_argument("--skip-core", action="store_true", help=argparse.SUPPRESS)  # legacy
    ap.add_argument("--no-pip-upgrade", action="store_true", help=argparse.SUPPRESS)  # legacy
    args = ap.parse_args()
    try:  # keep our messages in order with the pip/apt output when piped to a log
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

    print(f"{C}{B}EmberScan installer{E} — {platform.system()} {platform.machine()}, "
          f"running under Python {platform.python_version()}")
    res = Results()
    venv = Path(args.venv).resolve()

    if args.check:
        problem = venv_health(venv) if venv.exists() else "it does not exist"
        if problem:
            res.fail(f"virtualenv {venv} is not usable: {problem}", _repair_cmd())
            return summary(res, None)
        launcher = None if WINDOWS else Path.home() / ".local/bin/emberscan"
        if launcher and not launcher.exists():
            launcher = Path("/usr/local/bin/emberscan") if Path(
                "/usr/local/bin/emberscan").exists() else None
        verify(venv_python(venv), launcher, args.strict, res)
        return summary(res, launcher)

    if args.with_external:
        install_external(res)  # first: may provide python3-venv / build deps

    py = setup_venv(venv, args, res)
    if py is None:
        return summary(res, None)

    step("Helper tools (jefferson, ubi_reader)")
    install_pip_tools(py, res)

    launcher = install_launcher(venv, res)
    verify(py, launcher, args.strict, res)
    return summary(res, launcher)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{R}{B}Installation interrupted -- EmberScan is NOT fully installed.{E}")
        print("Re-run the installer to finish; it is safe to run repeatedly.")
        sys.exit(130)
