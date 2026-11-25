#!/usr/bin/env bash
#
# Cross-compile tests/vuln.c for multiple architectures (Kali/Debian).
# Produces UNSTRIPPED dynamic (and, where possible, static) ELFs under
# tests/samples/<arch>/, for end-to-end verification of the emulation scanner
# against real binaries of each architecture.
#
#   bash tests/build_test_binaries.sh
#   for b in tests/samples/*/vuln*; do emberscan analyze "$b" --backend qiling; done
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/vuln.c"
OUT="$HERE/samples"
mkdir -p "$OUT"

# toolchain packages (Debian/Kali)
PKGS="gcc-multilib gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu gcc-mips-linux-gnu gcc-mipsel-linux-gnu"

# arch tag -> compiler command
ARCHES="x86_64 x86 arm arm64 mips mipsel"
cc_for() {
    case "$1" in
        x86_64) echo "gcc" ;;
        x86)    echo "gcc -m32" ;;
        arm)    echo "arm-linux-gnueabi-gcc" ;;
        arm64)  echo "aarch64-linux-gnu-gcc" ;;
        mips)   echo "mips-linux-gnu-gcc" ;;
        mipsel) echo "mipsel-linux-gnu-gcc" ;;
    esac
}

CFLAGS="-fno-stack-protector -w"
echo "Missing a compiler? sudo apt-get install -y $PKGS"
echo

built=0
for arch in $ARCHES; do
    cc="$(cc_for "$arch")"
    bin="${cc%% *}"
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "skip   $arch  ($bin not installed)"
        continue
    fi
    mkdir -p "$OUT/$arch"
    if $cc $CFLAGS "$SRC" -o "$OUT/$arch/vuln" 2>/dev/null; then
        echo "built  $arch/vuln         (dynamic)"
        built=$((built + 1))
    else
        echo "FAILED $arch dynamic build"
    fi
    if $cc $CFLAGS -static "$SRC" -o "$OUT/$arch/vuln_static" 2>/dev/null; then
        echo "built  $arch/vuln_static  (static)"
    else
        echo "note   $arch static build skipped (static libc not present)"
    fi
done

echo
echo "built $built dynamic sample(s) under $OUT"
echo "next: for b in $OUT/*/vuln*; do emberscan analyze \"\$b\" --backend qiling; done"
echo "(test BOTH dynamic and static: static binaries stress Qiling symbol resolution)"
