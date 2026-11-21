#!/bin/sh
# GFOpenTLS for AmigaOS 3.x: gfopentls.library and its Amiga test programs.
#   STOVE    the stove (default ~/AmiCradle/stoves/os32-gcc16; the GCC 6.5
#            os32 stove builds it too)
#   CPU      040 (default: the 68040) or 060. GCC 16 with
#            -m68060 read the high word of 64-bit values from the wrong stack
#            slot (found 9 Oct 2026); GFOpenAmigaGCC's gcc patch 0008 fixes it.
#            CPU=060 with GCC 16 needs a stove built with that patch (its
#            patches/gcc/ says so: the stove of 9 Oct 2026 and later), or
#            ALLOW_GCC16_060=1 (not for shipping); GCC 6.5 (the os32 stove)
#            is right
#   OUT      the output directory (default build-amiga-tls)
#   EXTRA_CFLAGS  more compiler flags
#   FPCR_CHECK  gfopenrtg's tools/fpcr_check.py, run on the results when
#               set (the GCC 16 -m68040 FPCR clash; the build uses no FPU)
# Outputs: lib/gfopentls.library, tests/GFOpenTLSClient, tests/GFOpenTLSFTPSGet,
# and the headers under include/.
# MIT licensed and free. Copyright (c) 2026 AmiCradle Team.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# soft float: link libnix's libm020, not libm881 (specs/m68k-soft-m68040.specs)
SPECS="$HERE/specs/m68k-soft-m68040.specs"
STOVE=${STOVE:-"$HOME/AmiCradle/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
AR="$P/bin/m68k-amigaos-ar"
OUT=${OUT:-"$HERE/build-amiga-tls"}
case "${CPU:-040}" in
    040) CPUFLAGS="-m68040 -specs=$SPECS" ;;
    060) CPUFLAGS="-m68060" ;;
    *) echo "CPU is 040 or 060 (builds are 68040 only, with a 68060 variant)"; exit 2 ;;
esac

# The stove records the patches it was built with; the version number is the
# same with and without the fix.
gcc16_060_fixed() { ls "$STOVE"/patches/gcc/0008-*shift-by-32* >/dev/null 2>&1; }
if [ "${CPU:-040}" = 060 ] && "$CC" -dumpversion | grep -q '^16' && ! gcc16_060_fixed && [ "${ALLOW_GCC16_060:-}" != 1 ]; then
    echo "CPU=060 with GCC 16 is refused: this stove's GCC miscompiles 64-bit values at -m68060"
    echo "(no patches/gcc/0008 in $STOVE)."
    echo "Use a stove with GFOpenAmigaGCC patch 0008, the os32 stove (GCC 6.5), or CPU=040."
    exit 2
fi
mkdir -p "$OUT/lib" "$OUT/tests" "$OUT/include"
cp -r "$HERE/include/libraries" "$HERE/include/proto" "$HERE/include/inline" \
      "$HERE/include/clib" "$HERE/include/fd" "$OUT/include/"

# -fno-tree-loop-distribute-patterns: GCC 16.2.0b's loop-shift miscompile
# -fno-delete-null-pointer-checks: address 0 is memory on an Amiga
BASE="$CPUFLAGS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer ${EXTRA_CFLAGS:-}"
INC="-I$HERE/include -I$HERE/src/opentls"

OTSRC="$HERE/src/opentls/ot_core.c $HERE/src/opentls/ot_glue.c $HERE/src/opentls/ot_platform.c
       $HERE/src/opentls/ot_random.c $HERE/src/opentls/ot_trust.c $HERE/src/opentls/ot_x509.c
       $HERE/src/opentls/ot_tls13.c $HERE/src/opentls/ot_tls13_keys.c
       $HERE/src/opentls/ot_service.c $HERE/src/opentls/ot_hmac.c
       $HERE/src/opencrypto_pss.c"
WARN="-Wall -Wextra -Werror -Wno-unused-parameter"

"$CC" $BASE $WARN $INC -mcrt=nix20 -fno-toplevel-reorder -nostartfiles \
  -o "$OUT/lib/gfopentls.library" \
  "$HERE/library/opentls_lib.c" $OTSRC -lamiga -lgcc \
  -Wl,-Map,"$OUT/lib/gfopentls.library.map"
echo "$OUT/lib/gfopentls.library ($(wc -c < "$OUT/lib/gfopentls.library") bytes)"
# 2.0: no BearSSL at all. The library's undefined symbols must all be libnix's or libamiga's.
"$P/bin/m68k-amigaos-nm" -u "$OUT/lib/gfopentls.library"

"$CC" $BASE $WARN -Wno-format -I"$HERE/include" -noixemul -o "$OUT/tests/GFOpenTLSClient" \
  "$HERE/tests/opentls_client.c" -lm
"$CC" $BASE $WARN -Wno-format -I"$HERE/include" -noixemul -o "$OUT/tests/GFOpenTLSFTPSGet" \
  "$HERE/tests/opentls_ftps_get.c"

if [ -n "${FPCR_CHECK:-}" ]; then
    python3 "$FPCR_CHECK" "$P/bin/m68k-amigaos-objdump" "$OUT/lib/gfopentls.library" \
        "$OUT/tests/GFOpenTLSClient" "$OUT/tests/GFOpenTLSFTPSGet"
fi
for f in GFOpenTLSClient GFOpenTLSFTPSGet; do
    echo "$OUT/tests/$f ($(wc -c < "$OUT/tests/$f") bytes)"
done
sha256sum "$OUT/lib/gfopentls.library"
