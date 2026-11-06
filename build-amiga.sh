#!/bin/sh
# GFOpenCrypto for AmigaOS 3.x: gfopencrypto.library and its Amiga tests, with
# the os32 GCC 16 stove (bebbo's amiga-gcc, GCC 16, libnix).
#   STOVE    the stove (default ~/AmiCradle/stoves/os32-gcc16)
#   CPU      040 (default: the 68040, no FPU needed) or 060
#   OUT      the output directory (default build-amiga)
#   FPCR_CHECK  gfopenrtg's tools/fpcr_check.py, run on the objects when
#               set (the GCC 16 -m68040 FPCR clash; the build uses no FPU)
# Outputs: lib/gfopencrypto.library, tests/GFOpenCryptoLibTest (version 1's
# calls), tests/GFOpenCryptoVectors (the published vectors, as on the PC),
# tests/GFOpenCryptoBench (version 2's calls, checked and timed).
# MIT, Copyright (c) 2026 AmiCradle Team.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# soft float: link libnix's libm020, not libm881 (specs/m68k-soft-m68040.specs)
SPECS="$HERE/specs/m68k-soft-m68040.specs"
STOVE=${STOVE:-"$HOME/AmiCradle/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
OUT=${OUT:-"$HERE/build-amiga"}
case "${CPU:-040}" in
    040) CPUFLAGS="-m68040 -specs=$SPECS" ;;
    060) CPUFLAGS="-m68060" ;;
    *) echo "CPU is 040 or 060 (builds are 68040 only, with a 68060 variant)"; exit 2 ;;
esac
SRC="$HERE/src/opencrypto_sha256.c $HERE/src/opencrypto_sha512.c $HERE/src/opencrypto_sha1.c
     $HERE/src/opencrypto_x25519.c $HERE/src/opencrypto_ed25519.c
     $HERE/src/opencrypto_sntrup761.c $HERE/src/opencrypto_chacha20.c $HERE/src/opencrypto_ghash.c $HERE/src/opencrypto_ecdh.c
     $HERE/src/opencrypto_aes.c $HERE/src/opencrypto_pubkey.c $HERE/src/opencrypto_pss.c"

mkdir -p "$OUT/include/gfopencrypto" "$OUT/include/libraries" \
         "$OUT/include/inline" "$OUT/include/proto" "$OUT/lib" "$OUT/tests" "$OUT/obj"

cp "$HERE/include/gfopencrypto/gfopencrypto.h" "$OUT/include/gfopencrypto/"
cp "$HERE/include/libraries/gfopencrypto.h" "$OUT/include/libraries/"
cp "$HERE/include/inline/gfopencrypto.h" "$OUT/include/inline/"
cp "$HERE/include/proto/gfopencrypto.h" "$OUT/include/proto/"

# -fno-tree-loop-distribute-patterns: the stove's GCC 16.2.0b turns a loop
# that shifts an array up (v[i] = v[i - 1], i falling) into an inline
# forward copy, which corrupts it (src/opencrypto_sntrup761.c says more)
# -fno-delete-null-pointer-checks: address 0 is memory on an Amiga; without
# it GCC puts TRAP #7 (Software Failure 80000027) where it proves a pointer
# null, in place of the access
CFLAGS="$CPUFLAGS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer -Wall -Wextra -Werror -Wno-unused-parameter -I$HERE/include -I$HERE/library"

# the magic functions' tags are assembly: no LTO for that file (ac_magic.h)
"$CC" $CFLAGS -fno-lto -mcrt=nix20 -c "$HERE/library/oc_magic.c" -o "$OUT/obj/oc_magic.o"

"$CC" $CFLAGS -mcrt=nix20 -fno-toplevel-reorder -nostartfiles \
  -o "$OUT/lib/gfopencrypto.library" \
  "$HERE/library/opencrypto_lib.c" $SRC "$OUT/obj/oc_magic.o" \
  -lamiga -lgcc -Wl,-Map,"$OUT/lib/gfopencrypto.library.map"

echo "$OUT/lib/gfopencrypto.library ($(wc -c < "$OUT/lib/gfopencrypto.library") bytes)"
"$P/bin/m68k-amigaos-nm" -u "$OUT/lib/gfopencrypto.library"

"$CC" $CFLAGS -noixemul -o "$OUT/tests/GFOpenCryptoLibTest" "$HERE/tests/test_library.c"
"$CC" $CFLAGS -noixemul -I"$HERE/tests" -o "$OUT/tests/GFOpenCryptoVectors" "$HERE/tests/test_ssh_primitives.c" $SRC
"$CC" $CFLAGS -noixemul -I"$HERE/tests" -o "$OUT/tests/GFOpenCryptoBench" "$HERE/tests/bench_library.c" \
  "$HERE/src/opencrypto_sha256.c"

if [ -n "${FPCR_CHECK:-}" ]; then
    python3 "$FPCR_CHECK" "$P/bin/m68k-amigaos-objdump" "$OUT/lib/gfopencrypto.library" \
        "$OUT/tests/GFOpenCryptoVectors" "$OUT/tests/GFOpenCryptoBench"
fi
for f in GFOpenCryptoLibTest GFOpenCryptoVectors GFOpenCryptoBench; do
    echo "$OUT/tests/$f ($(wc -c < "$OUT/tests/$f") bytes)"
done
sha256sum "$OUT/lib/gfopencrypto.library"
