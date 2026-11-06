/* GFOpenCrypto: point multiplication on the NIST curves P-256, P-384 and
 * P-521, in constant time, for ECDH key exchange (TLS's ECDHE).
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Field elements are 32-bit limbs in Montgomery form; the product is CIOS
 * with its last subtraction taken by mask, and additions and subtractions
 * correct by mask too. Points are projective (X:Y:Z) and use Renes,
 * Costello and Batina's complete formulas for a = -3 ("Complete addition
 * formulas for prime order elliptic curves", 2016, algorithms 4 and 6):
 * they hold for every pair of points, the point at infinity and doubling
 * included, so nothing branches on a secret. The scalar is taken four bits
 * at a time from a table of 0 Q .. 15 Q, read whole for every window.
 *
 * P-256 skips Montgomery's reduction: a product is reduced with the
 * curve's special form (FIPS 186-4 appendix D.2.3), word sums only, so
 * its field elements are kept plain (its "R" is 1). */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

#define K_MAX 17                            /* limbs: P-521 */

typedef uint32_t limb;

typedef struct {
    int bits, k, bytes, p256;
    limb p[K_MAX], m0inv, rr[K_MAX], one[K_MAX], b[K_MAX];
    limb gx[K_MAX], gy[K_MAX];              /* plain */
} curve;

typedef struct { limb x[K_MAX], y[K_MAX], z[K_MAX]; } point;

static const struct {
    int bits;
    const char *p, *b, *gx, *gy;            /* hex, big-endian */
} defs[] = {
    { 256,
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" },
    { 384,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
      "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
      "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" },
    { 521,
      "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650" },
};

static void from_bytes(limb *x, int k, const uint8_t *b, size_t len)
{
    size_t i;
    memset(x, 0, (size_t)k * sizeof(limb));
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        if (bit / 32 < (size_t)k) x[bit / 32] |= (limb)b[i] << (bit % 32);
    }
}

static void to_bytes(uint8_t *b, size_t len, const limb *x, int k)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        b[i] = bit / 32 < (size_t)k ? (uint8_t)(x[bit / 32] >> (bit % 32)) : 0;
    }
}

static void from_hex(limb *x, int k, const char *h)
{
    uint8_t b[4 * K_MAX];
    size_t n = strlen(h) / 2, i;
    for (i = 0; i < n; ++i) {
        unsigned v = 0;
        int j;
        for (j = 0; j < 2; ++j) {
            char c = h[2 * i + j];
            v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        b[i] = (uint8_t)v;
    }
    from_bytes(x, k, b, n);
}

/* r = a - b, the borrow returned (0 or 1) */
static limb sub_n(limb *r, const limb *a, const limb *b, int k)
{
    limb c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        uint64_t d = (uint64_t)a[i] - b[i] - c;
        r[i] = (limb)d;
        c = (limb)(d >> 63);
    }
    return c;
}

static limb add_n(limb *r, const limb *a, const limb *b, int k)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        c += (uint64_t)a[i] + b[i];
        r[i] = (limb)c;
        c >>= 32;
    }
    return (limb)c;
}

/* r = a when mask is all ones, else r unchanged */
static void cmov(limb *r, const limb *a, limb mask, int k)
{
    int i;
    for (i = 0; i < k; ++i) r[i] ^= mask & (r[i] ^ a[i]);
}

/* operands below p */
static void f_add(limb *r, const limb *a, const limb *b, const curve *C)
{
    limb t[K_MAX];
    limb carry = add_n(r, a, b, C->k);
    limb borrow = sub_n(t, r, C->p, C->k);
    cmov(r, t, (limb)0 - (carry | (borrow ^ 1)), C->k);
}

static void f_sub(limb *r, const limb *a, const limb *b, const curve *C)
{
    limb t[K_MAX];
    limb borrow = sub_n(r, a, b, C->k);
    add_n(t, r, C->p, C->k);
    cmov(r, t, (limb)0 - borrow, C->k);
}

/* The 512-bit products for P-256. On the 68020/030/040 (not the 68060,
 * which traps 32x32->64 multiplies), written out column by column in
 * assembly: each product added straight into a three-word accumulator
 * (generated). */
#if defined(__GNUC__) && !defined(__mc68060__) \
    && (defined(__mc68020__) || defined(__mc68030__) || defined(__mc68040__))
#define P256_MUL_ASM \
    "\tmoveq #0,%%d5\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,4(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,8(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,12(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,16(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,20(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,24(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l (%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,28(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,32(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,36(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,40(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,44(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,48(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,52(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a1),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,56(%%a2)\n" \
    "\tmove.l %%d2,60(%%a2)\n" \
    ""
#define P256_SQR_ASM \
    "\tmoveq #0,%%d5\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l (%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 4(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,4(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 8(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 4(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,8(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 12(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,12(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 16(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 8(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,16(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,20(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 12(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,24(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l (%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,28(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 4(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 16(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,32(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l 8(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,36(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l 12(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 20(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,40(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 16(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,44(%%a2)\n" \
    "\tmoveq #0,%%d4\n" \
    "\tmove.l 20(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 24(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d2\n" \
    "\taddx.l %%d1,%%d3\n" \
    "\taddx.l %%d5,%%d4\n" \
    "\tmove.l %%d2,48(%%a2)\n" \
    "\tmoveq #0,%%d2\n" \
    "\tmove.l 24(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tadd.l %%d0,%%d3\n" \
    "\taddx.l %%d1,%%d4\n" \
    "\taddx.l %%d5,%%d2\n" \
    "\tmove.l %%d3,52(%%a2)\n" \
    "\tmoveq #0,%%d3\n" \
    "\tmove.l 28(%%a0),%%d0\n" \
    "\tmulu.l 28(%%a0),%%d1:%%d0\n" \
    "\tadd.l %%d0,%%d4\n" \
    "\taddx.l %%d1,%%d2\n" \
    "\taddx.l %%d5,%%d3\n" \
    "\tmove.l %%d4,56(%%a2)\n" \
    "\tmove.l %%d2,60(%%a2)\n" \
    ""

static void p256_prod(limb c[16], const limb *a, const limb *b)
{
    register const limb *ra __asm__("a0") = a;
    register const limb *rb __asm__("a1") = b;
    register limb *rc __asm__("a2") = c;
    __asm__ volatile(P256_MUL_ASM : : "a"(ra), "a"(rb), "a"(rc)
                     : "d0", "d1", "d2", "d3", "d4", "d5", "cc", "memory");
}

static void p256_square(limb c[16], const limb *a)
{
    register const limb *ra __asm__("a0") = a;
    register limb *rc __asm__("a2") = c;
    __asm__ volatile(P256_SQR_ASM : : "a"(ra), "a"(rc)
                     : "d0", "d1", "d2", "d3", "d4", "d5", "cc", "memory");
}
#else
static void p256_prod(limb c[16], const limb *a, const limb *b)
{
    int i, j;
    memset(c, 0, 16 * sizeof(limb));
    for (i = 0; i < 8; ++i) {
        uint64_t cy = 0;
        limb bi = b[i];
        for (j = 0; j < 8; ++j) {
            cy += (uint64_t)c[i + j] + (uint64_t)a[j] * bi;
            c[i + j] = (limb)cy;
            cy >>= 32;
        }
        c[i + 8] = (limb)cy;
    }
}

static void p256_square(limb c[16], const limb *a)
{
    p256_prod(c, a, a);
}
#endif

static void p256_reduce(limb *r, const limb *c, const curve *C);

/* P-256: r = a b mod p, a and b below p */
static void p256_mul(limb *r, const limb *a, const limb *b, const curve *C)
{
    limb c[16];
    p256_prod(c, a, b);
    p256_reduce(r, c, C);
}

/* P-256: r = a^2 mod p (each cross product once, doubled, in the
 * assembly) */
static void p256_sqr(limb *r, const limb *a, const curve *C)
{
    limb c[16];
    p256_square(c, a);
    p256_reduce(r, c, C);
}

/* P-256: r = c mod p, c a 512-bit product (FIPS 186-4 D.2.3) */
static void p256_reduce(limb *r, const limb *c, const curve *C)
{
    limb t[8];
    int64_t acc[8], k;
    int i, round;
    limb borrow;
    /* s1 + 2 s2 + 2 s3 + s4 + s5 - s6 - s7 - s8 - s9, word by word */
    acc[0] = (int64_t)c[0] + (int64_t)c[8] + (int64_t)c[9] - (int64_t)c[11] - (int64_t)c[12] - (int64_t)c[13] - (int64_t)c[14];
    acc[1] = (int64_t)c[1] + (int64_t)c[9] + (int64_t)c[10] - (int64_t)c[12] - (int64_t)c[13] - (int64_t)c[14] - (int64_t)c[15];
    acc[2] = (int64_t)c[2] + (int64_t)c[10] + (int64_t)c[11] - (int64_t)c[13] - (int64_t)c[14] - (int64_t)c[15];
    acc[3] = (int64_t)c[3] + 2 * (int64_t)c[11] + 2 * (int64_t)c[12] + (int64_t)c[13] - (int64_t)c[15] - (int64_t)c[8] - (int64_t)c[9];
    acc[4] = (int64_t)c[4] + 2 * (int64_t)c[12] + 2 * (int64_t)c[13] + (int64_t)c[14] - (int64_t)c[9] - (int64_t)c[10];
    acc[5] = (int64_t)c[5] + 2 * (int64_t)c[13] + 2 * (int64_t)c[14] + (int64_t)c[15] - (int64_t)c[10] - (int64_t)c[11];
    acc[6] = (int64_t)c[6] + 2 * (int64_t)c[14] + 2 * (int64_t)c[15] + (int64_t)c[14] + (int64_t)c[13] - (int64_t)c[8] - (int64_t)c[9];
    acc[7] = (int64_t)c[7] + 2 * (int64_t)c[15] + (int64_t)c[15] + (int64_t)c[8] - (int64_t)c[10] - (int64_t)c[11] - (int64_t)c[12] - (int64_t)c[13];
    /* carries; what passes 2^256 comes back as 2^224 - 2^192 - 2^96 + 1 */
    for (round = 0; round < 3; ++round) {
        k = 0;
        for (i = 0; i < 8; ++i) {
            acc[i] += k;
            k = acc[i] >> 32;                   /* floor */
            acc[i] -= k * ((int64_t)1 << 32);
        }
        acc[0] += k; acc[3] -= k; acc[6] -= k; acc[7] += k;
    }
    for (i = 0, k = 0; i < 8; ++i) {
        acc[i] += k;
        k = acc[i] >> 32;
        r[i] = (limb)acc[i];
    }
    /* below 2^256 now: take p away once when it is at or above p */
    borrow = sub_n(t, r, C->p, 8);
    cmov(r, t, (limb)0 - (borrow ^ 1), 8);
}

/* r = a b / 2^(32k) mod p (r may be a or b) */
static void mont_mul(limb *r, const limb *a, const limb *b, const curve *C)
{
    limb t[K_MAX + 2], u[K_MAX];
    int i, j, k = C->k;
    limb borrow;
    memset(t, 0, sizeof(limb) * (size_t)(k + 2));
    for (i = 0; i < k; ++i) {
        uint64_t c = 0, s;
        limb m, bi = b[i];
        for (j = 0; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * bi;
            t[j] = (limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k] = (limb)s;
        t[k + 1] = (limb)(s >> 32);
        m = t[0] * C->m0inv;
        c = ((uint64_t)t[0] + (uint64_t)m * C->p[0]) >> 32;
        for (j = 1; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)m * C->p[j];
            t[j - 1] = (limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k - 1] = (limb)s;
        t[k] = t[k + 1] + (limb)(s >> 32);
    }
    borrow = sub_n(u, t, C->p, k);
    cmov(t, u, (limb)0 - (t[k] | (borrow ^ 1)), k);
    memcpy(r, t, (size_t)k * sizeof(limb));
}

static void f_mul(limb *r, const limb *a, const limb *b, const curve *C)
{
    if (C->p256) p256_mul(r, a, b, C);
    else mont_mul(r, a, b, C);
}

static void f_sqr(limb *r, const limb *a, const curve *C)
{
    if (C->p256) p256_sqr(r, a, C);
    else mont_mul(r, a, a, C);
}

static int curve_init(curve *C, int bits)
{
    limb x = 1, t[K_MAX];
    int i, d = -1;
    for (i = 0; i < 3; ++i) if (defs[i].bits == bits) d = i;
    if (d < 0) return -1;
    memset(C, 0, sizeof *C);
    C->bits = bits;
    C->k = (bits + 31) / 32;
    C->bytes = (bits + 7) / 8;
    from_hex(C->p, C->k, defs[d].p);
    for (i = 0; i < 5; ++i) x *= 2 - C->p[0] * x;   /* 1/p mod 2^32, Newton */
    C->m0inv = (limb)0 - x;
    memset(t, 0, sizeof t);
    t[0] = 1;
    if (bits == 256) C->p256 = 1;               /* plain form: R = 1 */
    else                                        /* R^2 mod p: 1 doubled 64k times */
        for (i = 0; i < 64 * C->k; ++i) f_add(t, t, t, C);
    memcpy(C->rr, t, sizeof t);
    memset(t, 0, sizeof t);
    t[0] = 1;
    f_mul(C->one, t, C->rr, C);
    from_hex(t, C->k, defs[d].b);
    f_mul(C->b, t, C->rr, C);
    from_hex(C->gx, C->k, defs[d].gx);
    from_hex(C->gy, C->k, defs[d].gy);
    return 0;
}

/* RCB algorithm 4: r = p + q (r may be p or q) */
static void pt_add(point *r, const point *P, const point *Q, const curve *C)
{
    limb t0[K_MAX], t1[K_MAX], t2[K_MAX], t3[K_MAX], t4[K_MAX];
    limb X3[K_MAX], Y3[K_MAX], Z3[K_MAX];
    f_mul(t0, P->x, Q->x, C);  f_mul(t1, P->y, Q->y, C);  f_mul(t2, P->z, Q->z, C);
    f_add(t3, P->x, P->y, C);  f_add(t4, Q->x, Q->y, C);  f_mul(t3, t3, t4, C);
    f_add(t4, t0, t1, C);      f_sub(t3, t3, t4, C);      f_add(t4, P->y, P->z, C);
    f_add(X3, Q->y, Q->z, C);  f_mul(t4, t4, X3, C);      f_add(X3, t1, t2, C);
    f_sub(t4, t4, X3, C);      f_add(X3, P->x, P->z, C);  f_add(Y3, Q->x, Q->z, C);
    f_mul(X3, X3, Y3, C);      f_add(Y3, t0, t2, C);      f_sub(Y3, X3, Y3, C);
    f_mul(Z3, C->b, t2, C);    f_sub(X3, Y3, Z3, C);      f_add(Z3, X3, X3, C);
    f_add(X3, X3, Z3, C);      f_sub(Z3, t1, X3, C);      f_add(X3, t1, X3, C);
    f_mul(Y3, C->b, Y3, C);    f_add(t1, t2, t2, C);      f_add(t2, t1, t2, C);
    f_sub(Y3, Y3, t2, C);      f_sub(Y3, Y3, t0, C);      f_add(t1, Y3, Y3, C);
    f_add(Y3, t1, Y3, C);      f_add(t1, t0, t0, C);      f_add(t0, t1, t0, C);
    f_sub(t0, t0, t2, C);      f_mul(t1, t4, Y3, C);      f_mul(t2, t0, Y3, C);
    f_mul(Y3, X3, Z3, C);      f_add(Y3, Y3, t2, C);      f_mul(X3, t3, X3, C);
    f_sub(X3, X3, t1, C);      f_mul(Z3, t4, Z3, C);      f_mul(t1, t3, t0, C);
    f_add(Z3, Z3, t1, C);
    memcpy(r->x, X3, sizeof X3);
    memcpy(r->y, Y3, sizeof Y3);
    memcpy(r->z, Z3, sizeof Z3);
}

/* RCB algorithm 6: r = 2 p (r may be p) */
static void pt_double(point *r, const point *P, const curve *C)
{
    limb t0[K_MAX], t1[K_MAX], t2[K_MAX], t3[K_MAX], X3[K_MAX], Y3[K_MAX], Z3[K_MAX];
    f_sqr(t0, P->x, C);        f_sqr(t1, P->y, C);        f_sqr(t2, P->z, C);
    f_mul(t3, P->x, P->y, C);  f_add(t3, t3, t3, C);      f_mul(Z3, P->x, P->z, C);
    f_add(Z3, Z3, Z3, C);      f_mul(Y3, C->b, t2, C);    f_sub(Y3, Y3, Z3, C);
    f_add(X3, Y3, Y3, C);      f_add(Y3, X3, Y3, C);      f_sub(X3, t1, Y3, C);
    f_add(Y3, t1, Y3, C);      f_mul(Y3, X3, Y3, C);      f_mul(X3, X3, t3, C);
    f_add(t3, t2, t2, C);      f_add(t2, t2, t3, C);      f_mul(Z3, C->b, Z3, C);
    f_sub(Z3, Z3, t2, C);      f_sub(Z3, Z3, t0, C);      f_add(t3, Z3, Z3, C);
    f_add(Z3, Z3, t3, C);      f_add(t3, t0, t0, C);      f_add(t0, t3, t0, C);
    f_sub(t0, t0, t2, C);      f_mul(t0, t0, Z3, C);      f_add(Y3, Y3, t0, C);
    f_mul(t0, P->y, P->z, C);  f_add(t0, t0, t0, C);      f_mul(Z3, t0, Z3, C);
    f_sub(X3, X3, Z3, C);      f_mul(Z3, t0, t1, C);      f_add(Z3, Z3, Z3, C);
    f_add(Z3, Z3, Z3, C);
    memcpy(r->x, X3, sizeof X3);
    memcpy(r->y, Y3, sizeof Y3);
    memcpy(r->z, Z3, sizeof Z3);
}

/* x^(p-2) = 1/x (p is public, so its bits may steer the loop) */
static void f_inv(limb *r, const limb *x, const curve *C)
{
    limb e[K_MAX], two[K_MAX], acc[K_MAX];
    int i;
    memset(two, 0, sizeof two);
    two[0] = 2;
    sub_n(e, C->p, two, C->k);
    memcpy(acc, C->one, sizeof acc);
    for (i = 32 * C->k - 1; i >= 0; --i) {
        f_sqr(acc, acc, C);
        if ((e[i / 32] >> (i % 32)) & 1) f_mul(acc, acc, x, C);
    }
    memcpy(r, acc, sizeof acc);
}

/* y^2 = x^3 - 3x + b, coordinates already below p (Montgomery form) */
static int on_curve(const point *P, const curve *C)
{
    limb t[K_MAX], u[K_MAX], three[K_MAX], d = 0;
    int i;
    f_add(three, C->one, C->one, C);
    f_add(three, three, C->one, C);
    f_mul(t, P->x, P->x, C);
    f_sub(t, t, three, C);
    f_mul(t, t, P->x, C);
    f_add(t, t, C->b, C);
    f_mul(u, P->y, P->y, C);
    for (i = 0; i < C->k; ++i) d |= t[i] ^ u[i];
    return d == 0;
}

static int below_p(const limb *x, const curve *C)
{
    limb t[K_MAX];
    return (int)sub_n(t, x, C->p, C->k);
}

/* point = scalar . point, the point as X9.62 uncompressed (04 || x || y) */
static int mul_point(uint8_t *pt, const uint8_t *scalar, size_t slen, const curve *C, int check)
{
    point table[16], Q, R, S;
    limb x[K_MAX], y[K_MAX], zi[K_MAX];
    int i, j, k = C->k, bytes = C->bytes, ok = 1;
    if (pt[0] != 0x04) return 0;
    from_bytes(x, k, pt + 1, (size_t)bytes);
    from_bytes(y, k, pt + 1 + bytes, (size_t)bytes);
    if (check && (!below_p(x, C) || !below_p(y, C))) return 0;
    memset(&Q, 0, sizeof Q);
    f_mul(Q.x, x, C->rr, C);
    f_mul(Q.y, y, C->rr, C);
    memcpy(Q.z, C->one, sizeof Q.z);
    if (check && !on_curve(&Q, C)) return 0;

    /* table[i] = i Q; table[0] the point at infinity (0 : 1 : 0) */
    memset(table, 0, sizeof table);
    memcpy(table[0].y, C->one, sizeof table[0].y);
    table[1] = Q;
    for (i = 2; i < 16; ++i) {
        if (i & 1) pt_add(&table[i], &table[i - 1], &Q, C);
        else pt_double(&table[i], &table[i / 2], C);
    }
    R = table[0];
    for (i = 0; i < (int)slen; ++i) {
        int w;
        for (w = 4; w >= 0; w -= 4) {
            limb n = (limb)((scalar[i] >> w) & 15);
            pt_double(&R, &R, C);
            pt_double(&R, &R, C);
            pt_double(&R, &R, C);
            pt_double(&R, &R, C);
            /* S = table[n], every entry read */
            memset(&S, 0, sizeof S);
            for (j = 0; j < 16; ++j) {
                limb d = (limb)j ^ n;
                limb mask = (limb)0 - (limb)(((d | (0 - d)) >> 31) ^ 1);
                cmov(S.x, table[j].x, mask, k);
                cmov(S.y, table[j].y, mask, k);
                cmov(S.z, table[j].z, mask, k);
            }
            pt_add(&R, &R, &S, C);
        }
    }

    /* back to affine; a result at infinity (Z = 0) fails */
    f_inv(zi, R.z, C);
    f_mul(x, R.x, zi, C);
    f_mul(y, R.y, zi, C);
    {
        limb z = 0;
        for (i = 0; i < k; ++i) z |= R.z[i];
        ok = z != 0;
    }
    memset(zi, 0, sizeof zi);
    zi[0] = 1;
    f_mul(x, x, zi, C);                     /* out of Montgomery form */
    f_mul(y, y, zi, C);
    to_bytes(pt + 1, (size_t)bytes, x, k);
    to_bytes(pt + 1 + bytes, (size_t)bytes, y, k);
    oc_cleanse(table, sizeof table);
    oc_cleanse(&R, sizeof R);
    oc_cleanse(&S, sizeof S);
    return ok;
}

int oc_ec_mul(int curve_bits, uint8_t *point, size_t point_length,
              const uint8_t *scalar, size_t scalar_length)
{
    curve C;
    if (curve_init(&C, curve_bits)) return 0;
    if (point_length != (size_t)(1 + 2 * C.bytes)) return 0;
    return mul_point(point, scalar, scalar_length, &C, 1);
}

int oc_ec_mulgen(int curve_bits, uint8_t *point, const uint8_t *scalar, size_t scalar_length)
{
    curve C;
    if (curve_init(&C, curve_bits)) return 0;
    point[0] = 0x04;
    to_bytes(point + 1, (size_t)C.bytes, C.gx, C.k);
    to_bytes(point + 1 + C.bytes, (size_t)C.bytes, C.gy, C.k);
    return mul_point(point, scalar, scalar_length, &C, 0) ? 1 + 2 * C.bytes : 0;
}
