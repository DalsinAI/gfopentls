/* GFOpenCrypto: X25519 (RFC 7748), constant time.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * The Montgomery ladder over the u coordinate, 255 steps whatever the
 * scalar, with conditional swaps by mask (no branch on a secret bit).
 *
 * The field elements here are ten signed limbs of 26 and 25 bits in turn
 * (limb i at bit ceil(25.5 i)), the radix Bernstein's Curve25519 paper
 * (2006, section 4) describes: a product is 100 products of 32-bit values
 * into 64 bits (MULS.L on the 68020 to 68040), against 256 for the 16-limb
 * form Ed25519 uses (oc_fe25519.h). A term's position over 255 bits comes
 * back as 19 times itself (2^255 = 19 mod p), and two odd limbs' product
 * sits one bit higher, so it is doubled. Limbs are kept within 2^25 or
 * 2^24 of zero after each product, so sums of two stay safe to multiply
 * by 19 in 32 bits. */
#include "gfopencrypto/gfopencrypto.h"
#include "oc_fe25519.h"

typedef int32_t fe[10];

/* the product's columns back to limbs within 2^25 / 2^24 of zero: carries
 * rounded to nearest, the one out of the top limb coming back as 19 times
 * itself */
#define CARRY26(i) do { c = (t[i] + ((int64_t)1 << 25)) >> 26; t[(i) + 1] += c; t[i] -= c * ((int64_t)1 << 26); } while (0)
#define CARRY25(i) do { c = (t[i] + ((int64_t)1 << 24)) >> 25; t[(i) + 1] += c; t[i] -= c * ((int64_t)1 << 25); } while (0)
static void fe_carry(fe h, int64_t t[10])
{
    int64_t c;
    CARRY26(0); CARRY25(1); CARRY26(2); CARRY25(3); CARRY26(4);
    CARRY25(5); CARRY26(6); CARRY25(7); CARRY26(8);
    c = (t[9] + ((int64_t)1 << 24)) >> 25;
    t[0] += c * 19;
    t[9] -= c * ((int64_t)1 << 25);
    CARRY26(0);
    h[0] = (int32_t)t[0]; h[1] = (int32_t)t[1]; h[2] = (int32_t)t[2]; h[3] = (int32_t)t[3];
    h[4] = (int32_t)t[4]; h[5] = (int32_t)t[5]; h[6] = (int32_t)t[6]; h[7] = (int32_t)t[7];
    h[8] = (int32_t)t[8]; h[9] = (int32_t)t[9];
}

static void fe_mul(fe h, const fe f, const fe g)
{
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4], f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4], g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    int32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4, g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
    int32_t f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;
    int64_t t[10];
    t[0] = (int64_t)f0 * g0
           + (int64_t)f1_2 * g9_19
           + (int64_t)f2 * g8_19
           + (int64_t)f3_2 * g7_19
           + (int64_t)f4 * g6_19
           + (int64_t)f5_2 * g5_19
           + (int64_t)f6 * g4_19
           + (int64_t)f7_2 * g3_19
           + (int64_t)f8 * g2_19
           + (int64_t)f9_2 * g1_19;
    t[1] = (int64_t)f0 * g1
           + (int64_t)f1 * g0
           + (int64_t)f2 * g9_19
           + (int64_t)f3 * g8_19
           + (int64_t)f4 * g7_19
           + (int64_t)f5 * g6_19
           + (int64_t)f6 * g5_19
           + (int64_t)f7 * g4_19
           + (int64_t)f8 * g3_19
           + (int64_t)f9 * g2_19;
    t[2] = (int64_t)f0 * g2
           + (int64_t)f1_2 * g1
           + (int64_t)f2 * g0
           + (int64_t)f3_2 * g9_19
           + (int64_t)f4 * g8_19
           + (int64_t)f5_2 * g7_19
           + (int64_t)f6 * g6_19
           + (int64_t)f7_2 * g5_19
           + (int64_t)f8 * g4_19
           + (int64_t)f9_2 * g3_19;
    t[3] = (int64_t)f0 * g3
           + (int64_t)f1 * g2
           + (int64_t)f2 * g1
           + (int64_t)f3 * g0
           + (int64_t)f4 * g9_19
           + (int64_t)f5 * g8_19
           + (int64_t)f6 * g7_19
           + (int64_t)f7 * g6_19
           + (int64_t)f8 * g5_19
           + (int64_t)f9 * g4_19;
    t[4] = (int64_t)f0 * g4
           + (int64_t)f1_2 * g3
           + (int64_t)f2 * g2
           + (int64_t)f3_2 * g1
           + (int64_t)f4 * g0
           + (int64_t)f5_2 * g9_19
           + (int64_t)f6 * g8_19
           + (int64_t)f7_2 * g7_19
           + (int64_t)f8 * g6_19
           + (int64_t)f9_2 * g5_19;
    t[5] = (int64_t)f0 * g5
           + (int64_t)f1 * g4
           + (int64_t)f2 * g3
           + (int64_t)f3 * g2
           + (int64_t)f4 * g1
           + (int64_t)f5 * g0
           + (int64_t)f6 * g9_19
           + (int64_t)f7 * g8_19
           + (int64_t)f8 * g7_19
           + (int64_t)f9 * g6_19;
    t[6] = (int64_t)f0 * g6
           + (int64_t)f1_2 * g5
           + (int64_t)f2 * g4
           + (int64_t)f3_2 * g3
           + (int64_t)f4 * g2
           + (int64_t)f5_2 * g1
           + (int64_t)f6 * g0
           + (int64_t)f7_2 * g9_19
           + (int64_t)f8 * g8_19
           + (int64_t)f9_2 * g7_19;
    t[7] = (int64_t)f0 * g7
           + (int64_t)f1 * g6
           + (int64_t)f2 * g5
           + (int64_t)f3 * g4
           + (int64_t)f4 * g3
           + (int64_t)f5 * g2
           + (int64_t)f6 * g1
           + (int64_t)f7 * g0
           + (int64_t)f8 * g9_19
           + (int64_t)f9 * g8_19;
    t[8] = (int64_t)f0 * g8
           + (int64_t)f1_2 * g7
           + (int64_t)f2 * g6
           + (int64_t)f3_2 * g5
           + (int64_t)f4 * g4
           + (int64_t)f5_2 * g3
           + (int64_t)f6 * g2
           + (int64_t)f7_2 * g1
           + (int64_t)f8 * g0
           + (int64_t)f9_2 * g9_19;
    t[9] = (int64_t)f0 * g9
           + (int64_t)f1 * g8
           + (int64_t)f2 * g7
           + (int64_t)f3 * g6
           + (int64_t)f4 * g5
           + (int64_t)f5 * g4
           + (int64_t)f6 * g3
           + (int64_t)f7 * g2
           + (int64_t)f8 * g1
           + (int64_t)f9 * g0;
    fe_carry(h, t);
}

static void fe_sq(fe h, const fe f)
{
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4], f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int64_t t[10];
    t[0] = (int64_t)f0 * f0
           + (int64_t)(f1 * 4) * (f9 * 19)
           + (int64_t)(f2 * 2) * (f8 * 19)
           + (int64_t)(f3 * 4) * (f7 * 19)
           + (int64_t)(f4 * 2) * (f6 * 19)
           + (int64_t)(f5 * 2) * (f5 * 19);
    t[1] = (int64_t)(f0 * 2) * f1
           + (int64_t)(f2 * 2) * (f9 * 19)
           + (int64_t)(f3 * 2) * (f8 * 19)
           + (int64_t)(f4 * 2) * (f7 * 19)
           + (int64_t)(f5 * 2) * (f6 * 19);
    t[2] = (int64_t)(f0 * 2) * f2
           + (int64_t)(f1 * 2) * f1
           + (int64_t)(f3 * 4) * (f9 * 19)
           + (int64_t)(f4 * 2) * (f8 * 19)
           + (int64_t)(f5 * 4) * (f7 * 19)
           + (int64_t)f6 * (f6 * 19);
    t[3] = (int64_t)(f0 * 2) * f3
           + (int64_t)(f1 * 2) * f2
           + (int64_t)(f4 * 2) * (f9 * 19)
           + (int64_t)(f5 * 2) * (f8 * 19)
           + (int64_t)(f6 * 2) * (f7 * 19);
    t[4] = (int64_t)(f0 * 2) * f4
           + (int64_t)(f1 * 4) * f3
           + (int64_t)f2 * f2
           + (int64_t)(f5 * 4) * (f9 * 19)
           + (int64_t)(f6 * 2) * (f8 * 19)
           + (int64_t)(f7 * 2) * (f7 * 19);
    t[5] = (int64_t)(f0 * 2) * f5
           + (int64_t)(f1 * 2) * f4
           + (int64_t)(f2 * 2) * f3
           + (int64_t)(f6 * 2) * (f9 * 19)
           + (int64_t)(f7 * 2) * (f8 * 19);
    t[6] = (int64_t)(f0 * 2) * f6
           + (int64_t)(f1 * 4) * f5
           + (int64_t)(f2 * 2) * f4
           + (int64_t)(f3 * 2) * f3
           + (int64_t)(f7 * 4) * (f9 * 19)
           + (int64_t)f8 * (f8 * 19);
    t[7] = (int64_t)(f0 * 2) * f7
           + (int64_t)(f1 * 2) * f6
           + (int64_t)(f2 * 2) * f5
           + (int64_t)(f3 * 2) * f4
           + (int64_t)(f8 * 2) * (f9 * 19);
    t[8] = (int64_t)(f0 * 2) * f8
           + (int64_t)(f1 * 4) * f7
           + (int64_t)(f2 * 2) * f6
           + (int64_t)(f3 * 4) * f5
           + (int64_t)f4 * f4
           + (int64_t)(f9 * 2) * (f9 * 19);
    t[9] = (int64_t)(f0 * 2) * f9
           + (int64_t)(f1 * 2) * f8
           + (int64_t)(f2 * 2) * f7
           + (int64_t)(f3 * 2) * f6
           + (int64_t)(f4 * 2) * f5;
    fe_carry(h, t);
}

static void fe_add(fe h, const fe f, const fe g)
{
    int i;
    for (i = 0; i < 10; ++i) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g)
{
    int i;
    for (i = 0; i < 10; ++i) h[i] = f[i] - g[i];
}

/* h = f * 121665 ((A - 2) / 4 for Curve25519's A = 486662) */
static void fe_mul121665(fe h, const fe f)
{
    int64_t t[10];
    int i;
    for (i = 0; i < 10; ++i) t[i] = (int64_t)f[i] * 121665;
    fe_carry(h, t);
}

static void fe_cswap(fe f, fe g, int32_t mask)
{
    int i;
    for (i = 0; i < 10; ++i) {
        int32_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

static void fe_sq_n(fe h, const fe f, int n)
{
    fe_sq(h, f);
    while (--n > 0) fe_sq(h, h);
}

/* z^(p - 2) = 1/z: 254 squares and 11 products */
static void fe_invert(fe out, const fe z)
{
    fe z2, z9, z11, z5, z10, z20, z50, z100, t;
    fe_sq(z2, z);
    fe_sq_n(t, z2, 2);
    fe_mul(z9, t, z);
    fe_mul(z11, z9, z2);
    fe_sq(t, z11);
    fe_mul(z5, t, z9);                  /* z^(2^5 - 1) */
    fe_sq_n(t, z5, 5);
    fe_mul(z10, t, z5);                 /* z^(2^10 - 1) */
    fe_sq_n(t, z10, 10);
    fe_mul(z20, t, z10);
    fe_sq_n(t, z20, 20);
    fe_mul(t, t, z20);                  /* z^(2^40 - 1) */
    fe_sq_n(t, t, 10);
    fe_mul(z50, t, z10);
    fe_sq_n(t, z50, 50);
    fe_mul(z100, t, z50);
    fe_sq_n(t, z100, 100);
    fe_mul(t, t, z100);                 /* z^(2^200 - 1) */
    fe_sq_n(t, t, 50);
    fe_mul(t, t, z50);                  /* z^(2^250 - 1) */
    fe_sq_n(t, t, 5);
    fe_mul(out, t, z11);                /* z^(2^255 - 21) */
}

/* 32 little-endian bytes, the top bit ignored */
static void fe_frombytes(fe h, const uint8_t s[32])
{
    static const unsigned char pos[10] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
    int i, b;
    for (i = 0; i < 10; ++i) {
        int width = (i & 1) ? 25 : 26;
        uint32_t v = 0;
        for (b = 0; b < width; ++b) {
            int bit = pos[i] + b;
            if (bit < 255) v |= (uint32_t)((s[bit >> 3] >> (bit & 7)) & 1) << b;
        }
        h[i] = (int32_t)v;
    }
}

/* the canonical 32 bytes: limbs made non-negative and laid out as bytes,
 * then the 16-limb form's reduction below p */
static void fe_tobytes(uint8_t s[32], const fe f)
{
    static const unsigned char pos[10] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
    int64_t t[10], c;
    oc_gf g;
    int i, k;
    for (i = 0; i < 10; ++i) t[i] = f[i];
    for (k = 0; k < 2; ++k) {                       /* floor carries: all limbs >= 0 */
        for (i = 0; i < 9; ++i) {
            int w = (i & 1) ? 25 : 26;
            c = t[i] >> w;
            t[i + 1] += c;
            t[i] -= c * ((int64_t)1 << w);
        }
        c = t[9] >> 25;
        t[0] += 19 * c;
        t[9] -= c * ((int64_t)1 << 25);
    }
    for (i = 0; i < 9; ++i) {
        int w = (i & 1) ? 25 : 26;
        c = t[i] >> w;
        t[i + 1] += c;
        t[i] -= c * ((int64_t)1 << w);
    }
    memset(s, 0, 32);
    for (i = 0; i < 10; ++i) {
        uint32_t v = (uint32_t)t[i];
        int width = (i & 1) ? 25 : 26, b;
        for (b = 0; b < width; ++b) {
            int bit = pos[i] + b;
            if (bit < 256) s[bit >> 3] |= (uint8_t)(((v >> b) & 1) << (bit & 7));
        }
    }
    gf_unpack(g, s);                                /* below 2^255 by now */
    gf_pack(s, g);
    oc_cleanse(t, sizeof t);
    oc_cleanse(g, sizeof g);
}

int oc_x25519(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES],
              const uint8_t point[OC_X25519_BYTES])
{
    uint8_t z[32];
    fe x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb;
    int i;
    int32_t swap = 0, bit;
    uint8_t zero = 0;

    for (i = 0; i < 32; ++i) z[i] = scalar[i];
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;
    fe_frombytes(x1, point);
    memset(x2, 0, sizeof x2); x2[0] = 1;
    memset(z2, 0, sizeof z2);
    memcpy(x3, x1, sizeof x3);
    memset(z3, 0, sizeof z3); z3[0] = 1;
    /* RFC 7748 section 5's ladder */
    for (i = 254; i >= 0; --i) {
        bit = -(int32_t)((z[i >> 3] >> (i & 7)) & 1);
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;
        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b, x2, z2);
        fe_sq(bb, b);
        fe_sub(e, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);
        fe_add(x3, da, cb);
        fe_sq(x3, x3);
        fe_sub(z3, da, cb);
        fe_sq(z3, z3);
        fe_mul(z3, z3, x1);
        fe_mul(x2, aa, bb);
        fe_mul121665(z2, e);
        fe_add(z2, z2, aa);
        fe_mul(z2, z2, e);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
    oc_cleanse(z, sizeof z);
    oc_cleanse(x2, sizeof x2); oc_cleanse(z2, sizeof z2); oc_cleanse(x3, sizeof x3);
    oc_cleanse(z3, sizeof z3); oc_cleanse(a, sizeof a); oc_cleanse(aa, sizeof aa);
    oc_cleanse(b, sizeof b); oc_cleanse(bb, sizeof bb); oc_cleanse(e, sizeof e);
    oc_cleanse(c, sizeof c); oc_cleanse(d, sizeof d); oc_cleanse(da, sizeof da);
    oc_cleanse(cb, sizeof cb);
    /* an all-zero result (a small-order point) is refused, as RFC 7748
     * section 6.1 allows and SSH requires; the test is constant time */
    for (i = 0; i < 32; ++i) zero |= out[i];
    return zero ? 0 : -1;
}

void oc_x25519_base(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES])
{
    static const uint8_t nine[32] = { 9 };
    (void)oc_x25519(out, scalar, nine);
}
