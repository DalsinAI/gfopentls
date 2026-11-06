/* GFOpenCrypto: GHASH (NIST SP 800-38D, section 6.4), AES-GCM's hash, in
 * constant time. Our own code from the specification's algorithm 1: one
 * bit of X at a time, Z picking up V under a mask and V halving with the
 * reduction under a mask, so there is no table, no multiply and no branch
 * on a secret. Words are big-endian, so bit 0 of a block is bit 31 of
 * its first word.
 * Copyright (c) 2026 AmiCradle Team. MIT. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

static uint32_t be32(const uint8_t *p)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    if (!((uintptr_t)p & 1)) return *(const uint32_t *)(const void *)p;
#endif
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* y = y . h in GF(2^128) */
static void mul(uint32_t y[4], const uint32_t h[4])
{
#if defined(__GNUC__) && defined(__mc68000__)
    /* the 68k: each bit's mask from the carry (add, subx), V's halving one
     * shift and three rotates through X, the reduction's mask from X */
    uint32_t z[4] = { 0, 0, 0, 0 };
    uint32_t v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3], x, m, t, r;
    int i;
    for (i = 0; i < 4; ++i) {
        void *n = (void *)32;
        uint32_t *zp = z;
        x = y[i];
        __asm__ volatile(
            "1:\n\t"
            "add.l %[x],%[x]\n\t"
            "subx.l %[m],%[m]\n\t"
            "move.l %[v0],%[t]\n\tand.l %[m],%[t]\n\teor.l %[t],(%[z])\n\t"
            "move.l %[v1],%[t]\n\tand.l %[m],%[t]\n\teor.l %[t],4(%[z])\n\t"
            "move.l %[v2],%[t]\n\tand.l %[m],%[t]\n\teor.l %[t],8(%[z])\n\t"
            "move.l %[v3],%[t]\n\tand.l %[m],%[t]\n\teor.l %[t],12(%[z])\n\t"
            "lsr.l #1,%[v0]\n\troxr.l #1,%[v1]\n\troxr.l #1,%[v2]\n\troxr.l #1,%[v3]\n\t"
            "subx.l %[r],%[r]\n\t"
            "and.l #0xe1000000,%[r]\n\t"
            "eor.l %[r],%[v0]\n\t"
            "subq.l #1,%[n]\n\t"
            "tst.l %[n]\n\t"
            "bne.s 1b"
            : [v0] "+d"(v0), [v1] "+d"(v1), [v2] "+d"(v2), [v3] "+d"(v3), [x] "+d"(x),
              [m] "=&d"(m), [t] "=&d"(t), [r] "=&d"(r), [n] "+a"(n)
            : [z] "a"(zp)
            : "cc", "memory");
    }
    y[0] = z[0]; y[1] = z[1]; y[2] = z[2]; y[3] = z[3];
#else
    uint32_t z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    uint32_t v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
    int i, j;
    for (i = 0; i < 4; ++i) {
        uint32_t x = y[i];
        for (j = 0; j < 32; ++j) {
            uint32_t m = (uint32_t)-(int32_t)(x >> 31);   /* all ones when the bit is set */
            uint32_t r = (uint32_t)-(int32_t)(v3 & 1);
            z0 ^= v0 & m; z1 ^= v1 & m; z2 ^= v2 & m; z3 ^= v3 & m;
            v3 = (v3 >> 1) | (v2 << 31);
            v2 = (v2 >> 1) | (v1 << 31);
            v1 = (v1 >> 1) | (v0 << 31);
            v0 = (v0 >> 1) ^ (0xe1000000u & r);
            x <<= 1;
        }
    }
    y[0] = z0; y[1] = z1; y[2] = z2; y[3] = z3;
#endif
}

void oc_ghash(uint8_t y[16], const uint8_t h[16], const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t yw[4], hw[4];
    uint8_t last[16];
    int i;
    for (i = 0; i < 4; ++i) { yw[i] = be32(y + 4 * i); hw[i] = be32(h + 4 * i); }
    while (length) {
        const uint8_t *b = p;
        size_t n = 16;
        if (length < 16) {                      /* the last part, padded with zeros */
            memset(last, 0, sizeof last);
            memcpy(last, p, length);
            b = last;
            n = length;
        }
        for (i = 0; i < 4; ++i) yw[i] ^= be32(b + 4 * i);
        mul(yw, hw);
        p += n;
        length -= n;
    }
    for (i = 0; i < 4; ++i) put_be32(y + 4 * i, yw[i]);
    oc_cleanse(hw, sizeof hw);
    oc_cleanse(last, sizeof last);
}
