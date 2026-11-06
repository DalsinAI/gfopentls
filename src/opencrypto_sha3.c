/* GFOpenCrypto: SHA3-256, SHA3-384, SHA3-512 and SHAKE256 (FIPS 202).
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Keccak-f[1600] on 25 64-bit lanes; bytes go into a lane little-endian
 * (FIPS 202 section 3.1.2), on every machine. The sponge: rate r bytes =
 * 200 - 2 * the output's bytes (SHA-3) or 136 (SHAKE256); the domain bits
 * 01 (SHA-3) or 1111 (SHAKE) come before the pad10*1 padding. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

static const uint64_t round_const[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808a),
    UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008a),
    UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b), UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a), UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008) };

/* rho's offsets, by lane x + 5y (FIPS 202 table 2) */
static const unsigned char rho_off[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14 };

static uint64_t rotl64(uint64_t x, unsigned n)
{
    return n ? (x << n) | (x >> (64 - n)) : x;
}

static void keccak_f(uint64_t a[25])
{
    uint64_t c[5], d[5], b[25];
    int r, x, y;
    for (r = 0; r < 24; ++r) {
        /* theta */
        for (x = 0; x < 5; ++x)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (x = 0; x < 5; ++x)
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (x = 0; x < 25; ++x)
            a[x] ^= d[x % 5];
        /* rho and pi: B[y, 2x + 3y] = rot(A[x, y]) */
        for (y = 0; y < 5; ++y)
            for (x = 0; x < 5; ++x)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], rho_off[x + 5 * y]);
        /* chi */
        for (y = 0; y < 25; y += 5)
            for (x = 0; x < 5; ++x)
                a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
        /* iota */
        a[0] ^= round_const[r];
    }
}

void oc_keccak_f1600(uint64_t state[25])
{
    keccak_f(state);
}

int oc_sha3_init(OCSHA3 *ctx, int variant)
{
    memset(ctx, 0, sizeof *ctx);
    switch (variant) {
    case OC_SHA3_256: ctx->rate = 136; ctx->out_length = 32; ctx->domain = 0x06; break;
    case OC_SHA3_384: ctx->rate = 104; ctx->out_length = 48; ctx->domain = 0x06; break;
    case OC_SHA3_512: ctx->rate = 72;  ctx->out_length = 64; ctx->domain = 0x06; break;
    case OC_SHAKE256: ctx->rate = 136; ctx->out_length = 0;  ctx->domain = 0x1f; break;
    default: return -1;
    }
    return 0;
}

static void xor_byte(uint64_t *a, unsigned i, uint8_t v)
{
    a[i >> 3] ^= (uint64_t)v << (8 * (i & 7));
}

void oc_sha3_update(OCSHA3 *ctx, const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;
    while (length) {
        if (!ctx->used && length >= ctx->rate) {        /* whole blocks, a lane at a time */
            unsigned i, j;
            for (i = 0; i < ctx->rate / 8; ++i) {
                uint64_t v = 0;
                for (j = 0; j < 8; ++j) v |= (uint64_t)p[8 * i + j] << (8 * j);
                ctx->a[i] ^= v;
            }
            keccak_f(ctx->a);
            p += ctx->rate;
            length -= ctx->rate;
            continue;
        }
        xor_byte(ctx->a, ctx->used, *p++);
        --length;
        if (++ctx->used == ctx->rate) {
            keccak_f(ctx->a);
            ctx->used = 0;
        }
    }
}

/* the digest (out_length must be the variant's size), or for SHAKE256 any
 * number of bytes; the context is wiped */
int oc_sha3_final(OCSHA3 *ctx, uint8_t *out, size_t out_length)
{
    unsigned i = 0;
    if (ctx->out_length && out_length != ctx->out_length) {
        oc_cleanse(ctx, sizeof *ctx);
        return -1;
    }
    xor_byte(ctx->a, ctx->used, ctx->domain);
    xor_byte(ctx->a, ctx->rate - 1, 0x80);
    keccak_f(ctx->a);
    while (out_length--) {
        if (i == ctx->rate) {
            keccak_f(ctx->a);
            i = 0;
        }
        *out++ = (uint8_t)(ctx->a[i >> 3] >> (8 * (i & 7)));
        ++i;
    }
    oc_cleanse(ctx, sizeof *ctx);
    return 0;
}

int oc_sha3(int variant, const void *data, size_t length, uint8_t *out, size_t out_length)
{
    OCSHA3 ctx;
    if (oc_sha3_init(&ctx, variant)) return -1;
    oc_sha3_update(&ctx, data, length);
    return oc_sha3_final(&ctx, out, out_length);
}
