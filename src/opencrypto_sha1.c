/* SHA-1, our own code from FIPS 180-4 (August 2015): the functions of
 * section 4.1.1, the constants of 4.2.1, the padding of 5.1.1, the initial
 * value of 5.3.1 and the computation of 6.1.2.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * SHA-1 is no longer collision resistant (SHAttered, 2017). It is here for
 * formats and protocols that name it: file identity checks, legacy
 * signatures' digests, HMAC-SHA1 users. New designs use SHA-256.
 *
 * The message schedule is the 16-word circular form FIPS 180-4 gives in
 * section 6.1.3, so a block needs 64 bytes of stack, not 320. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

static uint32_t rotl(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void transform(uint32_t h[5], const uint8_t block[64])
{
    uint32_t w[16];
    uint32_t a, b, c, d, e, f, k, t;
    unsigned i, s;

    for (i = 0; i < 16; ++i)
        w[i] = load_be32(block + i * 4);

    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

    for (i = 0; i < 80; ++i) {
        s = i & 15;
        if (i >= 16)
            w[s] = rotl(w[(s + 13) & 15] ^ w[(s + 8) & 15] ^
                        w[(s + 2) & 15] ^ w[s], 1);
        if (i < 20) {
            f = (b & c) ^ (~b & d);              /* Ch */
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;                       /* Parity */
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) ^ (b & d) ^ (c & d);     /* Maj */
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;                       /* Parity */
            k = 0xca62c1d6u;
        }
        t = rotl(a, 5) + f + e + k + w[s];
        e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void oc_sha1_init(OCSHA1 *ctx)
{
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xefcdab89u;
    ctx->h[2] = 0x98badcfeu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xc3d2e1f0u;
    ctx->total_bytes = 0;
    ctx->block_used = 0;
}

void oc_sha1_update(OCSHA1 *ctx, const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->total_bytes += length;
    while (length) {
        size_t n = OC_SHA1_BLOCK_BYTES - ctx->block_used;
        if (n > length) n = length;
        memcpy(ctx->block + ctx->block_used, p, n);
        ctx->block_used += n;
        p += n;
        length -= n;
        if (ctx->block_used == OC_SHA1_BLOCK_BYTES) {
            transform(ctx->h, ctx->block);
            ctx->block_used = 0;
        }
    }
}

void oc_sha1_final(OCSHA1 *ctx, uint8_t out[OC_SHA1_BYTES])
{
    uint64_t bits = ctx->total_bytes * 8u;
    unsigned i;

    ctx->block[ctx->block_used++] = 0x80;
    if (ctx->block_used > 56) {
        memset(ctx->block + ctx->block_used, 0, 64 - ctx->block_used);
        transform(ctx->h, ctx->block);
        ctx->block_used = 0;
    }
    memset(ctx->block + ctx->block_used, 0, 56 - ctx->block_used);
    for (i = 0; i < 8; ++i)
        ctx->block[63 - i] = (uint8_t)(bits >> (i * 8));
    transform(ctx->h, ctx->block);
    for (i = 0; i < 5; ++i)
        store_be32(out + i * 4, ctx->h[i]);
    oc_cleanse(ctx, sizeof *ctx);
}

void oc_sha1(const void *data, size_t length, uint8_t out[OC_SHA1_BYTES])
{
    OCSHA1 ctx;
    oc_sha1_init(&ctx);
    oc_sha1_update(&ctx, data, length);
    oc_sha1_final(&ctx, out);
}

/* The compression function over whole blocks, the chaining value kept as
 * 20 bytes, big-endian (as oc_sha256_blocks). */
void oc_sha1_blocks(uint8_t state[OC_SHA1_BYTES], const void *data, size_t nblocks)
{
    uint32_t h[5];
    const uint8_t *p = (const uint8_t *)data;
    unsigned i;
    for (i = 0; i < 5; ++i)
        h[i] = load_be32(state + i * 4);
    for (; nblocks; --nblocks, p += 64)
        transform(h, p);
    for (i = 0; i < 5; ++i)
        store_be32(state + i * 4, h[i]);
    oc_cleanse(h, sizeof h);
}
