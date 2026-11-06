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
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    if (!((uintptr_t)p & 1)) return *(const uint32_t *)(const void *)p;   /* the 68k: one move */
#endif
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

/* word i of the schedule, made in place from the 16 before it (i >= 16) */
#define SCHED(i) (w[(i) & 15] = rotl(w[((i) + 13) & 15] ^ w[((i) + 8) & 15] ^ \
                                    w[((i) + 2) & 15] ^ w[(i) & 15], 1))
#define CH(b, c, d)  ((((c) ^ (d)) & (b)) ^ (d))
#define PAR(b, c, d) ((b) ^ (c) ^ (d))
#define MAJ(b, c, d) (((b) & (c)) | (((b) | (c)) & (d)))
/* one step, the five working words renamed rather than moved */
#define STEP(a, b, c, d, e, F, k, wi) do { \
    (e) += rotl(a, 5) + F(b, c, d) + (k) + (wi); (b) = rotl(b, 30); } while (0)
#define FIVE(F, k, i, W) do { \
    STEP(a, b, c, d, e, F, k, W(i));     STEP(e, a, b, c, d, F, k, W((i) + 1)); \
    STEP(d, e, a, b, c, F, k, W((i) + 2)); STEP(c, d, e, a, b, F, k, W((i) + 3)); \
    STEP(b, c, d, e, a, F, k, W((i) + 4)); } while (0)
#define WIN(i) w[i]

static void transform(uint32_t h[5], const uint8_t block[64])
{
    uint32_t w[16];
    uint32_t a, b, c, d, e;
    unsigned i;

    for (i = 0; i < 16; ++i)
        w[i] = load_be32(block + i * 4);

    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

    FIVE(CH, 0x5a827999u, 0, WIN);
    FIVE(CH, 0x5a827999u, 5, WIN);
    FIVE(CH, 0x5a827999u, 10, WIN);
    STEP(a, b, c, d, e, CH, 0x5a827999u, w[15]);
    STEP(e, a, b, c, d, CH, 0x5a827999u, SCHED(16));
    STEP(d, e, a, b, c, CH, 0x5a827999u, SCHED(17));
    STEP(c, d, e, a, b, CH, 0x5a827999u, SCHED(18));
    STEP(b, c, d, e, a, CH, 0x5a827999u, SCHED(19));
    /* written out: the schedule's indexes are then constants */
    FIVE(PAR, 0x6ed9eba1u, 20, SCHED); FIVE(PAR, 0x6ed9eba1u, 25, SCHED);
    FIVE(PAR, 0x6ed9eba1u, 30, SCHED); FIVE(PAR, 0x6ed9eba1u, 35, SCHED);
    FIVE(MAJ, 0x8f1bbcdcu, 40, SCHED); FIVE(MAJ, 0x8f1bbcdcu, 45, SCHED);
    FIVE(MAJ, 0x8f1bbcdcu, 50, SCHED); FIVE(MAJ, 0x8f1bbcdcu, 55, SCHED);
    FIVE(PAR, 0xca62c1d6u, 60, SCHED); FIVE(PAR, 0xca62c1d6u, 65, SCHED);
    FIVE(PAR, 0xca62c1d6u, 70, SCHED); FIVE(PAR, 0xca62c1d6u, 75, SCHED);

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
        size_t n;
        if (!ctx->block_used && length >= OC_SHA1_BLOCK_BYTES) {   /* whole blocks: no copy */
            transform(ctx->h, p);
            p += OC_SHA1_BLOCK_BYTES;
            length -= OC_SHA1_BLOCK_BYTES;
            continue;
        }
        n = OC_SHA1_BLOCK_BYTES - ctx->block_used;
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
