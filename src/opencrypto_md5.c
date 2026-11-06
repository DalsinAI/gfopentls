/* MD5, our own code from RFC 1321 (April 1992): the functions F, G, H and I
 * of section 3.4, the table T[i] = floor(2^32 |sin i|), the per-step shifts
 * and message word order of the four rounds, and the little-endian padding
 * of sections 3.1 and 3.2.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * MD5 is broken for collisions. It is here because TLS 1.0 and 1.1 name it
 * (their PRF and RSA signatures hash with MD5 and SHA-1 together); nothing
 * new should use it. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define G(x, y, z) ((((x) ^ (y)) & (z)) ^ (y))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define STEP(f, a, b, c, d, k, s, t) ((a) = (b) + ROTL((a) + f(b, c, d) + x[k] + (t), s))

static void transform(uint32_t h[4], const uint8_t *block)
{
    uint32_t x[16], a = h[0], b = h[1], c = h[2], d = h[3];
    int i;
    for (i = 0; i < 16; ++i) x[i] = le32(block + 4 * i);

    STEP(F, a, b, c, d,  0,  7, 0xd76aa478u); STEP(F, d, a, b, c,  1, 12, 0xe8c7b756u);
    STEP(F, c, d, a, b,  2, 17, 0x242070dbu); STEP(F, b, c, d, a,  3, 22, 0xc1bdceeeu);
    STEP(F, a, b, c, d,  4,  7, 0xf57c0fafu); STEP(F, d, a, b, c,  5, 12, 0x4787c62au);
    STEP(F, c, d, a, b,  6, 17, 0xa8304613u); STEP(F, b, c, d, a,  7, 22, 0xfd469501u);
    STEP(F, a, b, c, d,  8,  7, 0x698098d8u); STEP(F, d, a, b, c,  9, 12, 0x8b44f7afu);
    STEP(F, c, d, a, b, 10, 17, 0xffff5bb1u); STEP(F, b, c, d, a, 11, 22, 0x895cd7beu);
    STEP(F, a, b, c, d, 12,  7, 0x6b901122u); STEP(F, d, a, b, c, 13, 12, 0xfd987193u);
    STEP(F, c, d, a, b, 14, 17, 0xa679438eu); STEP(F, b, c, d, a, 15, 22, 0x49b40821u);

    STEP(G, a, b, c, d,  1,  5, 0xf61e2562u); STEP(G, d, a, b, c,  6,  9, 0xc040b340u);
    STEP(G, c, d, a, b, 11, 14, 0x265e5a51u); STEP(G, b, c, d, a,  0, 20, 0xe9b6c7aau);
    STEP(G, a, b, c, d,  5,  5, 0xd62f105du); STEP(G, d, a, b, c, 10,  9, 0x02441453u);
    STEP(G, c, d, a, b, 15, 14, 0xd8a1e681u); STEP(G, b, c, d, a,  4, 20, 0xe7d3fbc8u);
    STEP(G, a, b, c, d,  9,  5, 0x21e1cde6u); STEP(G, d, a, b, c, 14,  9, 0xc33707d6u);
    STEP(G, c, d, a, b,  3, 14, 0xf4d50d87u); STEP(G, b, c, d, a,  8, 20, 0x455a14edu);
    STEP(G, a, b, c, d, 13,  5, 0xa9e3e905u); STEP(G, d, a, b, c,  2,  9, 0xfcefa3f8u);
    STEP(G, c, d, a, b,  7, 14, 0x676f02d9u); STEP(G, b, c, d, a, 12, 20, 0x8d2a4c8au);

    STEP(H, a, b, c, d,  5,  4, 0xfffa3942u); STEP(H, d, a, b, c,  8, 11, 0x8771f681u);
    STEP(H, c, d, a, b, 11, 16, 0x6d9d6122u); STEP(H, b, c, d, a, 14, 23, 0xfde5380cu);
    STEP(H, a, b, c, d,  1,  4, 0xa4beea44u); STEP(H, d, a, b, c,  4, 11, 0x4bdecfa9u);
    STEP(H, c, d, a, b,  7, 16, 0xf6bb4b60u); STEP(H, b, c, d, a, 10, 23, 0xbebfbc70u);
    STEP(H, a, b, c, d, 13,  4, 0x289b7ec6u); STEP(H, d, a, b, c,  0, 11, 0xeaa127fau);
    STEP(H, c, d, a, b,  3, 16, 0xd4ef3085u); STEP(H, b, c, d, a,  6, 23, 0x04881d05u);
    STEP(H, a, b, c, d,  9,  4, 0xd9d4d039u); STEP(H, d, a, b, c, 12, 11, 0xe6db99e5u);
    STEP(H, c, d, a, b, 15, 16, 0x1fa27cf8u); STEP(H, b, c, d, a,  2, 23, 0xc4ac5665u);

    STEP(I, a, b, c, d,  0,  6, 0xf4292244u); STEP(I, d, a, b, c,  7, 10, 0x432aff97u);
    STEP(I, c, d, a, b, 14, 15, 0xab9423a7u); STEP(I, b, c, d, a,  5, 21, 0xfc93a039u);
    STEP(I, a, b, c, d, 12,  6, 0x655b59c3u); STEP(I, d, a, b, c,  3, 10, 0x8f0ccc92u);
    STEP(I, c, d, a, b, 10, 15, 0xffeff47du); STEP(I, b, c, d, a,  1, 21, 0x85845dd1u);
    STEP(I, a, b, c, d,  8,  6, 0x6fa87e4fu); STEP(I, d, a, b, c, 15, 10, 0xfe2ce6e0u);
    STEP(I, c, d, a, b,  6, 15, 0xa3014314u); STEP(I, b, c, d, a, 13, 21, 0x4e0811a1u);
    STEP(I, a, b, c, d,  4,  6, 0xf7537e82u); STEP(I, d, a, b, c, 11, 10, 0xbd3af235u);
    STEP(I, c, d, a, b,  2, 15, 0x2ad7d2bbu); STEP(I, b, c, d, a,  9, 21, 0xeb86d391u);

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

/* The compression function over whole 64-byte blocks, the chaining value
 * kept as 16 bytes, little-endian (MD5's own order). */
void oc_md5_blocks(uint8_t state[OC_MD5_BYTES], const void *data, size_t nblocks)
{
    uint32_t h[4];
    const uint8_t *p = (const uint8_t *)data;
    int i;
    for (i = 0; i < 4; ++i) h[i] = le32(state + 4 * i);
    for (; nblocks; --nblocks, p += 64) transform(h, p);
    for (i = 0; i < 4; ++i) put_le32(state + 4 * i, h[i]);
}

void oc_md5(const void *data, size_t length, uint8_t out[OC_MD5_BYTES])
{
    static const uint8_t iv[16] = { 0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
                                    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10 };
    uint8_t last[128];
    size_t whole = length / 64, rest = length % 64, total;
    uint64_t bits = (uint64_t)length * 8;
    int i;
    memcpy(out, iv, 16);
    oc_md5_blocks(out, data, whole);
    memcpy(last, (const uint8_t *)data + whole * 64, rest);
    last[rest] = 0x80;
    total = rest < 56 ? 64 : 128;
    memset(last + rest + 1, 0, total - rest - 1);
    for (i = 0; i < 8; ++i) last[total - 8 + i] = (uint8_t)(bits >> (8 * i));
    oc_md5_blocks(out, last, total / 64);
    oc_cleanse(last, sizeof last);
}
