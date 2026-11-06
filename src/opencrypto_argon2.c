/* GFOpenCrypto: Argon2 (RFC 9106), version 0x13, types d, i and id, and
 * the BLAKE2b (RFC 7693) it is built on.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * PuTTY's version 3 key files name Argon2id by default and may name
 * Argon2i or Argon2d, so all three are here; they differ only in how the
 * reference blocks are chosen. Lanes are filled one after another, slice by
 * slice, which gives the same memory as filling them at once: a block only
 * refers to other lanes' blocks in finished slices. The memory, m' blocks of
 * 1 KB (m' = m rounded down to a multiple of 4 * lanes, at least 8 * lanes),
 * comes from the caller: oc_argon2_memory() says how much. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

/* ---- BLAKE2b ---- */

typedef struct {
    uint64_t h[8], t;
    uint8_t b[128];
    size_t c, outlen;
} b2b;

static const uint64_t b2b_iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179) };

static const uint8_t sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 } };

static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

static uint64_t load64(const uint8_t *p)
{
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
           (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static void store64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define B2G(a, b, c, d, x, y) do {                       \
        v[a] = v[a] + v[b] + (x); v[d] = rotr64(v[d] ^ v[a], 32); \
        v[c] = v[c] + v[d];       v[b] = rotr64(v[b] ^ v[c], 24); \
        v[a] = v[a] + v[b] + (y); v[d] = rotr64(v[d] ^ v[a], 16); \
        v[c] = v[c] + v[d];       v[b] = rotr64(v[b] ^ v[c], 63); \
    } while (0)

static void b2b_compress(b2b *s, int last)
{
    uint64_t v[16], m[16];
    int i;
    for (i = 0; i < 8; ++i) { v[i] = s->h[i]; v[i + 8] = b2b_iv[i]; }
    v[12] ^= s->t;                      /* the counter's high word stays 0 here */
    if (last) v[14] = ~v[14];
    for (i = 0; i < 16; ++i) m[i] = load64(s->b + 8 * i);
    for (i = 0; i < 12; ++i) {
        const uint8_t *z = sigma[i];
        B2G(0, 4, 8, 12, m[z[0]], m[z[1]]);
        B2G(1, 5, 9, 13, m[z[2]], m[z[3]]);
        B2G(2, 6, 10, 14, m[z[4]], m[z[5]]);
        B2G(3, 7, 11, 15, m[z[6]], m[z[7]]);
        B2G(0, 5, 10, 15, m[z[8]], m[z[9]]);
        B2G(1, 6, 11, 12, m[z[10]], m[z[11]]);
        B2G(2, 7, 8, 13, m[z[12]], m[z[13]]);
        B2G(3, 4, 9, 14, m[z[14]], m[z[15]]);
    }
    for (i = 0; i < 8; ++i) s->h[i] ^= v[i] ^ v[i + 8];
}

static void b2b_init(b2b *s, size_t outlen)
{
    int i;
    for (i = 0; i < 8; ++i) s->h[i] = b2b_iv[i];
    s->h[0] ^= UINT64_C(0x01010000) ^ (uint64_t)outlen;
    s->t = 0;
    s->c = 0;
    s->outlen = outlen;
}

static void b2b_update(b2b *s, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    while (len--) {
        if (s->c == 128) {
            s->t += 128;
            b2b_compress(s, 0);
            s->c = 0;
        }
        s->b[s->c++] = *p++;
    }
}

static void b2b_final(b2b *s, uint8_t *out)
{
    uint8_t h[64];
    int i;
    s->t += s->c;
    while (s->c < 128) s->b[s->c++] = 0;
    b2b_compress(s, 1);
    for (i = 0; i < 8; ++i) store64(h + 8 * i, s->h[i]);
    memcpy(out, h, s->outlen);
    oc_cleanse(h, sizeof h);
    oc_cleanse(s, sizeof *s);
}

static void b2b_le32(b2b *s, uint32_t v)
{
    uint8_t b[4];
    store32(b, v);
    b2b_update(s, b, 4);
}

/* H' (RFC 9106 section 3.3): out_length bytes from in */
static void hprime(uint8_t *out, uint32_t out_length, const uint8_t *in, size_t in_length)
{
    b2b s;
    uint8_t v[64];
    if (out_length <= 64) {
        b2b_init(&s, out_length);
        b2b_le32(&s, out_length);
        b2b_update(&s, in, in_length);
        b2b_final(&s, out);
        return;
    }
    b2b_init(&s, 64);
    b2b_le32(&s, out_length);
    b2b_update(&s, in, in_length);
    b2b_final(&s, v);
    memcpy(out, v, 32);
    out += 32;
    out_length -= 32;
    while (out_length > 64) {
        b2b_init(&s, 64);
        b2b_update(&s, v, 64);
        b2b_final(&s, v);
        memcpy(out, v, 32);
        out += 32;
        out_length -= 32;
    }
    b2b_init(&s, out_length);
    b2b_update(&s, v, 64);
    b2b_final(&s, out);
    oc_cleanse(v, sizeof v);
}

/* ---- Argon2 ---- */

#define QW 128                          /* 64-bit words in a block */

typedef struct { uint64_t v[QW]; } block;

static uint64_t fBlaMka(uint64_t x, uint64_t y)
{
    return x + y + 2 * (uint64_t)(uint32_t)x * (uint32_t)y;
}

#define GB(a, b, c, d) do {                                   \
        a = fBlaMka(a, b); d = rotr64(d ^ a, 32);             \
        c = fBlaMka(c, d); b = rotr64(b ^ c, 24);             \
        a = fBlaMka(a, b); d = rotr64(d ^ a, 16);             \
        c = fBlaMka(c, d); b = rotr64(b ^ c, 63);             \
    } while (0)

/* P on 16 words, given by index */
static void perm(uint64_t *r, const int *ix)
{
    uint64_t *v0 = &r[ix[0]], *v1 = &r[ix[1]], *v2 = &r[ix[2]], *v3 = &r[ix[3]];
    uint64_t *v4 = &r[ix[4]], *v5 = &r[ix[5]], *v6 = &r[ix[6]], *v7 = &r[ix[7]];
    uint64_t *v8 = &r[ix[8]], *v9 = &r[ix[9]], *v10 = &r[ix[10]], *v11 = &r[ix[11]];
    uint64_t *v12 = &r[ix[12]], *v13 = &r[ix[13]], *v14 = &r[ix[14]], *v15 = &r[ix[15]];
    GB(*v0, *v4, *v8, *v12);
    GB(*v1, *v5, *v9, *v13);
    GB(*v2, *v6, *v10, *v14);
    GB(*v3, *v7, *v11, *v15);
    GB(*v0, *v5, *v10, *v15);
    GB(*v1, *v6, *v11, *v12);
    GB(*v2, *v7, *v8, *v13);
    GB(*v3, *v4, *v9, *v14);
}

/* G(x, y): out = (x ^ y) ^ P_cols(P_rows(x ^ y)); with_xor: out ^= that */
static void fill(block *out, const block *x, const block *y, int with_xor)
{
    block r, z;
    int i, j, ix[16];
    for (i = 0; i < QW; ++i) r.v[i] = z.v[i] = x->v[i] ^ y->v[i];
    for (i = 0; i < 8; ++i) {               /* rows: 16 consecutive words */
        for (j = 0; j < 16; ++j) ix[j] = 16 * i + j;
        perm(z.v, ix);
    }
    for (i = 0; i < 8; ++i) {               /* columns: word pairs 2i, 2i+1 of each row */
        for (j = 0; j < 8; ++j) {
            ix[2 * j] = 16 * j + 2 * i;
            ix[2 * j + 1] = 16 * j + 2 * i + 1;
        }
        perm(z.v, ix);
    }
    if (with_xor)
        for (i = 0; i < QW; ++i) out->v[i] ^= z.v[i] ^ r.v[i];
    else
        for (i = 0; i < QW; ++i) out->v[i] = z.v[i] ^ r.v[i];
    oc_cleanse(&r, sizeof r);
    oc_cleanse(&z, sizeof z);
}

static void block_from_bytes(block *b, const uint8_t *p)
{
    int i;
    for (i = 0; i < QW; ++i) b->v[i] = load64(p + 8 * i);
}

static void block_to_bytes(uint8_t *p, const block *b)
{
    int i;
    for (i = 0; i < QW; ++i) store64(p + 8 * i, b->v[i]);
}

static uint32_t mprime(uint32_t m_kib, uint32_t lanes)
{
    uint32_t m = m_kib;
    if (m < 8 * lanes) m = 8 * lanes;
    return m - m % (4 * lanes);
}

size_t oc_argon2_memory(uint32_t m_kib, uint32_t lanes)
{
    if (!lanes || lanes > 0xffffff) return 0;
    return (size_t)mprime(m_kib, lanes) * sizeof(block);
}

int oc_argon2(int type, uint8_t *out, uint32_t out_length,
              const void *password, size_t password_length,
              const void *salt, size_t salt_length,
              const void *secret, size_t secret_length,
              const void *ad, size_t ad_length,
              uint32_t t_cost, uint32_t m_kib, uint32_t lanes, void *memory)
{
    block *B = (block *)memory, zero, input, addr, tmp;
    uint8_t h0[64 + 8], buf[1024];
    uint32_t mp, lane_len, seg_len, pass, slice, lane, i;
    b2b s;

    if (type < OC_ARGON2D || type > OC_ARGON2ID || !out || out_length < 4 || !memory
        || !lanes || lanes > 0xffffff || !t_cost || m_kib < 8 * lanes || salt_length < 8
        || (!password && password_length) || (!salt && salt_length)
        || (!secret && secret_length) || (!ad && ad_length))
        return -1;
    mp = mprime(m_kib, lanes);
    lane_len = mp / lanes;
    seg_len = lane_len / 4;

    /* H0 */
    b2b_init(&s, 64);
    b2b_le32(&s, lanes);
    b2b_le32(&s, out_length);
    b2b_le32(&s, m_kib);
    b2b_le32(&s, t_cost);
    b2b_le32(&s, 0x13);
    b2b_le32(&s, (uint32_t)type);
    b2b_le32(&s, (uint32_t)password_length);
    b2b_update(&s, password, password_length);
    b2b_le32(&s, (uint32_t)salt_length);
    b2b_update(&s, salt, salt_length);
    b2b_le32(&s, (uint32_t)secret_length);
    b2b_update(&s, secret, secret_length);
    b2b_le32(&s, (uint32_t)ad_length);
    b2b_update(&s, ad, ad_length);
    b2b_final(&s, h0);

    /* the first two blocks of each lane */
    for (lane = 0; lane < lanes; ++lane) {
        for (i = 0; i < 2; ++i) {
            store32(h0 + 64, i);
            store32(h0 + 68, lane);
            hprime(buf, 1024, h0, 72);
            block_from_bytes(&B[lane * lane_len + i], buf);
        }
    }

    memset(&zero, 0, sizeof zero);
    for (pass = 0; pass < t_cost; ++pass) {
        for (slice = 0; slice < 4; ++slice) {
            for (lane = 0; lane < lanes; ++lane) {
                int indep = type == OC_ARGON2I || (type == OC_ARGON2ID && pass == 0 && slice < 2);
                uint32_t start = (pass == 0 && slice == 0) ? 2 : 0, idx;
                if (indep) {
                    memset(&input, 0, sizeof input);
                    input.v[0] = pass;
                    input.v[1] = lane;
                    input.v[2] = slice;
                    input.v[3] = mp;
                    input.v[4] = t_cost;
                    input.v[5] = (uint64_t)type;
                    if (start == 2) {
                        ++input.v[6];
                        fill(&tmp, &zero, &input, 0);
                        fill(&addr, &zero, &tmp, 0);
                    }
                }
                for (idx = start; idx < seg_len; ++idx) {
                    uint32_t cur = lane * lane_len + slice * seg_len + idx;
                    uint32_t prev = (cur % lane_len == 0) ? cur + lane_len - 1 : cur - 1;
                    uint64_t pr, rel, area, startpos;
                    uint32_t ref_lane, ref;
                    int same;
                    if (indep) {
                        if (idx % QW == 0) {
                            ++input.v[6];
                            fill(&tmp, &zero, &input, 0);
                            fill(&addr, &zero, &tmp, 0);
                        }
                        pr = addr.v[idx % QW];
                    } else {
                        pr = B[prev].v[0];
                    }
                    ref_lane = (uint32_t)((pr >> 32) % lanes);
                    if (pass == 0 && slice == 0) ref_lane = lane;
                    same = ref_lane == lane;
                    if (pass == 0) {
                        if (slice == 0) area = idx - 1;
                        else if (same) area = (uint64_t)slice * seg_len + idx - 1;
                        else area = (uint64_t)slice * seg_len - (idx == 0 ? 1 : 0);
                    } else {
                        if (same) area = (uint64_t)lane_len - seg_len + idx - 1;
                        else area = (uint64_t)lane_len - seg_len - (idx == 0 ? 1 : 0);
                    }
                    rel = pr & 0xffffffffu;
                    rel = (rel * rel) >> 32;
                    rel = area - 1 - ((area * rel) >> 32);
                    startpos = (pass != 0 && slice != 3) ? (uint64_t)(slice + 1) * seg_len : 0;
                    ref = ref_lane * lane_len + (uint32_t)((startpos + rel) % lane_len);
                    fill(&B[cur], &B[prev], &B[ref], pass != 0);
                }
            }
        }
    }

    /* the last column, xored, through H' */
    tmp = B[lane_len - 1];
    for (lane = 1; lane < lanes; ++lane)
        for (i = 0; i < QW; ++i) tmp.v[i] ^= B[lane * lane_len + lane_len - 1].v[i];
    block_to_bytes(buf, &tmp);
    hprime(out, out_length, buf, 1024);

    oc_cleanse(buf, sizeof buf);
    oc_cleanse(h0, sizeof h0);
    oc_cleanse(&tmp, sizeof tmp);
    oc_cleanse(&addr, sizeof addr);
    oc_cleanse(memory, (size_t)mp * sizeof(block));
    return 0;
}

/* BLAKE2b itself, unkeyed, 1 to 64 bytes out (Argon2's H; also for callers) */
int oc_blake2b(uint8_t *out, size_t out_length, const void *data, size_t length)
{
    b2b s;
    if (!out || !out_length || out_length > 64 || (!data && length)) return -1;
    b2b_init(&s, out_length);
    b2b_update(&s, data, length);
    b2b_final(&s, out);
    return 0;
}
