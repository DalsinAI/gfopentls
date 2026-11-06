/* GFOpenCrypto: HMAC (RFC 2104) over SHA-1, SHA-256, SHA-384 and SHA-512,
 * and PBKDF2 (RFC 8018 section 5.2) over the same.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Everything runs on the block functions (oc_sha1_blocks and the rest) with
 * the chaining value as big-endian bytes. The key's inner and outer states
 * are made once; PBKDF2's later rounds hash a digest that fits one padded
 * block, so each round is two compressions and nothing else. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

typedef struct {
    size_t out, state, block;               /* bytes */
    void (*blocks)(uint8_t *state, const void *data, size_t nblocks);
    const uint8_t *iv;
} hdef;

static const uint8_t iv_sha1[20] = {
    0x67,0x45,0x23,0x01, 0xef,0xcd,0xab,0x89, 0x98,0xba,0xdc,0xfe,
    0x10,0x32,0x54,0x76, 0xc3,0xd2,0xe1,0xf0 };
static const uint8_t iv_sha256[32] = {
    0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85, 0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
    0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c, 0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19 };
static const uint8_t iv_sha384[64] = {
    0xcb,0xbb,0x9d,0x5d,0xc1,0x05,0x9e,0xd8, 0x62,0x9a,0x29,0x2a,0x36,0x7c,0xd5,0x07,
    0x91,0x59,0x01,0x5a,0x30,0x70,0xdd,0x17, 0x15,0x2f,0xec,0xd8,0xf7,0x0e,0x59,0x39,
    0x67,0x33,0x26,0x67,0xff,0xc0,0x0b,0x31, 0x8e,0xb4,0x4a,0x87,0x68,0x58,0x15,0x11,
    0xdb,0x0c,0x2e,0x0d,0x64,0xf9,0x8f,0xa7, 0x47,0xb5,0x48,0x1d,0xbe,0xfa,0x4f,0xa4 };
static const uint8_t iv_sha512[64] = {
    0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08, 0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
    0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b, 0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
    0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1, 0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
    0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b, 0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79 };

static void blocks_sha1(uint8_t *s, const void *d, size_t n) { oc_sha1_blocks(s, d, n); }
static void blocks_sha256(uint8_t *s, const void *d, size_t n) { oc_sha256_blocks(s, d, n); }
static void blocks_sha512(uint8_t *s, const void *d, size_t n) { oc_sha512_blocks(s, d, n); }

static int hash_def(int hash, hdef *h)
{
    switch (hash) {
    case OC_HASH_SHA1:   h->out = 20; h->state = 20; h->block = 64;  h->blocks = blocks_sha1;   h->iv = iv_sha1;   return 0;
    case OC_HASH_SHA256: h->out = 32; h->state = 32; h->block = 64;  h->blocks = blocks_sha256; h->iv = iv_sha256; return 0;
    case OC_HASH_SHA384: h->out = 48; h->state = 64; h->block = 128; h->blocks = blocks_sha512; h->iv = iv_sha384; return 0;
    case OC_HASH_SHA512: h->out = 64; h->state = 64; h->block = 128; h->blocks = blocks_sha512; h->iv = iv_sha512; return 0;
    }
    return -1;
}

size_t oc_hash_length(int hash)
{
    hdef h;
    return hash_def(hash, &h) ? 0 : h.out;
}

/* the last block(s): data (len < block bytes) then the padding, for a
 * message of total bytes; state is the chaining value */
static void finish(const hdef *h, uint8_t *state, const uint8_t *data, size_t len, uint64_t total)
{
    uint8_t buf[256];
    size_t lenbytes = h->block == 64 ? 8 : 16, n = len + 1, i;
    memcpy(buf, data, len);
    buf[len] = 0x80;
    if (n + lenbytes > h->block) n = 2 * h->block;
    else n = h->block;
    memset(buf + len + 1, 0, n - len - 1);
    total <<= 3;
    for (i = 0; i < 8; ++i)
        buf[n - 1 - i] = (uint8_t)(total >> (8 * i));
    h->blocks(state, buf, n / h->block);
    oc_cleanse(buf, n);
}

static void hash_data(const hdef *h, uint8_t *state, uint64_t done, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t whole = len / h->block;
    if (whole) h->blocks(state, p, whole);
    finish(h, state, p + whole * h->block, len - whole * h->block, done + len);
}

/* the states after the key xor ipad and xor opad */
static void key_states(const hdef *h, const void *key, size_t key_length,
                       uint8_t *istate, uint8_t *ostate)
{
    uint8_t k[128], pad[128];
    size_t i;
    memset(k, 0, sizeof k);
    if (key_length > h->block) {
        memcpy(istate, h->iv, h->state);
        hash_data(h, istate, 0, key, key_length);
        memcpy(k, istate, h->out);
    } else if (key_length) {
        memcpy(k, key, key_length);
    }
    for (i = 0; i < h->block; ++i) pad[i] = k[i] ^ 0x36;
    memcpy(istate, h->iv, h->state);
    h->blocks(istate, pad, 1);
    for (i = 0; i < h->block; ++i) pad[i] = k[i] ^ 0x5c;
    memcpy(ostate, h->iv, h->state);
    h->blocks(ostate, pad, 1);
    oc_cleanse(k, sizeof k);
    oc_cleanse(pad, sizeof pad);
}

static void outer(const hdef *h, const uint8_t *ostate, uint8_t *inner_state, uint8_t *out)
{
    uint8_t s[64];
    memcpy(s, ostate, h->state);
    finish(h, s, inner_state, h->out, h->block + h->out);
    memcpy(out, s, h->out);
    oc_cleanse(s, sizeof s);
}

int oc_hmac(int hash, const void *key, size_t key_length,
            const void *data, size_t data_length, uint8_t *out)
{
    hdef h;
    uint8_t is[64], os[64];
    if (hash_def(hash, &h) || !out || (!key && key_length) || (!data && data_length)) return -1;
    key_states(&h, key, key_length, is, os);
    hash_data(&h, is, h.block, data, data_length);
    outer(&h, os, is, out);
    oc_cleanse(is, sizeof is);
    oc_cleanse(os, sizeof os);
    return 0;
}

void oc_hmac_sha1(const void *key, size_t key_length, const void *data, size_t data_length,
                  uint8_t out[OC_SHA1_BYTES])
{
    oc_hmac(OC_HASH_SHA1, key, key_length, data, data_length, out);
}

void oc_hmac_sha512(const void *key, size_t key_length, const void *data, size_t data_length,
                    uint8_t out[OC_SHA512_BYTES])
{
    oc_hmac(OC_HASH_SHA512, key, key_length, data, data_length, out);
}

int oc_pbkdf2(int hash, const void *password, size_t password_length,
              const void *salt, size_t salt_length, uint32_t iterations,
              void *out, size_t out_length)
{
    hdef h;
    uint8_t is[64], os[64], s[64], u[256], t[64];
    uint8_t *dst = (uint8_t *)out;
    const uint8_t *sp = (const uint8_t *)salt;
    uint32_t block = 0, j;
    size_t i, ublock;
    if (hash_def(hash, &h) || !iterations || (!out && out_length)
        || (!password && password_length) || (!salt && salt_length))
        return -1;
    ublock = h.block;                   /* U padded: digest, 0x80, zeros, length */
    key_states(&h, password, password_length, is, os);
    while (out_length) {
        size_t take = out_length < h.out ? out_length : h.out;
        uint8_t ctr[4];
        ++block;
        if (!block) { oc_cleanse(is, sizeof is); oc_cleanse(os, sizeof os); return -1; }
        ctr[0] = (uint8_t)(block >> 24); ctr[1] = (uint8_t)(block >> 16);
        ctr[2] = (uint8_t)(block >> 8);  ctr[3] = (uint8_t)block;
        /* U1 = HMAC(P, S || INT(i)): the salt's whole blocks, then the rest */
        memcpy(s, is, h.state);
        {
            size_t whole = salt_length / h.block, rest = salt_length - whole * h.block;
            uint8_t tail[128 + 4];
            if (whole) h.blocks(s, sp, whole);
            memcpy(tail, sp + whole * h.block, rest);
            memcpy(tail + rest, ctr, 4);
            if (rest + 4 > h.block) {
                h.blocks(s, tail, 1);
                finish(&h, s, tail + h.block, rest + 4 - h.block, h.block + salt_length + 4);
            } else {
                finish(&h, s, tail, rest + 4, h.block + salt_length + 4);
            }
        }
        outer(&h, os, s, u);
        memcpy(t, u, h.out);
        /* U2.. : one block each way, the padding fixed */
        memset(u + h.out, 0, ublock - h.out);
        u[h.out] = 0x80;
        {
            uint64_t bits = (uint64_t)(h.block + h.out) << 3;
            for (i = 0; i < 8; ++i) u[ublock - 1 - i] = (uint8_t)(bits >> (8 * i));
        }
        for (j = 1; j < iterations; ++j) {
            memcpy(s, is, h.state);
            h.blocks(s, u, 1);
            memcpy(u, s, h.out);
            memcpy(s, os, h.state);
            h.blocks(s, u, 1);
            memcpy(u, s, h.out);
            for (i = 0; i < h.out; ++i) t[i] ^= u[i];
        }
        memcpy(dst, t, take);
        dst += take;
        out_length -= take;
    }
    oc_cleanse(is, sizeof is); oc_cleanse(os, sizeof os); oc_cleanse(s, sizeof s);
    oc_cleanse(u, sizeof u); oc_cleanse(t, sizeof t);
    return 0;
}
