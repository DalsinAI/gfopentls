/* GFOpenTLS: BearSSL's pluggable maths, all done by GFOpenCrypto.
 *
 * BearSSL takes its hash functions, block ciphers, GHASH, ChaCha20/Poly1305,
 * RSA, ECDSA and elliptic curves through function tables and a few named
 * functions. Every one of them is GFOpenCrypto's: on an Amiga through
 * gfopencrypto.library (2.3 or newer), which runs each as host code where
 * the machine offers it (AmiCradle) and as its own 68k code everywhere
 * else; for the host tests over GFOpenCrypto's portable C. BearSSL's own
 * crypto code is not linked: this file defines the hash names BearSSL's
 * protocol code calls (br_md5_*, br_sha1_*, br_sha224/256/384/512_*), with
 * BearSSL's context layouts and state encodings, so that HMAC, the PRFs,
 * the multihash and X.509 work unchanged.
 *
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"
#include "inner.h"      /* BearSSL's br_rsa_pkcs1_sig_unpad(), br_ecdsa_asn1_to_raw() */

#ifdef __amigaos__
#include <exec/execbase.h>
#include <proto/exec.h>
#include <libraries/gfopencrypto.h>
#include <inline/gfopencrypto.h>
struct Library *OpenCryptoBase;
#else
#include <gfopencrypto/gfopencrypto.h>
#endif

/* ---- the calls into GFOpenCrypto ---- */

#ifdef __amigaos__
static ULONG oc_flags;
static int oc_tried;

/* gfopencrypto.library 2.3 or newer: every operation is its call */
static void oc_open(void)
{
    if (oc_tried) return;
    Forbid();
    if (!oc_tried) {
        struct Library *b;
        oc_tried = 1;
        b = OpenLibrary((CONST_STRPTR)"gfopencrypto.library", 2);
        if (b && b->lib_Version == 2 && b->lib_Revision < 3) {
            CloseLibrary(b);
            b = NULL;
        }
        OpenCryptoBase = b;
        oc_flags = b ? OC_Accelerated() : 0;
    }
    Permit();
}

int ot_glue_ready(void)
{
    oc_open();
    return OpenCryptoBase != NULL;
}

void ot_glue_cleanup(void)
{
    if (OpenCryptoBase) CloseLibrary(OpenCryptoBase);
    OpenCryptoBase = NULL;
    oc_tried = 0;
    oc_flags = 0;
}

/* Without the library (ot_glue_ready() 0) no connection starts and no
 * random bytes are given; these then do nothing rather than crash. */
#define OC_BLOCKS(fn, lvo) \
static void fn(unsigned char *state, const void *data, size_t n) \
{ \
    struct OCBlocksRequest r; \
    if (!OpenCryptoBase) return; \
    r.state = state; r.data = data; r.blocks = n; \
    lvo(&r); \
}
OC_BLOCKS(g_md5_blocks, OC_MD5Blocks)
OC_BLOCKS(g_sha1_blocks, OC_SHA1Blocks)
OC_BLOCKS(g_sha256_blocks, OC_SHA256Blocks)
OC_BLOCKS(g_sha512_blocks, OC_SHA512Blocks)

static void g_ghash(void *y, const void *h, const void *data, size_t len)
{
    struct OCGHASHRequest r;
    if (!OpenCryptoBase) return;
    r.y = y; r.h = h; r.data = data; r.length = len;
    OC_GHASH(&r);
}

static int g_ecmul(int curve, unsigned char *pt, size_t ptlen, const unsigned char *k, size_t klen)
{
    struct OCECMulRequest r;
    if (!OpenCryptoBase) return 0;
    r.curve = curve; r.point = pt; r.point_length = ptlen; r.scalar = k; r.scalar_length = klen;
    return OC_ECMul(&r) == 1;
}

static size_t g_ecmulgen(int curve, unsigned char *pt, const unsigned char *k, size_t klen)
{
    struct OCECMulRequest r;
    LONG n;
    if (!OpenCryptoBase) return 0;
    r.curve = curve; r.point = pt; r.point_length = 0; r.scalar = k; r.scalar_length = klen;
    n = OC_ECMulGen(&r);
    return n > 0 ? (size_t)n : 0;
}

static int g_aes(unsigned char *buf, size_t len, const unsigned char *key, size_t keylen,
                 const unsigned char *iv, int mode)
{
    struct OCAESRequest r;
    if (!OpenCryptoBase) return OCERR_ARGS;
    r.buf = buf; r.length = len; r.key = key; r.key_length = keylen;
    r.iv = iv; r.mode = (ULONG)mode;
    return OC_AES(&r);
}

static void g_chacha(unsigned char *buf, size_t len, const unsigned char *key,
                     const unsigned char *nonce, uint64_t counter)
{
    struct OCChaChaRequest r;
    if (!OpenCryptoBase) { memset(buf, 0, len); return; }
    r.out = buf; r.in = buf; r.length = len; r.key = key; r.nonce = nonce;
    r.counter_hi = (ULONG)(counter >> 32); r.counter_lo = (ULONG)counter;
    OC_ChaCha20(&r);
}

static void g_poly(unsigned char *tag, const void *data, size_t len, const unsigned char *key)
{
    struct OCPolyRequest r;
    if (!OpenCryptoBase) { memset(tag, 0xff, 16); return; }
    r.tag = tag; r.data = data; r.length = len; r.key = key;
    OC_Poly1305(&r);
}

static int g_x25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    struct OCX25519Request r;
    if (!OpenCryptoBase) return -1;
    r.out = out; r.scalar = scalar; r.point = point;
    return OC_X25519(&r);
}

static int g_rsa(unsigned char *out, const unsigned char *x, const unsigned char *n, size_t nlen,
                 const unsigned char *e, size_t elen)
{
    struct OCRSARequest r;
    if (!OpenCryptoBase) return -1;
    r.out = out; r.sig = x; r.n = n; r.n_length = nlen; r.e = e; r.e_length = elen;
    return OC_RSAPublic(&r);
}

static int g_ecdsa(int curve, const unsigned char *qx, const unsigned char *qy,
                   const unsigned char *rr, const unsigned char *ss,
                   const unsigned char *hash, size_t hlen)
{
    struct OCECDSARequest r;
    if (!OpenCryptoBase) return 0;
    r.curve = curve; r.qx = qx; r.qy = qy; r.r = rr; r.s = ss;
    r.hash = hash; r.hash_length = hlen;
    return OC_ECDSAVerify(&r);
}

/* Ed25519 for TLS 1.3 server certificates: gfopencrypto.library's, whether
 * or not the host runs it, since BearSSL has none */
int ot_glue_has_ed25519(void)
{
    oc_open();
    return OpenCryptoBase != NULL;
}

int ot_glue_ed25519(const unsigned char *sig, const unsigned char *pk, const void *msg, size_t len)
{
    struct OCEd25519Request r;
    oc_open();
    if (!OpenCryptoBase) return 0;
    r.sig = sig; r.pk = pk; r.msg = msg; r.length = (ULONG)len;
    return OC_Ed25519Verify(&r) == 1;
}

ULONG ot_glue_accelerated(void)
{
    ULONG f = 0;
    oc_open();
    if ((oc_flags & (OCF_SHA256 | OCF_SHA512)) == (OCF_SHA256 | OCF_SHA512)) f |= OTACC_HASH;
    if (oc_flags & OCF_AES) f |= OTACC_AES;
    if ((oc_flags & (OCF_CHACHA20 | OCF_POLY1305)) == (OCF_CHACHA20 | OCF_POLY1305)) f |= OTACC_CHACHA;
    if (oc_flags & OCF_X25519) f |= OTACC_X25519;
    if (oc_flags & OCF_RSA) f |= OTACC_RSA;
    if (oc_flags & OCF_ECDSA) f |= OTACC_ECDSA;
    return f;
}

#else /* the host tests: GFOpenCrypto's portable C */

void ot_glue_cleanup(void) {}
int ot_glue_ready(void) { return 1; }

static void g_md5_blocks(unsigned char *state, const void *data, size_t n)
{ oc_md5_blocks(state, data, n); }
static void g_sha1_blocks(unsigned char *state, const void *data, size_t n)
{ oc_sha1_blocks(state, data, n); }
static void g_sha256_blocks(unsigned char *state, const void *data, size_t n)
{ oc_sha256_blocks(state, data, n); }
static void g_sha512_blocks(unsigned char *state, const void *data, size_t n)
{ oc_sha512_blocks(state, data, n); }
static int g_aes(unsigned char *buf, size_t len, const unsigned char *key, size_t keylen,
                 const unsigned char *iv, int mode)
{ return oc_aes(buf, len, key, keylen, iv, mode); }
static void g_chacha(unsigned char *buf, size_t len, const unsigned char *key,
                     const unsigned char *nonce, uint64_t counter)
{ oc_chacha20_xor(buf, buf, len, key, nonce, counter); }
static void g_poly(unsigned char *tag, const void *data, size_t len, const unsigned char *key)
{ oc_poly1305(tag, data, len, key); }
static void g_ghash(void *y, const void *h, const void *data, size_t len)
{ oc_ghash(y, h, data, len); }
static int g_ecmul(int curve, unsigned char *pt, size_t ptlen, const unsigned char *k, size_t klen)
{ return oc_ec_mul(curve, pt, ptlen, k, klen) == 1; }
static size_t g_ecmulgen(int curve, unsigned char *pt, const unsigned char *k, size_t klen)
{ int n = oc_ec_mulgen(curve, pt, k, klen); return n > 0 ? (size_t)n : 0; }
static int g_x25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    if (!point) { oc_x25519_base(out, scalar); return 0; }
    return oc_x25519(out, scalar, point);
}
static int g_rsa(unsigned char *out, const unsigned char *x, const unsigned char *n, size_t nlen,
                 const unsigned char *e, size_t elen)
{ return oc_rsa_public(out, x, n, nlen, e, elen); }
static int g_ecdsa(int curve, const unsigned char *qx, const unsigned char *qy,
                   const unsigned char *rr, const unsigned char *ss,
                   const unsigned char *hash, size_t hlen)
{ return oc_ecdsa_verify(curve, qx, qy, rr, ss, hash, hlen); }

int ot_glue_has_ed25519(void) { return 1; }
int ot_glue_ed25519(const unsigned char *sig, const unsigned char *pk, const void *msg, size_t len)
{ return oc_ed25519_verify(sig, pk, msg, len) == 1; }

ULONG ot_glue_accelerated(void)
{
    return OTACC_HASH | OTACC_AES | OTACC_CHACHA | OTACC_X25519 | OTACC_RSA | OTACC_ECDSA;
}
#endif

/* the MD5 and SHA initial values: RFC 1321 3.3, FIPS 180-4 5.3 */
static const unsigned char iv_md5[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};
static const unsigned char iv_sha1[20] = {
    0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe,
    0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0
};
static const unsigned char iv_sha224[32] = {
    0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17,
    0xf7, 0x0e, 0x59, 0x39, 0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11,
    0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4
};
static const unsigned char iv_sha256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72,
    0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};
static const unsigned char iv_sha384[64] = {
    0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a,
    0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17,
    0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67,
    0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11,
    0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d,
    0xbe, 0xfa, 0x4f, 0xa4
};
static const unsigned char iv_sha512[64] = {
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85,
    0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
    0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
    0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
    0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19,
    0x13, 0x7e, 0x21, 0x79
};

/* ---- MD5, SHA-1 and SHA-2 under BearSSL's names ----
 * Each context is BearSSL's: the vtable, the partial block (buf), the byte
 * count, and the chaining value (val), which we keep as the bytes our
 * block functions take: big-endian for SHA, little-endian for MD5, which is
 * also how BearSSL's state() and set_state() encode it. */

typedef void (*ot_blocks_fn)(unsigned char *state, const void *data, size_t n);

static void md_update(ot_blocks_fn blocks, size_t bl, unsigned char *buf, uint64_t *count,
                      unsigned char *st, const void *data, size_t len)
{
    const unsigned char *p = data;
    size_t ptr = (size_t)*count & (bl - 1), n;
    if (!len) return;                 /* BearSSL's HMAC-DRBG hands over (NULL, 0) */
    *count += len;
    if (ptr) {
        n = bl - ptr < len ? bl - ptr : len;
        memcpy(buf + ptr, p, n);
        p += n; len -= n; ptr += n;
        if (ptr < bl) return;
        blocks(st, buf, 1);
    }
    n = len / bl;
    if (n) {
        blocks(st, p, n);
        p += n * bl;
        len -= n * bl;
    }
    if (len) memcpy(buf, p, len);
}

/* MD padding: 0x80, zeros, the length in bits in the last 8 (64-byte
 * blocks) or 16 (128-byte blocks) bytes, big-endian, or little-endian for
 * MD5 */
static void md_out(ot_blocks_fn blocks, size_t bl, int le, size_t stlen,
                   const unsigned char *buf, uint64_t count, const unsigned char *st,
                   void *dst, size_t outlen)
{
    unsigned char last[256], state[64];
    size_t ptr = (size_t)count & (bl - 1), lenbytes = bl == 64 ? 8 : 16, total, i;
    uint64_t bits = count << 3;
    memcpy(state, st, stlen);
    memcpy(last, buf, ptr);
    last[ptr] = 0x80;
    total = ptr + 1 + lenbytes <= bl ? bl : 2 * bl;
    memset(last + ptr + 1, 0, total - ptr - 1);
    for (i = 0; i < 8; ++i)
        last[le ? total - 8 + i : total - 1 - i] = (unsigned char)(bits >> (8 * i));
    blocks(state, last, total / bl);
    memcpy(dst, state, outlen);
}

#define OT_HASH(name, ctxtype, blocks, bl, le, stlen, outlen, iv) \
void br_##name##_init(ctxtype *ctx) \
{ \
    ctx->vtable = &br_##name##_vtable; \
    memcpy(ctx->val, iv, stlen); \
    ctx->count = 0; \
} \
void br_##name##_update(ctxtype *ctx, const void *data, size_t len) \
{ md_update(blocks, bl, ctx->buf, &ctx->count, (unsigned char *)ctx->val, data, len); } \
void br_##name##_out(const ctxtype *ctx, void *out) \
{ md_out(blocks, bl, le, stlen, ctx->buf, ctx->count, (const unsigned char *)ctx->val, out, outlen); } \
uint64_t br_##name##_state(const ctxtype *ctx, void *out) \
{ memcpy(out, ctx->val, stlen); return ctx->count; } \
void br_##name##_set_state(ctxtype *ctx, const void *stb, uint64_t count) \
{ memcpy(ctx->val, stb, stlen); ctx->count = count; }

/* BearSSL defines the SHA-256 and SHA-512 update, state and set_state as
 * SHA-224's and SHA-384's (bearssl_hash.h); each has its own init and out */
#undef br_sha256_update
#undef br_sha256_state
#undef br_sha256_set_state
#undef br_sha512_update
#undef br_sha512_state
#undef br_sha512_set_state

OT_HASH(md5, br_md5_context, g_md5_blocks, 64, 1, 16, 16, iv_md5)
OT_HASH(sha1, br_sha1_context, g_sha1_blocks, 64, 0, 20, 20, iv_sha1)
OT_HASH(sha224, br_sha224_context, g_sha256_blocks, 64, 0, 32, 28, iv_sha224)
OT_HASH(sha384, br_sha384_context, g_sha512_blocks, 128, 0, 64, 48, iv_sha384)

void br_sha256_init(br_sha256_context *ctx)
{
    ctx->vtable = &br_sha256_vtable;
    memcpy(ctx->val, iv_sha256, 32);
    ctx->count = 0;
}
void br_sha256_out(const br_sha256_context *ctx, void *out)
{ md_out(g_sha256_blocks, 64, 0, 32, ctx->buf, ctx->count, (const unsigned char *)ctx->val, out, 32); }
void br_sha512_init(br_sha512_context *ctx)
{
    ctx->vtable = &br_sha512_vtable;
    memcpy(ctx->val, iv_sha512, 64);
    ctx->count = 0;
}
void br_sha512_out(const br_sha512_context *ctx, void *out)
{ md_out(g_sha512_blocks, 128, 0, 64, ctx->buf, ctx->count, (const unsigned char *)ctx->val, out, 64); }

#define OT_HASH_CLASS(name, ctxtype, upd, st, setst, desc) \
const br_hash_class br_##name##_vtable = { \
    sizeof(ctxtype), desc, \
    (void (*)(const br_hash_class **))&br_##name##_init, \
    (void (*)(const br_hash_class **, const void *, size_t))&upd, \
    (void (*)(const br_hash_class *const *, void *))&br_##name##_out, \
    (uint64_t (*)(const br_hash_class *const *, void *))&st, \
    (void (*)(const br_hash_class **, const void *, uint64_t))&setst \
};
#define OT_DESC(id, out, st, lblen) \
    (BR_HASHDESC_ID(id) | BR_HASHDESC_OUT(out) | BR_HASHDESC_STATE(st) \
     | BR_HASHDESC_LBLEN(lblen) | BR_HASHDESC_MD_PADDING)

OT_HASH_CLASS(md5, br_md5_context, br_md5_update, br_md5_state, br_md5_set_state,
              OT_DESC(br_md5_ID, 16, 16, 6))
OT_HASH_CLASS(sha1, br_sha1_context, br_sha1_update, br_sha1_state, br_sha1_set_state,
              OT_DESC(br_sha1_ID, 20, 20, 6) | BR_HASHDESC_MD_PADDING_BE)
OT_HASH_CLASS(sha224, br_sha224_context, br_sha224_update, br_sha224_state, br_sha224_set_state,
              OT_DESC(br_sha224_ID, 28, 32, 6) | BR_HASHDESC_MD_PADDING_BE)
OT_HASH_CLASS(sha256, br_sha256_context, br_sha224_update, br_sha224_state, br_sha224_set_state,
              OT_DESC(br_sha256_ID, 32, 32, 6) | BR_HASHDESC_MD_PADDING_BE)
OT_HASH_CLASS(sha384, br_sha384_context, br_sha384_update, br_sha384_state, br_sha384_set_state,
              OT_DESC(br_sha384_ID, 48, 64, 7) | BR_HASHDESC_MD_PADDING_BE | BR_HASHDESC_MD_PADDING_128)
OT_HASH_CLASS(sha512, br_sha512_context, br_sha384_update, br_sha384_state, br_sha384_set_state,
              OT_DESC(br_sha512_ID, 64, 64, 7) | BR_HASHDESC_MD_PADDING_BE | BR_HASHDESC_MD_PADDING_128)

/* ---- AES: CBC and CTR (GCM's counter mode) ---- */

typedef struct {
    const void *vtable;
    unsigned char key[32];
    size_t key_len;
} ot_aes_context;

static void aes_set(void *ctx, const void *key, size_t len)
{
    ot_aes_context *c = ctx;
    if (len > sizeof c->key) len = 0;     /* the run then refuses */
    memcpy(c->key, key, len);
    c->key_len = len;
}

static const br_block_cbcenc_class ot_aes_cbcenc_vtable;
static const br_block_cbcdec_class ot_aes_cbcdec_vtable;
static const br_block_ctr_class ot_aes_ctr_vtable;

static void aes_cbcenc_init(const br_block_cbcenc_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_cbcenc_vtable; aes_set(ctx, key, len); }
static void aes_cbcdec_init(const br_block_cbcdec_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_cbcdec_vtable; aes_set(ctx, key, len); }
static void aes_ctr_init(const br_block_ctr_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_ctr_vtable; aes_set(ctx, key, len); }

static void aes_cbcenc_run(const br_block_cbcenc_class *const *ctx, void *iv, void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    if (!len) return;
    if (g_aes(data, len, c->key, c->key_len, iv, OC_AES_CBC_ENCRYPT) != 0)
        memset(data, 0, len);   /* never send what was not encrypted */
    memcpy(iv, (unsigned char *)data + len - 16, 16);
}

static void aes_cbcdec_run(const br_block_cbcdec_class *const *ctx, void *iv, void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    unsigned char next[16];
    if (!len) return;
    memcpy(next, (unsigned char *)data + len - 16, 16);
    g_aes(data, len, c->key, c->key_len, iv, OC_AES_CBC_DECRYPT);
    memcpy(iv, next, 16);
}

static uint32_t aes_ctr_run(const br_block_ctr_class *const *ctx, const void *iv, uint32_t cc,
                            void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    unsigned char block[16];
    memcpy(block, iv, 12);
    br_enc32be(block + 12, cc);
    if (len && g_aes(data, len, c->key, c->key_len, block, OC_AES_CTR) != 0)
        memset(data, 0, len);   /* never send what was not encrypted */
    return cc + (uint32_t)((len + 15) >> 4);
}

static const br_block_cbcenc_class ot_aes_cbcenc_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_cbcenc_init, aes_cbcenc_run
};
static const br_block_cbcdec_class ot_aes_cbcdec_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_cbcdec_init, aes_cbcdec_run
};
static const br_block_ctr_class ot_aes_ctr_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_ctr_init, aes_ctr_run
};

/* ---- ChaCha20 and Poly1305 (RFC 7539's AEAD, as TLS uses) ---- */

/* RFC 7539's 32-bit counter and 96-bit nonce are the original's 64-bit
 * counter (cc, then the nonce's first word) and 64-bit nonce (the rest). */
static uint32_t ot_chacha20_run(const void *key, const void *iv, uint32_t cc, void *data, size_t len)
{
    const unsigned char *v = iv;
    uint64_t counter = (uint64_t)cc | ((uint64_t)br_dec32le(v) << 32);
    if (len) g_chacha(data, len, key, v + 4, counter);
    return cc + (uint32_t)((len + 63) >> 6);
}

static void ot_poly1305_run(const void *key, const void *iv, void *data, size_t len,
                            const void *aad, size_t aad_len, void *tag,
                            br_chacha20_run ichacha, int encrypt)
{
    unsigned char pkey[32], small[512], *mac;
    size_t apad = (aad_len + 15) & ~(size_t)15, dpad = (len + 15) & ~(size_t)15;
    size_t total = apad + dpad + 16;
    mac = total <= sizeof small ? small : ot_alloc(total);
    if (!mac) {
        /* no memory for the one-shot MAC: nothing sent can be read, and a
         * tag no one can guess makes the record received fail its check */
        if (encrypt) memset(data, 0, len);
        if (ot_random(tag, 16) != OTERR_OK) memset(tag, 0, 16);
        ((unsigned char *)tag)[0] ^= 0x5a;
        return;
    }
    memset(pkey, 0, sizeof pkey);
    ichacha(key, iv, 0, pkey, sizeof pkey);
    if (encrypt) ichacha(key, iv, 1, data, len);
    memset(mac, 0, total);
    memcpy(mac, aad, aad_len);
    memcpy(mac + apad, data, len);
    br_enc64le(mac + apad + dpad, (uint64_t)aad_len);
    br_enc64le(mac + apad + dpad + 8, (uint64_t)len);
    g_poly(tag, mac, total, pkey);
    if (mac != small) ot_free(mac);
    if (!encrypt) ichacha(key, iv, 1, data, len);
    memset(pkey, 0, sizeof pkey);
}

/* ---- RSA ---- */

static int rsa_trim(const br_rsa_public_key *pk, const unsigned char **n, size_t *nlen)
{
    *n = pk->n;
    *nlen = pk->nlen;
    while (*nlen && **n == 0) { ++*n; --*nlen; }
    return *nlen > 0 && *nlen <= 1024;
}

static uint32_t ot_rsa_public(unsigned char *x, size_t xlen, const br_rsa_public_key *pk)
{
    const unsigned char *n;
    size_t nlen;
    unsigned char *out;
    int rc;
    if (!rsa_trim(pk, &n, &nlen) || xlen != nlen) return 0;
    out = ot_alloc(nlen);
    if (!out) return 0;
    rc = g_rsa(out, x, n, nlen, pk->e, pk->elen);
    if (rc == 0) memcpy(x, out, nlen);
    ot_free(out);
    return rc == 0;
}

static uint32_t ot_rsa_pkcs1_vrfy(const unsigned char *x, size_t xlen,
                                  const unsigned char *hash_oid, size_t hash_len,
                                  const br_rsa_public_key *pk, unsigned char *hash_out)
{
    const unsigned char *n;
    size_t nlen;
    unsigned char *sig;
    uint32_t ok = 0;
    if (!rsa_trim(pk, &n, &nlen) || xlen != nlen) return 0;
    sig = ot_alloc(nlen);
    if (!sig) return 0;
    if (g_rsa(sig, x, n, nlen, pk->e, pk->elen) == 0)
        ok = br_rsa_pkcs1_sig_unpad(sig, nlen, hash_oid, hash_len, hash_out);
    ot_free(sig);
    return ok;
}

/* ---- ECDSA verification (P-256, P-384, P-521) ---- */

static uint32_t ot_ecdsa_vrfy_asn1(const br_ec_impl *impl, const void *hash, size_t hash_len,
                                   const br_ec_public_key *pk, const void *sig, size_t sig_len)
{
    unsigned char raw[160], r[66], s[66];
    size_t flen, rlen, half;
    int bits;
    (void)impl;
    switch (pk->curve) {
    case BR_EC_secp256r1: bits = 256; flen = 32; break;
    case BR_EC_secp384r1: bits = 384; flen = 48; break;
    case BR_EC_secp521r1: bits = 521; flen = 66; break;
    default: return 0;
    }
    if (pk->qlen != 1 + 2 * flen || pk->q[0] != 0x04 || sig_len > sizeof raw) return 0;
    memcpy(raw, sig, sig_len);
    rlen = br_ecdsa_asn1_to_raw(raw, sig_len);
    if (rlen == 0 || (rlen & 1)) return 0;
    half = rlen / 2;
    if (half > flen) return 0;
    memset(r, 0, sizeof r);
    memset(s, 0, sizeof s);
    memcpy(r + flen - half, raw, half);
    memcpy(s + flen - half, raw + half, half);
    return g_ecdsa(bits, pk->q + 1, pk->q + 1 + flen, r, s, hash, hash_len) == 1;
}

/* ---- elliptic curves: X25519, P-256, P-384 and P-521 ----
 * The generators and orders: SEC 2 (2010) 2.4.2, 2.5.1 and 2.6.1 (FIPS
 * 186-4 D.1.2), uncompressed; Curve25519's as BearSSL's interface wants
 * them (RFC 7748's u = 9, and a "order" that gives any 255-bit scalar,
 * which X25519 clamps). */
static const unsigned char p256_g[65] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
    0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42,
    0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
    0x68, 0x37, 0xbf, 0x51, 0xf5
};
static const unsigned char p256_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const unsigned char p384_g[97] = {
    0x04, 0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7,
    0x1e, 0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b,
    0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2,
    0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a,
    0xb7, 0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98,
    0xbf, 0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14,
    0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1,
    0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e,
    0x5f
};
static const unsigned char p384_n[48] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
    0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
};
static const unsigned char p521_g[133] = {
    0x04, 0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e,
    0x3e, 0xcb, 0x66, 0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05,
    0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba, 0xa1,
    0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2,
    0xff, 0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9,
    0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66, 0x01, 0x18, 0x39, 0x29, 0x6a,
    0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d, 0x1b,
    0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd,
    0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26,
    0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70,
    0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66,
    0x50
};
static const unsigned char p521_n[66] = {
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86,
    0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
    0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09
};
static const unsigned char c25519_g[32] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char c25519_n[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const unsigned char *ot_ec_generator(int curve, size_t *len)
{
    switch (curve) {
    case BR_EC_secp256r1: *len = sizeof p256_g; return p256_g;
    case BR_EC_secp384r1: *len = sizeof p384_g; return p384_g;
    case BR_EC_secp521r1: *len = sizeof p521_g; return p521_g;
    case BR_EC_curve25519: *len = sizeof c25519_g; return c25519_g;
    }
    *len = 0;
    return NULL;
}

static const unsigned char *ot_ec_order(int curve, size_t *len)
{
    switch (curve) {
    case BR_EC_secp256r1: *len = sizeof p256_n; return p256_n;
    case BR_EC_secp384r1: *len = sizeof p384_n; return p384_n;
    case BR_EC_secp521r1: *len = sizeof p521_n; return p521_n;
    case BR_EC_curve25519: *len = sizeof c25519_n; return c25519_n;
    }
    *len = 0;
    return NULL;
}

static size_t ot_ec_xoff(int curve, size_t *len)
{
    switch (curve) {
    case BR_EC_secp256r1: *len = 32; return 1;
    case BR_EC_secp384r1: *len = 48; return 1;
    case BR_EC_secp521r1: *len = 66; return 1;
    case BR_EC_curve25519: *len = 32; return 0;
    }
    *len = 0;
    return 0;
}

static int nist_bits(int curve)
{
    return curve == BR_EC_secp256r1 ? 256 : curve == BR_EC_secp384r1 ? 384
         : curve == BR_EC_secp521r1 ? 521 : 0;
}

static uint32_t ot_ec_mul(unsigned char *G, size_t Glen, const unsigned char *x, size_t xlen, int curve)
{
    unsigned char k[32], out[32];
    int rc;
    if (curve != BR_EC_curve25519) {
        int bits = nist_bits(curve);
        return bits && g_ecmul(bits, G, Glen, x, xlen);
    }
    if (Glen != 32 || xlen > 32) return 0;
    memcpy(k, x, xlen);
    memset(k + xlen, 0, 32 - xlen);
    G[31] &= 0x7F;
    rc = g_x25519(out, k, G);
    memcpy(G, out, 32);
    memset(k, 0, sizeof k);
    return rc == 0;     /* an all-zero shared secret is refused */
}

static size_t ot_ec_mulgen(unsigned char *R, const unsigned char *x, size_t xlen, int curve)
{
    unsigned char k[32];
    if (curve != BR_EC_curve25519) {
        int bits = nist_bits(curve);
        return bits ? g_ecmulgen(bits, R, x, xlen) : 0;
    }
    if (xlen > 32) return 0;
    memcpy(k, x, xlen);
    memset(k + xlen, 0, 32 - xlen);
    g_x25519(R, k, NULL);
    memset(k, 0, sizeof k);
    return 32;
}

/* only BearSSL's own ECDSA verification calls this, and it is not linked:
 * ours (above) goes to GFOpenCrypto whole */
static uint32_t ot_ec_muladd(unsigned char *A, const unsigned char *B, size_t len,
                             const unsigned char *x, size_t xlen,
                             const unsigned char *y, size_t ylen, int curve)
{
    (void)A; (void)B; (void)len; (void)x; (void)xlen; (void)y; (void)ylen; (void)curve;
    return 0;
}

static const br_ec_impl ot_ec_impl = {
    (uint32_t)0x23800000,     /* P-256, P-384, P-521 and Curve25519 */
    ot_ec_generator, ot_ec_order, ot_ec_xoff, ot_ec_mul, ot_ec_mulgen, ot_ec_muladd
};

/* ---- the choice ----
 * There is none left: every table is GFOpenCrypto's. offload (no
 * OTCF_NO_OFFLOAD) no longer changes anything here, since
 * gfopencrypto.library decides what runs as host code. */

void ot_glue_select(struct ot_impls *m, int offload)
{
    (void)offload;
    m->sha256 = &br_sha256_vtable;
    m->sha384 = &br_sha384_vtable;
    m->sha512 = &br_sha512_vtable;
    m->rsa_vrfy = ot_rsa_pkcs1_vrfy;
    m->rsa_pub = ot_rsa_public;
    m->ecdsa_vrfy = ot_ecdsa_vrfy_asn1;
    m->ec = &ot_ec_impl;
    m->ghash = g_ghash;
    m->aes_cbcenc = &ot_aes_cbcenc_vtable;
    m->aes_cbcdec = &ot_aes_cbcdec_vtable;
    m->aes_ctr = &ot_aes_ctr_vtable;
    m->chacha20 = ot_chacha20_run;
    m->poly1305 = ot_poly1305_run;
}
