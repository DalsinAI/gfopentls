/* GFOpenTLS: HMAC (RFC 2104) over the hash classes, and HMAC-DRBG (NIST
 * SP 800-90A section 10.1.2) with SHA-256 for ot_random.c.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"

static size_t block_of(const ot_hash_class *h)
{
    return (size_t)1 << ((h->desc >> OT_HASHDESC_LBLEN_OFF) & OT_HASHDESC_LBLEN_MASK);
}

static size_t out_of(const ot_hash_class *h)
{
    return (h->desc >> OT_HASHDESC_OUT_OFF) & OT_HASHDESC_OUT_MASK;
}

void ot_hmac_key_init(struct ot_hmac_key *k, const ot_hash_class *h, const void *key, size_t len)
{
    memset(k, 0, sizeof *k);
    k->h = h;
    if (len > block_of(h)) {
        ot_hash_compat_context c;
        h->init(&c.vtable);
        h->update(&c.vtable, key, len);
        h->out(&c.vtable, k->key);
    } else {
        memcpy(k->key, key, len);
    }
}

static void pad_in(const struct ot_hmac_key *k, ot_hash_compat_context *c, unsigned char x)
{
    unsigned char b[128];
    size_t i, n = block_of(k->h);
    for (i = 0; i < n; ++i) b[i] = (unsigned char)(k->key[i] ^ x);
    k->h->init(&c->vtable);
    k->h->update(&c->vtable, b, n);
    memset(b, 0, sizeof b);
}

void ot_hmac_init(struct ot_hmac *m, const struct ot_hmac_key *k)
{
    m->key = k;
    pad_in(k, &m->inner, 0x36);
}

void ot_hmac_update(struct ot_hmac *m, const void *data, size_t len)
{
    m->key->h->update(&m->inner.vtable, data, len);
}

size_t ot_hmac_out(struct ot_hmac *m, void *out)
{
    const ot_hash_class *h = m->key->h;
    ot_hash_compat_context outer;
    unsigned char t[64];
    size_t n = out_of(h);
    h->out(&m->inner.vtable, t);
    pad_in(m->key, &outer, 0x5C);
    h->update(&outer.vtable, t, n);
    h->out(&outer.vtable, out);
    memset(t, 0, sizeof t);
    return n;
}

/* ---- HMAC-DRBG ---- */

static void mac2(const unsigned char k[32], const unsigned char *a, size_t al, const unsigned char *b, size_t bl,
                 const unsigned char *c, size_t cl, unsigned char out[32])
{
    struct ot_hmac_key key;
    struct ot_hmac m;
    ot_hmac_key_init(&key, &ot_sha256_vtable, k, 32);
    ot_hmac_init(&m, &key);
    ot_hmac_update(&m, a, al);
    if (bl) ot_hmac_update(&m, b, bl);
    if (cl) ot_hmac_update(&m, c, cl);
    ot_hmac_out(&m, out);
    memset(&key, 0, sizeof key);
}

void ot_drbg_update(struct ot_drbg *d, const void *data, size_t len)
{
    unsigned char zero = 0, one = 1;
    mac2(d->k, d->v, 32, &zero, 1, data, len, d->k);
    mac2(d->k, d->v, 32, NULL, 0, NULL, 0, d->v);
    if (!len) return;
    mac2(d->k, d->v, 32, &one, 1, data, len, d->k);
    mac2(d->k, d->v, 32, NULL, 0, NULL, 0, d->v);
}

void ot_drbg_init(struct ot_drbg *d, const void *seed, size_t len)
{
    memset(d->k, 0, 32);
    memset(d->v, 1, 32);
    ot_drbg_update(d, seed, len);
}

void ot_drbg_generate(struct ot_drbg *d, void *out, size_t len)
{
    unsigned char *p = out;
    while (len) {
        size_t n = len < 32 ? len : 32;
        mac2(d->k, d->v, 32, NULL, 0, NULL, 0, d->v);
        memcpy(p, d->v, n);
        p += n;
        len -= n;
    }
    ot_drbg_update(d, NULL, 0);
}
