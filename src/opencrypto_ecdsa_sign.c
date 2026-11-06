/* GFOpenCrypto: ECDSA signing and key generation on P-256, P-384 and P-521.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * The nonce k is RFC 6979's (deterministic, HMAC-DRBG over the private key
 * and the hash, with the hash its length names), so signing needs no random
 * source and a weak one cannot leak the key. k G is oc_ec_mulgen's constant
 * time product; the arithmetic mod n is oc_bn.h's, by mask throughout. */
#include "oc_bn.h"

#include <string.h>

#define EK 17                       /* limbs: P-521 */

static const struct {
    int bits;
    const char *n;
} orders[] = {
    { 256, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" },
    { 384, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973" },
    { 521, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409" },
};

typedef struct {
    int bits, bytes, k;
    oc_limb n[EK];
} order;

static int order_init(order *O, int curve)
{
    int i;
    for (i = 0; i < 3; ++i)
        if (orders[i].bits == curve) {
            uint8_t b[66];
            const char *h = orders[i].n;
            size_t len = strlen(h) / 2, j;
            for (j = 0; j < len; ++j) {
                unsigned v = 0;
                int x;
                for (x = 0; x < 2; ++x) {
                    char c = h[2 * j + x];
                    v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
                }
                b[j] = (uint8_t)v;
            }
            O->bits = curve;
            O->bytes = (curve + 7) / 8;
            O->k = (curve + 31) / 32;
            oc_bn_from_bytes(O->n, O->k, b, len);
            return 0;
        }
    return -1;
}

/* the leftmost qlen bits of b as a number (RFC 6979 bits2int) */
static void bits2int(oc_limb *x, const order *O, const uint8_t *b, size_t len)
{
    int i, shift;
    if (len * 8 <= (size_t)O->bits) {
        oc_bn_from_bytes(x, O->k, b, len);
        return;
    }
    oc_bn_from_bytes(x, O->k, b, (size_t)O->bytes);
    shift = 8 * O->bytes - O->bits;
    if (shift)
        for (i = 0; i < O->k; ++i)
            x[i] = (x[i] >> shift) | (i + 1 < O->k ? x[i + 1] << (32 - shift) : 0);
}

/* x mod n for x < 2n, by mask */
static void reduce_once(oc_limb *x, const order *O)
{
    oc_limb u[EK], borrow = oc_bn_sub(u, x, O->n, O->k);
    oc_bn_cmov(x, u, borrow - 1, O->k);
}

static int hash_for(size_t hash_length)
{
    switch (hash_length) {
    case 20: return OC_HASH_SHA1;
    case 32: return OC_HASH_SHA256;
    case 48: return OC_HASH_SHA384;
    case 64: return OC_HASH_SHA512;
    }
    return 0;
}

int oc_ecdsa_sign(int curve, uint8_t *r, uint8_t *s, const uint8_t *d,
                  const uint8_t *hash, size_t hash_length)
{
    order O;
    oc_mont N;
    oc_limb dv[EK], e[EK], kv[EK], rv[EK], sv[EK], t[EK], two[EK];
    uint8_t K[64], V[64], buf[64 + 1 + 66 + 66], xb[66], hb[66], kb[66], nb[4 * EK];
    uint8_t pt[1 + 2 * 66];
    int alg = hash_for(hash_length), rc = -1;
    size_t hl = hash_length, rl, n;

    if (!alg || !r || !s || !d || !hash || order_init(&O, curve)) return -1;
    if (oc_bn_mont_init(&N, O.n, O.k)) return -1;
    rl = (size_t)O.bytes;

    /* 0 < d < n */
    oc_bn_from_bytes(dv, O.k, d, rl);
    if (oc_bn_zero_mask(dv, O.k) || !oc_bn_less(dv, O.n, O.k)) return -1;

    /* e = bits2int(hash) mod n; RFC 6979's h1 octets are the same number */
    bits2int(e, &O, hash, hl);
    reduce_once(e, &O);
    oc_bn_to_bytes(hb, rl, e, O.k);
    oc_bn_to_bytes(xb, rl, dv, O.k);

    /* RFC 6979 section 3.2, steps b to f */
    memset(V, 0x01, hl);
    memset(K, 0x00, hl);
    memcpy(buf, V, hl);
    buf[hl] = 0x00;
    memcpy(buf + hl + 1, xb, rl);
    memcpy(buf + hl + 1 + rl, hb, rl);
    n = hl + 1 + 2 * rl;
    oc_hmac(alg, K, hl, buf, n, K);
    oc_hmac(alg, K, hl, V, hl, V);
    memcpy(buf, V, hl);
    buf[hl] = 0x01;
    oc_hmac(alg, K, hl, buf, n, K);
    oc_hmac(alg, K, hl, V, hl, V);

    memset(two, 0, sizeof two);
    two[0] = 2;
    oc_bn_sub(t, O.n, two, O.k);
    oc_bn_to_bytes(nb, (size_t)(4 * O.k), t, O.k);

    for (;;) {
        uint8_t T[66 + 64];
        size_t tl = 0;
        oc_limb ok;
        while (tl < rl) {
            oc_hmac(alg, K, hl, V, hl, V);
            memcpy(T + tl, V, hl);
            tl += hl;
        }
        bits2int(kv, &O, T, tl);
        oc_cleanse(T, sizeof T);
        /* 1 <= k < n: a public decision (a rejected k is thrown away) */
        if (!oc_bn_zero_mask(kv, O.k) && oc_bn_less(kv, O.n, O.k)) {
            oc_bn_to_bytes(kb, rl, kv, O.k);
            if (oc_ec_mulgen(curve, pt, kb, rl)) {
                /* r = x(kG) mod n */
                oc_bn_from_bytes(rv, O.k, pt + 1, rl);
                reduce_once(rv, &O);
                /* s = (e + r d) / k mod n */
                oc_bn_to_mont(t, kv, &N);
                oc_bn_mont_pow(t, t, nb, (size_t)(4 * O.k), &N);    /* 1/k, Montgomery form */
                oc_bn_mont_mul(sv, rv, dv, &N);                     /* r d / R */
                oc_bn_mont_mul(sv, sv, N.rr, &N);                   /* r d */
                oc_bn_mod_add(sv, sv, e, O.n, O.k);
                oc_bn_mont_mul(sv, sv, t, &N);                      /* (e + r d) / k */
                ok = ~oc_bn_zero_mask(rv, O.k) & ~oc_bn_zero_mask(sv, O.k);
                if (ok) {
                    oc_bn_to_bytes(r, rl, rv, O.k);
                    oc_bn_to_bytes(s, rl, sv, O.k);
                    rc = 0;
                    break;
                }
            }
        }
        memcpy(buf, V, hl);
        buf[hl] = 0x00;
        oc_hmac(alg, K, hl, buf, hl + 1, K);
        oc_hmac(alg, K, hl, V, hl, V);
    }
    oc_cleanse(K, sizeof K); oc_cleanse(V, sizeof V); oc_cleanse(buf, sizeof buf);
    oc_cleanse(xb, sizeof xb); oc_cleanse(kb, sizeof kb); oc_cleanse(dv, sizeof dv);
    oc_cleanse(kv, sizeof kv); oc_cleanse(t, sizeof t); oc_cleanse(sv, sizeof sv);
    oc_cleanse(pt, sizeof pt);
    return rc;
}

int oc_ec_keygen(int curve, uint8_t *d, uint8_t *point, const uint8_t *seed, size_t seed_length)
{
    order O;
    oc_limb a[EK + 3], nm1[EK], one[EK], dv[EK];
    int ka;
    if (!d || !point || !seed || order_init(&O, curve)) return 0;
    if (seed_length < (size_t)O.bytes + 8 || seed_length > 4 * (EK + 3)) return 0;
    /* d = 1 + (seed mod (n - 1)): the seed's extra 64 bits make the bias
     * negligible (FIPS 186-5 A.2.1) */
    memset(one, 0, sizeof one);
    one[0] = 1;
    oc_bn_sub(nm1, O.n, one, O.k);
    ka = (int)((seed_length + 3) / 4);
    oc_bn_from_bytes(a, ka, seed, seed_length);
    oc_bn_mod(dv, a, ka, nm1, O.k);
    oc_bn_add(dv, dv, one, O.k);
    oc_bn_to_bytes(d, (size_t)O.bytes, dv, O.k);
    oc_cleanse(a, sizeof a);
    oc_cleanse(dv, sizeof dv);
    return oc_ec_mulgen(curve, point, d, (size_t)O.bytes);
}
