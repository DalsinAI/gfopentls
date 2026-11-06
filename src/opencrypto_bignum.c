/* GFOpenCrypto: constant-time big numbers (oc_bn.h), and on them modular
 * exponentiation for Diffie-Hellman, RSA's private operation with the
 * Chinese remainder theorem, and a probable-prime test.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Products modulo an odd number are Montgomery's (CIOS), the last
 * subtraction taken by mask. Exponentiation takes the exponent four bits at
 * a time and reads the whole table of x^0 .. x^15 for each window, so
 * neither the time nor the memory touched depends on the exponent's or the
 * base's bits. Reductions by an even number (d mod p - 1) or a number too
 * long for Montgomery go bit by bit, with a masked subtraction. */
#include "oc_bn.h"

#include <string.h>

void oc_bn_from_bytes(oc_limb *x, int k, const uint8_t *b, size_t len)
{
    size_t i;
    memset(x, 0, (size_t)k * sizeof(oc_limb));
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        if (bit / 32 < (size_t)k)
            x[bit / 32] |= (oc_limb)b[i] << (bit % 32);
    }
}

void oc_bn_to_bytes(uint8_t *b, size_t len, const oc_limb *x, int k)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        b[i] = bit / 32 < (size_t)k ? (uint8_t)(x[bit / 32] >> (bit % 32)) : 0;
    }
}

oc_limb oc_bn_add(oc_limb *r, const oc_limb *a, const oc_limb *b, int k)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        c += (uint64_t)a[i] + b[i];
        r[i] = (oc_limb)c;
        c >>= 32;
    }
    return (oc_limb)c;
}

oc_limb oc_bn_sub(oc_limb *r, const oc_limb *a, const oc_limb *b, int k)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        uint64_t d = (uint64_t)a[i] - b[i] - c;
        r[i] = (oc_limb)d;
        c = (d >> 32) & 1;
    }
    return (oc_limb)c;
}

void oc_bn_cmov(oc_limb *r, const oc_limb *a, oc_limb mask, int k)
{
    int i;
    for (i = 0; i < k; ++i) r[i] ^= mask & (r[i] ^ a[i]);
}

oc_limb oc_bn_zero_mask(const oc_limb *a, int k)
{
    oc_limb z = 0;
    int i;
    for (i = 0; i < k; ++i) z |= a[i];
    /* (z | -z) has its top bit set exactly when z != 0 */
    return ((z | ((oc_limb)0 - z)) >> 31) - 1;
}

int oc_bn_less(const oc_limb *a, const oc_limb *m, int k)
{
    int i;
    for (i = k - 1; i >= 0; --i)
        if (a[i] != m[i]) return a[i] < m[i];
    return 0;
}

void oc_bn_mod_add(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_limb *m, int k)
{
    oc_limb u[OC_BN_MAX], carry, borrow;
    carry = oc_bn_add(r, a, b, k);
    borrow = oc_bn_sub(u, r, m, k);
    /* take r - m when the sum carried out or did not borrow */
    oc_bn_cmov(r, u, (oc_limb)0 - (carry | (borrow ^ 1)), k);
}

void oc_bn_mod_sub(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_limb *m, int k)
{
    oc_limb u[OC_BN_MAX], borrow;
    borrow = oc_bn_sub(r, a, b, k);
    oc_bn_add(u, r, m, k);
    oc_bn_cmov(r, u, (oc_limb)0 - borrow, k);
}

void oc_bn_mont_mul(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_mont *M)
{
    oc_limb t[OC_BN_MAX + 2], u[OC_BN_MAX], borrow, top;
    const oc_limb *m = M->m;
    int i, j, k = M->k;
    memset(t, 0, sizeof(oc_limb) * (size_t)(k + 2));
    for (i = 0; i < k; ++i) {
        uint64_t c = 0, s;
        oc_limb bi = b[i], q;
        for (j = 0; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * bi;
            t[j] = (oc_limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k] = (oc_limb)s;
        t[k + 1] = (oc_limb)(s >> 32);
        q = t[0] * M->m0inv;
        c = ((uint64_t)t[0] + (uint64_t)q * m[0]) >> 32;
        for (j = 1; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)q * m[j];
            t[j - 1] = (oc_limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k - 1] = (oc_limb)s;
        t[k] = t[k + 1] + (oc_limb)(s >> 32);
    }
    /* t < 2m: subtract m when t[k] is set or t >= m, by mask */
    borrow = oc_bn_sub(u, t, m, k);
    top = (t[k] | ((oc_limb)0 - t[k])) >> 31;
    oc_bn_cmov(t, u, (oc_limb)0 - (top | (borrow ^ 1)), k);
    memcpy(r, t, sizeof(oc_limb) * (size_t)k);
    oc_cleanse(t, sizeof(oc_limb) * (size_t)(k + 2));
    oc_cleanse(u, sizeof(oc_limb) * (size_t)k);
}

int oc_bn_mont_init(oc_mont *M, const oc_limb *m, int k)
{
    oc_limb x = 1, r[OC_BN_MAX];
    int i;
    if (k < 1 || k > OC_BN_MAX || !(m[0] & 1)) return -1;
    if (k == 1 && m[0] == 1) return -1;
    M->k = k;
    M->m = m;
    for (i = 0; i < 5; ++i) x *= 2 - m[0] * x;     /* 1/m mod 2^32, Newton */
    M->m0inv = (oc_limb)0 - x;
    /* R^2 mod m: 1 doubled 64k times (m is public) */
    memset(r, 0, sizeof(oc_limb) * (size_t)k);
    r[0] = 1;
    for (i = 0; i < 64 * k; ++i) oc_bn_mod_add(r, r, r, m, k);
    memcpy(M->rr, r, sizeof(oc_limb) * (size_t)k);
    return 0;
}

void oc_bn_to_mont(oc_limb *r, const oc_limb *a, const oc_mont *M)
{
    oc_bn_mont_mul(r, a, M->rr, M);
}

void oc_bn_from_mont(oc_limb *r, const oc_limb *a, const oc_mont *M)
{
    oc_limb one[OC_BN_MAX];
    memset(one, 0, sizeof(oc_limb) * (size_t)M->k);
    one[0] = 1;
    oc_bn_mont_mul(r, a, one, M);
}

void oc_bn_mod(oc_limb *r, const oc_limb *a, int ka, const oc_limb *m, int k)
{
    oc_limb t[OC_BN_MAX + 1], u[OC_BN_MAX + 1], mm[OC_BN_MAX + 1], borrow;
    int bit, i;
    memset(t, 0, sizeof(oc_limb) * (size_t)(k + 1));
    memcpy(mm, m, sizeof(oc_limb) * (size_t)k);
    mm[k] = 0;
    for (bit = 32 * ka - 1; bit >= 0; --bit) {
        for (i = k; i > 0; --i) t[i] = t[i] << 1 | t[i - 1] >> 31;
        t[0] = t[0] << 1 | ((a[bit / 32] >> (bit % 32)) & 1);
        borrow = oc_bn_sub(u, t, mm, k + 1);
        oc_bn_cmov(t, u, borrow - 1, k + 1);
    }
    memcpy(r, t, sizeof(oc_limb) * (size_t)k);
    oc_cleanse(t, sizeof t);
    oc_cleanse(u, sizeof u);
}

void oc_bn_mont_pow(oc_limb *r, const oc_limb *x, const uint8_t *e, size_t elen, const oc_mont *M)
{
    int k = M->k, i, j;
    size_t n = (size_t)k * sizeof(oc_limb);
    oc_limb table[16 * k], acc[k], sel[k], one[k];
    memset(one, 0, n);
    one[0] = 1;
    oc_bn_mont_mul(table, one, M->rr, M);           /* x^0 = R mod m */
    memcpy(table + k, x, n);
    for (i = 2; i < 16; ++i)
        oc_bn_mont_mul(table + i * k, table + (i - 1) * k, x, M);
    memcpy(acc, table, n);
    for (j = 0; j < (int)elen; ++j) {
        int w;
        for (w = 4; w >= 0; w -= 4) {
            oc_limb nib = (oc_limb)((e[j] >> w) & 15);
            oc_bn_mont_mul(acc, acc, acc, M);
            oc_bn_mont_mul(acc, acc, acc, M);
            oc_bn_mont_mul(acc, acc, acc, M);
            oc_bn_mont_mul(acc, acc, acc, M);
            memset(sel, 0, n);
            for (i = 0; i < 16; ++i) {
                oc_limb d = (oc_limb)i ^ nib;
                oc_bn_cmov(sel, table + i * k, ((d | ((oc_limb)0 - d)) >> 31) - 1, k);
            }
            oc_bn_mont_mul(acc, acc, sel, M);
        }
    }
    memcpy(r, acc, n);
    oc_cleanse(table, sizeof table);
    oc_cleanse(acc, n);
    oc_cleanse(sel, n);
}

/* ---- modular exponentiation (Diffie-Hellman) ---- */

static size_t strip(const uint8_t **b, size_t len)
{
    while (len && !**b) { ++*b; --len; }
    return len;
}

int oc_modexp(uint8_t *out, const uint8_t *base, size_t base_length,
              const uint8_t *exponent, size_t exponent_length,
              const uint8_t *modulus, size_t modulus_length)
{
    oc_limb m[OC_BN_MAX], b[OC_BN_MAX + 1], x[OC_BN_MAX];
    oc_mont M;
    size_t ml;
    int k, kb;
    const uint8_t *mod = modulus;
    if (!out || !modulus || (!base && base_length) || (!exponent && exponent_length))
        return -1;
    ml = strip(&mod, modulus_length);
    if (!ml || ml > OC_RSA_MAX_BYTES || base_length > 4 * (OC_BN_MAX + 1)) return -1;
    k = (int)((ml + 3) / 4);
    oc_bn_from_bytes(m, k, mod, ml);
    if (oc_bn_mont_init(&M, m, k)) return -1;
    kb = (int)((base_length + 3) / 4);
    if (kb < 1) kb = 1;
    oc_bn_from_bytes(b, kb, base, base_length);
    oc_bn_mod(x, b, kb, m, k);
    oc_bn_to_mont(x, x, &M);
    oc_bn_mont_pow(x, x, exponent, exponent_length, &M);
    oc_bn_from_mont(x, x, &M);
    memset(out, 0, modulus_length - ml);
    oc_bn_to_bytes(out + (modulus_length - ml), ml, x, k);
    oc_cleanse(b, sizeof b);
    oc_cleanse(x, sizeof x);
    return 0;
}

/* ---- RSA's private operation with the CRT ---- */

/* r = a mod (m - 1), m odd: the even modulus by the bit-serial reduction */
static void mod_minus_one(oc_limb *r, const oc_limb *a, int ka, const oc_limb *m, int k)
{
    oc_limb mm[OC_BN_MAX];
    memcpy(mm, m, sizeof(oc_limb) * (size_t)k);
    mm[0] &= ~(oc_limb)1;
    oc_bn_mod(r, a, ka, mm, k);
}

int oc_rsa_private(uint8_t *out, const uint8_t *in,
                   const uint8_t *n, size_t n_length,
                   const uint8_t *e, size_t e_length,
                   const uint8_t *d, size_t d_length,
                   const uint8_t *p, size_t p_length,
                   const uint8_t *q, size_t q_length,
                   const uint8_t *dp, size_t dp_length,
                   const uint8_t *dq, size_t dq_length,
                   const uint8_t *qinv, size_t qinv_length)
{
    /* the halves are up to OC_BN_MAX limbs each so that unbalanced keys work */
    oc_limb pp[OC_BN_MAX], qq[OC_BN_MAX], c[OC_BN_MAX], t[OC_BN_MAX + 1];
    oc_limb ep[OC_BN_MAX], eq[OC_BN_MAX], mp[OC_BN_MAX], mq[OC_BN_MAX], h[OC_BN_MAX];
    oc_limb res[2 * OC_BN_MAX];
    uint8_t eb[OC_RSA_MAX_BYTES], check[OC_RSA_MAX_BYTES];
    oc_mont Mp, Mq;
    size_t nl, pl, ql;
    int kn, kp, kq, i, rc = -1;
    const uint8_t *nn = n, *in_b = in;

    if (!out || !in || !n || !e || !p || !q || (!d && !(dp && dq))) return -1;
    nl = strip(&nn, n_length);
    in_b = in + (n_length - nl);
    pl = strip(&p, p_length);
    ql = strip(&q, q_length);
    if (!nl || nl > OC_RSA_MAX_BYTES || !pl || !ql || pl > nl || ql > nl) return -1;
    if (d && d_length > OC_RSA_MAX_BYTES + 4) return -1;
    for (i = 0; i < (int)(n_length - nl); ++i)
        if (in[i]) return -1;
    kn = (int)((nl + 3) / 4);
    kp = (int)((pl + 3) / 4);
    kq = (int)((ql + 3) / 4);
    if (kp + kq > kn + 1) return -1;
    oc_bn_from_bytes(pp, kp, p, pl);
    oc_bn_from_bytes(qq, kq, q, ql);
    if (oc_bn_mont_init(&Mp, pp, kp) || oc_bn_mont_init(&Mq, qq, kq)) return -1;
    oc_bn_from_bytes(c, kn, in_b, nl);
    {
        oc_limb nlimbs[OC_BN_MAX];
        oc_bn_from_bytes(nlimbs, kn, nn, nl);
        if (!oc_bn_less(c, nlimbs, kn)) return -1;
    }

    /* the exponents mod p - 1 and q - 1 */
    if (dp && dp_length) {
        if (dp_length > OC_RSA_MAX_BYTES) return -1;
        oc_bn_from_bytes(t, (int)((dp_length + 3) / 4), dp, dp_length);
        mod_minus_one(ep, t, (int)((dp_length + 3) / 4), pp, kp);
    } else {
        int kd = (int)((d_length + 3) / 4);
        oc_limb dd[OC_BN_MAX + 1];
        oc_bn_from_bytes(dd, kd, d, d_length);
        mod_minus_one(ep, dd, kd, pp, kp);
        oc_cleanse(dd, sizeof dd);
    }
    if (dq && dq_length) {
        if (dq_length > OC_RSA_MAX_BYTES) goto out;
        oc_bn_from_bytes(t, (int)((dq_length + 3) / 4), dq, dq_length);
        mod_minus_one(eq, t, (int)((dq_length + 3) / 4), qq, kq);
    } else {
        int kd = (int)((d_length + 3) / 4);
        oc_limb dd[OC_BN_MAX + 1];
        oc_bn_from_bytes(dd, kd, d, d_length);
        mod_minus_one(eq, dd, kd, qq, kq);
        oc_cleanse(dd, sizeof dd);
    }

    /* m_p = c^dp mod p, m_q = c^dq mod q */
    oc_bn_mod(mp, c, kn, pp, kp);
    oc_bn_to_mont(mp, mp, &Mp);
    oc_bn_to_bytes(eb, (size_t)(4 * kp), ep, kp);
    oc_bn_mont_pow(mp, mp, eb, (size_t)(4 * kp), &Mp);
    oc_bn_from_mont(mp, mp, &Mp);
    oc_bn_mod(mq, c, kn, qq, kq);
    oc_bn_to_mont(mq, mq, &Mq);
    oc_bn_to_bytes(eb, (size_t)(4 * kq), eq, kq);
    oc_bn_mont_pow(mq, mq, eb, (size_t)(4 * kq), &Mq);
    oc_bn_from_mont(mq, mq, &Mq);

    /* qinv = 1/q mod p, given or q^(p-2) */
    if (qinv && qinv_length) {
        if (qinv_length > OC_RSA_MAX_BYTES) goto out;
        oc_bn_from_bytes(t, (int)((qinv_length + 3) / 4), qinv, qinv_length);
        oc_bn_mod(h, t, (int)((qinv_length + 3) / 4), pp, kp);
        oc_bn_to_mont(h, h, &Mp);
    } else {
        oc_limb two[OC_BN_MAX];
        oc_bn_mod(h, qq, kq, pp, kp);
        oc_bn_to_mont(h, h, &Mp);
        memset(two, 0, sizeof(oc_limb) * (size_t)kp);
        two[0] = 2;
        oc_bn_sub(t, pp, two, kp);
        oc_bn_to_bytes(eb, (size_t)(4 * kp), t, kp);
        oc_bn_mont_pow(h, h, eb, (size_t)(4 * kp), &Mp);
    }

    /* h = qinv (m_p - m_q) mod p; m = m_q + h q */
    oc_bn_mod(t, mq, kq, pp, kp);
    oc_bn_mod_sub(t, mp, t, pp, kp);
    oc_bn_mont_mul(h, h, t, &Mp);                   /* plain: (qinv R)(diff)/R */
    memset(res, 0, sizeof(oc_limb) * (size_t)(kp + kq + 1));
    for (i = 0; i < kp; ++i) {
        uint64_t cc = 0;
        int j;
        for (j = 0; j < kq; ++j) {
            cc += (uint64_t)res[i + j] + (uint64_t)h[i] * qq[j];
            res[i + j] = (oc_limb)cc;
            cc >>= 32;
        }
        res[i + kq] = (oc_limb)cc;
    }
    {
        uint64_t cc = 0;
        for (i = 0; i < kp + kq + 1; ++i) {
            cc += (uint64_t)res[i] + (i < kq ? mq[i] : 0);
            res[i] = (oc_limb)cc;
            cc >>= 32;
        }
    }
    memset(out, 0, n_length - nl);
    oc_bn_to_bytes(out + (n_length - nl), nl, res, kp + kq + 1);

    /* a fault or a wrong key must not give a bad signature: check m^e = c */
    if (oc_rsa_public(check, out + (n_length - nl), nn, nl, e, e_length) == 0
        && oc_ct_equal(check, in_b, nl)) {
        rc = 0;
    } else {
        memset(out, 0, n_length);
    }
out:
    oc_cleanse(ep, sizeof ep); oc_cleanse(eq, sizeof eq);
    oc_cleanse(mp, sizeof mp); oc_cleanse(mq, sizeof mq);
    oc_cleanse(h, sizeof h); oc_cleanse(t, sizeof t); oc_cleanse(c, sizeof c);
    oc_cleanse(res, sizeof res); oc_cleanse(eb, sizeof eb);
    oc_cleanse(pp, sizeof pp); oc_cleanse(qq, sizeof qq);
    return rc;
}

/* ---- probable primes (for Diffie-Hellman group exchange) ---- */

static const uint16_t small_primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
    89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
    271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373,
    379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593,
    599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
    701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821,
    823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
    941, 947, 953, 967, 971, 977, 983, 991, 997 };

/* Public values only. Trial division by the primes below 1000, then
 * Miller-Rabin: base 2 and rounds - 1 more bases made from SHA-512 of the
 * number and a counter, so a number cannot be built to fool fixed bases.
 * 1 probably prime, 0 composite, -1 bad arguments. */
int oc_is_probable_prime(const uint8_t *number, size_t length, int rounds)
{
    oc_limb n[OC_BN_MAX], nm1[OC_BN_MAX], one_m[OC_BN_MAX], mone_m[OC_BN_MAX];
    oc_limb x[OC_BN_MAX], a[OC_BN_MAX + 1], dd[OC_BN_MAX];
    uint8_t eb[OC_RSA_MAX_BYTES], hb[4 * (OC_BN_MAX + 1)];
    oc_mont M;
    const uint8_t *num = number;
    size_t len;
    int k, s, i, round;
    if (!number || rounds < 0) return -1;
    if (!rounds) rounds = 40;
    len = strip(&num, length);
    if (len > OC_RSA_MAX_BYTES) return -1;
    if (!len) return 0;
    k = (int)((len + 3) / 4);
    oc_bn_from_bytes(n, k, num, len);
    if (k == 1 && n[0] < 1000) {
        if (n[0] == 2) return 1;
        if (n[0] < 2 || !(n[0] & 1)) return 0;
        for (i = 0; i < (int)(sizeof small_primes / sizeof small_primes[0]); ++i)
            if (n[0] == small_primes[i]) return 1;
        return 0;
    }
    if (!(n[0] & 1)) return 0;
    for (i = 0; i < (int)(sizeof small_primes / sizeof small_primes[0]); ++i) {
        uint32_t r = 0;
        int j;
        for (j = k - 1; j >= 0; --j)
            r = (uint32_t)((((uint64_t)r << 32) | n[j]) % small_primes[i]);
        if (!r) return 0;
    }
    if (oc_bn_mont_init(&M, n, k)) return 0;
    /* n - 1 = 2^s d */
    memset(x, 0, sizeof(oc_limb) * (size_t)k);
    x[0] = 1;
    oc_bn_sub(nm1, n, x, k);
    memcpy(dd, nm1, sizeof(oc_limb) * (size_t)k);
    for (s = 0; !(dd[0] & 1); ++s) {
        for (i = 0; i < k - 1; ++i) dd[i] = dd[i] >> 1 | dd[i + 1] << 31;
        dd[k - 1] >>= 1;
    }
    oc_bn_to_bytes(eb, (size_t)(4 * k), dd, k);
    oc_bn_to_mont(one_m, x, &M);
    oc_bn_to_mont(mone_m, nm1, &M);
    for (round = 0; round < rounds; ++round) {
        int r;
        if (round == 0) {
            memset(a, 0, sizeof(oc_limb) * (size_t)k);
            a[0] = 2;
        } else {
            /* a = 2 + (H mod (n - 3)), H as long as n plus 4 bytes */
            OCSHA512 ctx;
            oc_limb n3[OC_BN_MAX], three[OC_BN_MAX];
            size_t got = 0, want = 4 * (size_t)k + 4;
            uint32_t ctr = 0;
            while (got < want) {
                uint8_t c4[8], dgst[64];
                size_t take;
                c4[0] = (uint8_t)(round >> 24); c4[1] = (uint8_t)(round >> 16);
                c4[2] = (uint8_t)(round >> 8);  c4[3] = (uint8_t)round;
                c4[4] = (uint8_t)(ctr >> 24);   c4[5] = (uint8_t)(ctr >> 16);
                c4[6] = (uint8_t)(ctr >> 8);    c4[7] = (uint8_t)ctr;
                ++ctr;
                oc_sha512_init(&ctx);
                oc_sha512_update(&ctx, "GFOpenCrypto MR", 15);
                oc_sha512_update(&ctx, num, len);
                oc_sha512_update(&ctx, c4, 8);
                oc_sha512_final(&ctx, dgst);
                take = want - got < 64 ? want - got : 64;
                memcpy(hb + got, dgst, take);
                got += take;
            }
            memset(three, 0, sizeof(oc_limb) * (size_t)k);
            three[0] = 3;
            oc_bn_sub(n3, n, three, k);
            oc_bn_from_bytes(a, k + 1, hb, want);
            oc_bn_mod(a, a, k + 1, n3, k);
            three[0] = 2;
            oc_bn_add(a, a, three, k);
        }
        oc_bn_to_mont(x, a, &M);
        oc_bn_mont_pow(x, x, eb, (size_t)(4 * k), &M);
        if (!memcmp(x, one_m, sizeof(oc_limb) * (size_t)k)
            || !memcmp(x, mone_m, sizeof(oc_limb) * (size_t)k))
            continue;
        for (r = 1; r < s; ++r) {
            oc_bn_mont_mul(x, x, x, &M);
            if (!memcmp(x, mone_m, sizeof(oc_limb) * (size_t)k)) break;
            if (!memcmp(x, one_m, sizeof(oc_limb) * (size_t)k)) return 0;
        }
        if (r >= s) return 0;
    }
    return 1;
}
