/* GFOpenCrypto: constant-time big numbers, for the private-key operations
 * (RSA with CRT, Diffie-Hellman's modular exponentiation, ECDSA signing).
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Numbers are arrays of 32-bit limbs, least significant first. Nothing
 * here branches on or indexes by a value's bits: only the sizes (limb
 * counts, the exponent's byte count) and the modulus steer the code. */
#ifndef OC_BN_H
#define OC_BN_H

#include "gfopencrypto/gfopencrypto.h"

typedef uint32_t oc_limb;

#define OC_BN_MAX (OC_RSA_MAX_BYTES / 4 + 1)   /* limbs: up to 8192 bits */

typedef struct {
    int k;                      /* limbs */
    const oc_limb *m;           /* the odd modulus, k limbs */
    oc_limb m0inv;              /* -1/m mod 2^32 */
    oc_limb rr[OC_BN_MAX];      /* R^2 mod m, R = 2^(32k) */
} oc_mont;

void oc_bn_from_bytes(oc_limb *x, int k, const uint8_t *b, size_t len);
void oc_bn_to_bytes(uint8_t *b, size_t len, const oc_limb *x, int k);
oc_limb oc_bn_add(oc_limb *r, const oc_limb *a, const oc_limb *b, int k);
oc_limb oc_bn_sub(oc_limb *r, const oc_limb *a, const oc_limb *b, int k);
/* r = mask ? a : r (mask all ones or zero) */
void oc_bn_cmov(oc_limb *r, const oc_limb *a, oc_limb mask, int k);
/* all ones when a is zero, else zero */
oc_limb oc_bn_zero_mask(const oc_limb *a, int k);
/* a < m as public values (not constant time): 1 or 0 */
int oc_bn_less(const oc_limb *a, const oc_limb *m, int k);

/* 0, or -1 when m is even or 1 */
int oc_bn_mont_init(oc_mont *M, const oc_limb *m, int k);
/* r = a b / R mod m; a, b below m (a below R is enough when b is below m) */
void oc_bn_mont_mul(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_mont *M);
/* r = a + b, a - b mod m, operands below m */
void oc_bn_mod_add(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_limb *m, int k);
void oc_bn_mod_sub(oc_limb *r, const oc_limb *a, const oc_limb *b, const oc_limb *m, int k);
/* r (k limbs) = a (ka limbs) mod m (k limbs, top limb nonzero); bit by bit */
void oc_bn_mod(oc_limb *r, const oc_limb *a, int ka, const oc_limb *m, int k);
/* r = x^e, x and r in Montgomery form, e big-endian, every bit of its elen
 * bytes taken (four at a time, from a table read whole each time) */
void oc_bn_mont_pow(oc_limb *r, const oc_limb *x, const uint8_t *e, size_t elen, const oc_mont *M);
/* to and from Montgomery form */
void oc_bn_to_mont(oc_limb *r, const oc_limb *a, const oc_mont *M);
void oc_bn_from_mont(oc_limb *r, const oc_limb *a, const oc_mont *M);

#endif
