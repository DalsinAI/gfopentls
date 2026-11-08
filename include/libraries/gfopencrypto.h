#ifndef LIBRARIES_OPENCRYPTO_H
#define LIBRARIES_OPENCRYPTO_H

#include <exec/types.h>
#include <gfopencrypto/gfopencrypto.h>

#define OPENCRYPTOLIB_NAME "gfopencrypto.library"
#define OPENCRYPTOLIB_VERSION 2
#define OPENCRYPTOLIB_REVISION 4

struct OCBufferHash {
    const void *data;
    ULONG length;
    UBYTE *out;
};

struct OCHmacRequest {
    const void *key;
    ULONG key_length;
    const void *data;
    ULONG data_length;
    UBYTE *out;
};

struct OCHKDFRequest {
    const void *salt;
    ULONG salt_length;
    const void *ikm;
    ULONG ikm_length;
    const void *info;
    ULONG info_length;
    void *out;
    ULONG out_length;
};

struct OCCompareRequest {
    const void *a;
    const void *b;
    ULONG length;
};

struct OCCleanseRequest {
    void *data;
    ULONG length;
};

/* ---- version 2 (8 Oct 2026): SSH's key exchanges, host keys and ciphers ----
 * Each call answers 0 when done (or 1/0 for a verification) and a
 * negative number when it refused: OCERR_ARGS for bad sizes or a NULL
 * pointer, OCERR_STACK when the calling task has less stack free than the
 * operation needs (OC_STACK_NEEDED: sntrup761 builds its polynomials on
 * the stack, so that several tasks can call at once). OC_Accelerated()
 * says which operations this machine runs as host code (OCF_*, in
 * <gfopencrypto/gfopencrypto.h>): on AmiCradle all of them, on a real Amiga
 * none, where every call runs as 68k code. */
#define OCERR_ARGS (-1)
#define OCERR_STACK (-2)
#define OC_STACK_NEEDED 32768

struct OCX25519Request {          /* out = scalar * point; point NULL: the base point (9) */
    UBYTE *out;                   /* 32 bytes */
    const UBYTE *scalar;          /* 32 bytes */
    const UBYTE *point;           /* 32 bytes or NULL */
};                                /* 0; -1 for an all-zero result (refuse it) */

struct OCEd25519Request {
    const UBYTE *sig;             /* 64 bytes */
    const UBYTE *pk;              /* 32 bytes */
    const void *msg;
    ULONG length;
};                                /* 1 valid, 0 not */

struct OCKemRequest {             /* sntrup761 */
    UBYTE *pk;                    /* 1158 bytes: KeyPair's output, Enc's input */
    UBYTE *sk;                    /* 1763 bytes: KeyPair's output, Dec's input */
    UBYTE *ct;                    /* 1039 bytes: Enc's output, Dec's input */
    UBYTE *ss;                    /* 32 bytes: Enc's and Dec's output */
    const UBYTE *seed;            /* 32 fresh secret random bytes (KeyPair, Enc) */
};

struct OCBlocksRequest {          /* SHA-256 or SHA-1 (64-byte blocks), SHA-512 (128) */
    UBYTE *state;                 /* 32, 64 or (SHA-1) 20 bytes, big-endian; changed */
    const void *data;
    ULONG blocks;
};

struct OCChaChaRequest {          /* ChaCha20, 64-bit nonce and counter */
    UBYTE *out;
    const UBYTE *in;              /* may be out; NULL for the key stream */
    ULONG length;
    const UBYTE *key;             /* 32 bytes */
    const UBYTE *nonce;           /* 8 bytes */
    ULONG counter_hi, counter_lo; /* the first block's number */
};

struct OCPolyRequest {
    UBYTE *tag;                   /* 16 bytes */
    const void *data;
    ULONG length;
    const UBYTE *key;             /* 32 bytes, once only */
};

struct OCAESRequest {
    UBYTE *buf;                   /* changed in place */
    ULONG length;                 /* CBC, ECB: whole blocks */
    const UBYTE *key;
    ULONG key_length;             /* 16, 24 or 32 */
    const UBYTE *iv;              /* 16 bytes: the IV or the first counter block */
    ULONG mode;                   /* OC_AES_CTR, _CBC_ENCRYPT, _CBC_DECRYPT, _ECB_ENCRYPT */
};

struct OCRSARequest {             /* out = sig^e mod n, big-endian */
    UBYTE *out;                   /* n_length bytes */
    const UBYTE *sig;             /* n_length bytes */
    const UBYTE *n;
    ULONG n_length;               /* up to OC_RSA_MAX_BYTES */
    const UBYTE *e;
    ULONG e_length;
};

struct OCECDSARequest {
    LONG curve;                   /* 256, 384 or 521 */
    const UBYTE *qx, *qy, *r, *s; /* (curve + 7) / 8 bytes each, big-endian */
    const UBYTE *hash;
    ULONG hash_length;
};                                /* 1 valid, 0 not */

/* ---- version 2, revision 1 (20 October 2026): for TLS 1.3 ---- */

struct OCRSAPSSRequest {          /* RSASSA-PSS, MGF1 with the same hash */
    const UBYTE *sig;             /* n_length bytes */
    const UBYTE *n;
    ULONG n_length;               /* up to OC_RSA_MAX_BYTES */
    const UBYTE *e;
    ULONG e_length;
    const UBYTE *hash;            /* the message's hash */
    ULONG hash_length;            /* 32 SHA-256, 48 SHA-384, 64 SHA-512 */
    LONG salt_length;             /* -1: any */
};                                /* 1 valid, 0 not */

/* ---- version 2, revision 2 (6 November 2026): SHA-1 ----
 * OC_SHA1(struct OCBufferHash *): out gets 20 bytes (OC_SHA1_BYTES).
 * OC_SHA1Blocks(struct OCBlocksRequest *): whole 64-byte blocks, the
 * chaining value as 20 big-endian bytes; start it from OC_SHA1_IV and pad
 * the last block yourself (FIPS 180-4 5.1.1), as for OC_SHA256Blocks.
 * SHA-1 is for formats that name it; it is not collision resistant.
 * Both run as 68k code on every machine (no OCF_ flag). */
#define OC_SHA1_IV { 0x67,0x45,0x23,0x01, 0xef,0xcd,0xab,0x89, \
                     0x98,0xba,0xdc,0xfe, 0x10,0x32,0x54,0x76, \
                     0xc3,0xd2,0xe1,0xf0 }

/* ---- version 2, revision 3 (6 November 2026): for GFOpenTLS ----
 * OC_MD5Blocks(struct OCBlocksRequest *): whole 64-byte blocks, the
 * chaining value as 16 little-endian bytes (MD5's own order, RFC 1321);
 * start it from OC_MD5_IV and pad the last block yourself. MD5 is only for
 * what still names it (TLS 1.0 and 1.1).
 * OC_GHASH(struct OCGHASHRequest *): y = GHASH_h(y, data), NIST SP 800-38D;
 * a partial last block counts as if padded with zeros. 0 done.
 * OC_ECMul(struct OCECMulRequest *): point (uncompressed, 1 + 2 * field
 * bytes) = scalar * point on P-256, P-384 or P-521; 1 done, 0 refused (not
 * on the curve, a zero scalar, the point at infinity).
 * OC_ECMulGen(struct OCECMulRequest *): point = scalar * G (point_length
 * ignored); the point's length, or 0 refused.
 * OC_MD5Blocks and OC_GHASH run as 68k code on every machine. OC_ECMul and
 * OC_ECMulGen are magic functions, in constant time: host code on AC090,
 * this same C as 68k code when the tag is declined. Since this revision
 * OC_RSAPublic, OC_ECDSAVerify, OC_ECMul and OC_ECMulGen run on a
 * stack of their own when the caller has too little free, rather than
 * answering OCERR_STACK (which they still answer if that memory is not
 * there). */
#define OC_MD5_IV { 0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef, \
                    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10 }

struct OCGHASHRequest {
    UBYTE *y;                     /* 16 bytes, in and out */
    const UBYTE *h;               /* 16 bytes: the hash key */
    const void *data;
    ULONG length;
};

struct OCECMulRequest {
    LONG curve;                   /* 256, 384 or 521 */
    UBYTE *point;                 /* 0x04 || x || y */
    ULONG point_length;
    const UBYTE *scalar;          /* big-endian */
    ULONG scalar_length;
};

/* ---- version 2, revision 4 (6 November 2026): for FileZilla ----
 * HMAC with SHA-1 and SHA-512, PBKDF2, SHA-3 and SHAKE256, Argon2, Ed25519
 * and ECDSA signing, ECDSA key generation, constant-time modular
 * exponentiation (Diffie-Hellman), RSA's private operation with the CRT,
 * and a probable-prime test. All run as 68k code on every machine (no
 * OCF_ flag), the secret ones in constant time, and like the public-key
 * calls of revision 3 on a stack of their own when the caller's is short.
 * <gfopencrypto/gfopencrypto.h> says more about each (oc_hmac, oc_pbkdf2,
 * oc_sha3_*, oc_argon2, oc_ed25519_sign, oc_ecdsa_sign, oc_ec_keygen,
 * oc_modexp, oc_rsa_private, oc_is_probable_prime).
 *
 * OC_HMAC_SHA1, OC_HMAC_SHA512(struct OCHmacRequest *): out gets 20 or 64
 * bytes, as OC_HMAC_SHA256 does.
 * OC_PBKDF2(struct OCPBKDF2Request *): 0, or OCERR_ARGS.
 * OC_SHA3(struct OCSHA3Request *): one call, ctx unused. OC_SHA3Init,
 * OC_SHA3Update, OC_SHA3Final: the same request with ctx pointing at the
 * caller's struct OCSHA3 (init reads variant; update data and length;
 * final out and out_length). 0, or OCERR_ARGS.
 * OC_Argon2(struct OCArgon2Request *): the library allocates the memory
 * (m_kib KB, MEMF_ANY) and frees it; 0, OCERR_ARGS or OCERR_NOMEM.
 * OC_Ed25519Sign(struct OCEd25519SignRequest *): out gets 64 bytes.
 * OC_Ed25519PublicKey(struct OCEd25519SignRequest *): out gets 32 bytes
 * (msg and length unused). Both 0, or OCERR_ARGS.
 * OC_ECDSASign(struct OCECDSASignRequest *): 0, or OCERR_ARGS.
 * OC_ECKeyGen(struct OCECKeyGenRequest *): the point's length, or 0.
 * OC_ModExp(struct OCModExpRequest *): 0, or OCERR_ARGS.
 * OC_RSAPrivate(struct OCRSAPrivateRequest *): 0, or OCERR_ARGS (also for
 * a key whose answer does not check out with e).
 * OC_IsProbablePrime(struct OCPrimeRequest *): 1 probably prime, 0
 * composite, OCERR_ARGS. */
#define OCERR_NOMEM (-3)

/* OC_HASH_SHA1 .. OC_HASH_SHA512, OC_SHA3_*, OC_SHAKE256, OC_ARGON2* and
 * struct OCSHA3 are in <gfopencrypto/gfopencrypto.h> */

struct OCPBKDF2Request {
    LONG hash;                    /* OC_HASH_SHA1, _SHA256, _SHA384, _SHA512 */
    const void *password;
    ULONG password_length;
    const void *salt;
    ULONG salt_length;
    ULONG iterations;             /* 1 or more */
    UBYTE *out;
    ULONG out_length;
};

struct OCSHA3Request {
    OCSHA3 *ctx;                  /* the caller's (Init, Update, Final); unused by OC_SHA3 */
    LONG variant;                 /* OC_SHA3_256, _384, _512, OC_SHAKE256 */
    const void *data;
    ULONG length;
    UBYTE *out;
    ULONG out_length;             /* the digest's size; SHAKE256 any */
};

struct OCArgon2Request {
    LONG type;                    /* OC_ARGON2D, OC_ARGON2I, OC_ARGON2ID */
    UBYTE *out;
    ULONG out_length;             /* 4 or more */
    const void *password;
    ULONG password_length;
    const void *salt;
    ULONG salt_length;            /* 8 or more */
    const void *secret;           /* may be NULL */
    ULONG secret_length;
    const void *ad;               /* may be NULL */
    ULONG ad_length;
    ULONG passes, m_kib, lanes;   /* t, m (KB, at least 8 * lanes), p */
};

struct OCEd25519SignRequest {
    UBYTE *out;                   /* 64 bytes (Sign) or 32 (PublicKey) */
    const UBYTE *seed;            /* the 32-byte private key */
    const void *msg;
    ULONG length;
};

struct OCECDSASignRequest {
    LONG curve;                   /* 256, 384 or 521 */
    UBYTE *r, *s;                 /* (curve + 7) / 8 bytes each, big-endian */
    const UBYTE *d;               /* the private key, the same size */
    const UBYTE *hash;
    ULONG hash_length;            /* 20, 32, 48 or 64: RFC 6979 uses that hash */
};

struct OCECKeyGenRequest {
    LONG curve;
    UBYTE *d;                     /* (curve + 7) / 8 bytes out */
    UBYTE *point;                 /* 1 + 2 * that out: 04 || x || y */
    const UBYTE *seed;            /* fresh secret random bytes */
    ULONG seed_length;            /* at least d's size + 8 */
};

struct OCModExpRequest {          /* out = base^exponent mod modulus */
    UBYTE *out;                   /* modulus_length bytes */
    const UBYTE *base;
    ULONG base_length;
    const UBYTE *exponent;
    ULONG exponent_length;
    const UBYTE *modulus;         /* odd, up to OC_RSA_MAX_BYTES */
    ULONG modulus_length;
};

struct OCRSAPrivateRequest {      /* out = in^d mod n, big-endian */
    UBYTE *out;                   /* n_length bytes */
    const UBYTE *in;              /* n_length bytes, below n */
    const UBYTE *n; ULONG n_length;
    const UBYTE *e; ULONG e_length;
    const UBYTE *d; ULONG d_length;
    const UBYTE *p; ULONG p_length;
    const UBYTE *q; ULONG q_length;
    const UBYTE *dp; ULONG dp_length;     /* the last three may be NULL */
    const UBYTE *dq; ULONG dq_length;
    const UBYTE *qinv; ULONG qinv_length;
};

struct OCPrimeRequest {
    const UBYTE *number;
    ULONG length;
    LONG rounds;                  /* 0: 40 */
};

#endif
