#ifndef LIBRARIES_OPENCRYPTO_H
#define LIBRARIES_OPENCRYPTO_H

#include <exec/types.h>
#include <gfopencrypto/gfopencrypto.h>

#define OPENCRYPTOLIB_NAME "gfopencrypto.library"
#define OPENCRYPTOLIB_VERSION 2
#define OPENCRYPTOLIB_REVISION 2

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

#endif
