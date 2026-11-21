/* GFOpenTLS: the types the library's parts share. Their shapes are
 * BearSSL's (MIT), which GFOpenTLS was built on until 2.0, so that the
 * host tests can still hold the code to BearSSL's; the code is all ours.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#ifndef OT_TYPES_H
#define OT_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* ---- hashes ---- */

typedef struct ot_hash_class_ ot_hash_class;
struct ot_hash_class_ {
    size_t context_size;
    uint32_t desc;                   /* OT_HASHDESC_* */
    void (*init)(const ot_hash_class **ctx);
    void (*update)(const ot_hash_class **ctx, const void *data, size_t len);
    void (*out)(const ot_hash_class *const *ctx, void *dst);
    uint64_t (*state)(const ot_hash_class *const *ctx, void *dst);
    void (*set_state)(const ot_hash_class **ctx, const void *stb, uint64_t count);
};

#define OT_HASHDESC_ID(id)           ((uint32_t)(id) << OT_HASHDESC_ID_OFF)
#define OT_HASHDESC_ID_OFF           0
#define OT_HASHDESC_ID_MASK          0xFF
#define OT_HASHDESC_OUT(size)        ((uint32_t)(size) << OT_HASHDESC_OUT_OFF)
#define OT_HASHDESC_OUT_OFF          8
#define OT_HASHDESC_OUT_MASK         0x7F
#define OT_HASHDESC_STATE(size)      ((uint32_t)(size) << OT_HASHDESC_STATE_OFF)
#define OT_HASHDESC_STATE_OFF        15
#define OT_HASHDESC_STATE_MASK       0xFF
#define OT_HASHDESC_LBLEN(ls)        ((uint32_t)(ls) << OT_HASHDESC_LBLEN_OFF)
#define OT_HASHDESC_LBLEN_OFF        23
#define OT_HASHDESC_LBLEN_MASK       0x0F
#define OT_HASHDESC_MD_PADDING       ((uint32_t)1 << 28)
#define OT_HASHDESC_MD_PADDING_128   ((uint32_t)1 << 29)
#define OT_HASHDESC_MD_PADDING_BE    ((uint32_t)1 << 30)

#define ot_md5_ID     1
#define ot_sha1_ID    2
#define ot_sha224_ID  3
#define ot_sha256_ID  4
#define ot_sha384_ID  5
#define ot_sha512_ID  6

/* the DER of each hash's OID, after a length byte (PKCS #1 v1.5's DigestInfo) */
#define OT_HASH_OID_SHA1   ((const unsigned char *)"\x05\x2B\x0E\x03\x02\x1A")
#define OT_HASH_OID_SHA256 ((const unsigned char *)"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")
#define OT_HASH_OID_SHA384 ((const unsigned char *)"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02")
#define OT_HASH_OID_SHA512 ((const unsigned char *)"\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")

typedef struct {
    const ot_hash_class *vtable;
    unsigned char buf[64];
    uint64_t count;
    uint32_t val[4];
} ot_md5_context;
typedef struct {
    const ot_hash_class *vtable;
    unsigned char buf[64];
    uint64_t count;
    uint32_t val[5];
} ot_sha1_context;
typedef struct {
    const ot_hash_class *vtable;
    unsigned char buf[64];
    uint64_t count;
    uint32_t val[8];
} ot_sha224_context;
typedef ot_sha224_context ot_sha256_context;
typedef struct {
    const ot_hash_class *vtable;
    unsigned char buf[128];
    uint64_t count;
    uint64_t val[8];
} ot_sha384_context;
typedef ot_sha384_context ot_sha512_context;

typedef union {
    const ot_hash_class *vtable;
    ot_md5_context md5;
    ot_sha1_context sha1;
    ot_sha224_context sha224;
    ot_sha256_context sha256;
    ot_sha384_context sha384;
    ot_sha512_context sha512;
} ot_hash_compat_context;

/* over GFOpenCrypto, in ot_glue.c */
extern const ot_hash_class ot_md5_vtable, ot_sha1_vtable, ot_sha224_vtable, ot_sha256_vtable,
                           ot_sha384_vtable, ot_sha512_vtable;
void ot_md5_init(ot_md5_context *ctx);
void ot_md5_update(ot_md5_context *ctx, const void *data, size_t len);
void ot_md5_out(const ot_md5_context *ctx, void *out);
uint64_t ot_md5_state(const ot_md5_context *ctx, void *out);
void ot_md5_set_state(ot_md5_context *ctx, const void *stb, uint64_t count);
void ot_sha1_init(ot_sha1_context *ctx);
void ot_sha1_update(ot_sha1_context *ctx, const void *data, size_t len);
void ot_sha1_out(const ot_sha1_context *ctx, void *out);
uint64_t ot_sha1_state(const ot_sha1_context *ctx, void *out);
void ot_sha1_set_state(ot_sha1_context *ctx, const void *stb, uint64_t count);
void ot_sha224_init(ot_sha224_context *ctx);
void ot_sha224_update(ot_sha224_context *ctx, const void *data, size_t len);
void ot_sha224_out(const ot_sha224_context *ctx, void *out);
uint64_t ot_sha224_state(const ot_sha224_context *ctx, void *out);
void ot_sha224_set_state(ot_sha224_context *ctx, const void *stb, uint64_t count);
void ot_sha256_init(ot_sha256_context *ctx);
#define ot_sha256_update ot_sha224_update
void ot_sha256_out(const ot_sha256_context *ctx, void *out);
#define ot_sha256_state ot_sha224_state
#define ot_sha256_set_state ot_sha224_set_state
void ot_sha384_init(ot_sha384_context *ctx);
void ot_sha384_update(ot_sha384_context *ctx, const void *data, size_t len);
void ot_sha384_out(const ot_sha384_context *ctx, void *out);
uint64_t ot_sha384_state(const ot_sha384_context *ctx, void *out);
void ot_sha384_set_state(ot_sha384_context *ctx, const void *stb, uint64_t count);
void ot_sha512_init(ot_sha512_context *ctx);
#define ot_sha512_update ot_sha384_update
void ot_sha512_out(const ot_sha512_context *ctx, void *out);
#define ot_sha512_state ot_sha384_state
#define ot_sha512_set_state ot_sha384_set_state

/* ---- block ciphers and AEAD pieces ---- */

typedef struct ot_block_cbcenc_class_ ot_block_cbcenc_class;
struct ot_block_cbcenc_class_ {
    size_t context_size;
    unsigned block_size, log_block_size;
    void (*init)(const ot_block_cbcenc_class **ctx, const void *key, size_t key_len);
    void (*run)(const ot_block_cbcenc_class *const *ctx, void *iv, void *data, size_t len);
};
typedef struct ot_block_cbcdec_class_ ot_block_cbcdec_class;
struct ot_block_cbcdec_class_ {
    size_t context_size;
    unsigned block_size, log_block_size;
    void (*init)(const ot_block_cbcdec_class **ctx, const void *key, size_t key_len);
    void (*run)(const ot_block_cbcdec_class *const *ctx, void *iv, void *data, size_t len);
};
typedef struct ot_block_ctr_class_ ot_block_ctr_class;
struct ot_block_ctr_class_ {
    size_t context_size;
    unsigned block_size, log_block_size;
    void (*init)(const ot_block_ctr_class **ctx, const void *key, size_t key_len);
    uint32_t (*run)(const ot_block_ctr_class *const *ctx, const void *iv, uint32_t cc, void *data, size_t len);
};
typedef void (*ot_ghash)(void *y, const void *h, const void *data, size_t len);
typedef uint32_t (*ot_chacha20_run)(const void *key, const void *iv, uint32_t cc, void *data, size_t len);
typedef void (*ot_poly1305_run)(const void *key, const void *iv, void *data, size_t len,
                                const void *aad, size_t aad_len, void *tag, ot_chacha20_run ichacha, int encrypt);

/* ---- public keys ---- */

#define OT_KEYTYPE_RSA    1
#define OT_KEYTYPE_EC     2
#define OT_KEYTYPE_KEYX   0x10           /* the key may exchange keys (RSA key exchange, static ECDH) */
#define OT_KEYTYPE_SIGN   0x20           /* the key may sign */

#define OT_EC_secp256r1   23
#define OT_EC_secp384r1   24
#define OT_EC_secp521r1   25
#define OT_EC_curve25519  29

typedef struct {
    unsigned char *n;
    size_t nlen;
    unsigned char *e;
    size_t elen;
} ot_rsa_public_key;
typedef struct {
    int curve;
    unsigned char *q;                /* uncompressed: 04, X, Y */
    size_t qlen;
} ot_ec_public_key;
typedef struct {
    unsigned char key_type;          /* OT_KEYTYPE_RSA or OT_KEYTYPE_EC */
    union {
        ot_rsa_public_key rsa;
        ot_ec_public_key ec;
    } key;
} ot_x509_pkey;

/* an elliptic curve implementation: points uncompressed (or X25519's u) */
typedef struct {
    uint32_t supported_curves;
    const unsigned char *(*generator)(int curve, size_t *len);
    const unsigned char *(*order)(int curve, size_t *len);
    size_t (*xoff)(int curve, size_t *len);
    uint32_t (*mul)(unsigned char *G, size_t Glen, const unsigned char *x, size_t xlen, int curve);
    size_t (*mulgen)(unsigned char *R, const unsigned char *x, size_t xlen, int curve);
    uint32_t (*muladd)(unsigned char *A, const unsigned char *B, size_t len, const unsigned char *x, size_t xlen,
                       const unsigned char *y, size_t ylen, int curve);
} ot_ec_impl;

typedef uint32_t (*ot_rsa_public)(unsigned char *x, size_t xlen, const ot_rsa_public_key *pk);
typedef uint32_t (*ot_rsa_pkcs1_vrfy)(const unsigned char *x, size_t xlen, const unsigned char *hash_oid,
                                      size_t hash_len, const ot_rsa_public_key *pk, unsigned char *hash_out);
typedef uint32_t (*ot_ecdsa_vrfy)(const ot_ec_impl *impl, const void *hash, size_t hash_len,
                                  const ot_ec_public_key *pk, const void *sig, size_t sig_len);

/* ---- certificates ---- */

typedef struct {
    unsigned char *data;
    size_t len;
} ot_x500_name;
#define OT_X509_TA_CA     0x0001         /* the anchor may sign certificates */
typedef struct {
    ot_x500_name dn;                 /* the subject, whole DER */
    unsigned flags;
    ot_x509_pkey pkey;
} ot_x509_trust_anchor;

/* the certificate engine the handshake feeds (ot_x509.c is the one) */
typedef struct ot_x509_class_ ot_x509_class;
struct ot_x509_class_ {
    size_t context_size;
    void (*start_chain)(const ot_x509_class **ctx, const char *server_name);
    void (*start_cert)(const ot_x509_class **ctx, uint32_t length);
    void (*append)(const ot_x509_class **ctx, const unsigned char *buf, size_t len);
    void (*end_cert)(const ot_x509_class **ctx);
    unsigned (*end_chain)(const ot_x509_class **ctx);
    const ot_x509_pkey *(*get_pkey)(const ot_x509_class *const *ctx, unsigned *usages);
};

/* ---- records and error codes ---- */

#define OT_SSL_CHANGE_CIPHER_SPEC    20
#define OT_SSL_ALERT                 21
#define OT_SSL_HANDSHAKE             22
#define OT_SSL_APPLICATION_DATA      23

/* the handshake's and the certificate checks' codes (OT_GetErrorDetail) */
#define OT_ERR_BAD_PARAM               1
#define OT_ERR_UNSUPPORTED_VERSION     3
#define OT_ERR_BAD_VERSION             4
#define OT_ERR_TOO_LARGE               6
#define OT_ERR_BAD_MAC                 7
#define OT_ERR_NO_RANDOM               8
#define OT_ERR_BAD_CIPHER_SUITE       16
#define OT_ERR_BAD_FINISHED           24
#define OT_ERR_INVALID_ALGORITHM      26
#define OT_ERR_BAD_SIGNATURE          27
#define OT_ERR_WRONG_KEY_USAGE        28
#define OT_ERR_IO                     31
#define OT_ERR_X509_OK                32
#define OT_ERR_X509_INVALID_VALUE     33
#define OT_ERR_X509_EMPTY_CHAIN       35
#define OT_ERR_X509_BAD_TIME          48
#define OT_ERR_X509_UNSUPPORTED       49
#define OT_ERR_X509_LIMIT_EXCEEDED    50
#define OT_ERR_X509_WRONG_KEY_TYPE    51
#define OT_ERR_X509_BAD_SIGNATURE     52
#define OT_ERR_X509_TIME_UNKNOWN      53
#define OT_ERR_X509_EXPIRED           54
#define OT_ERR_X509_BAD_SERVER_NAME   56
#define OT_ERR_X509_CRITICAL_EXTENSION 57
#define OT_ERR_X509_NOT_CA            58
#define OT_ERR_X509_FORBIDDEN_KEY_USAGE 59
#define OT_ERR_X509_WEAK_PUBLIC_KEY   60
#define OT_ERR_X509_NOT_TRUSTED       62
#define OT_ERR_RECV_FATAL_ALERT      256   /* plus the alert */
#define OT_ERR_SEND_FATAL_ALERT      512   /* plus the alert */

#endif
