/* GFOpenTLS internals: the connection, context and session structures, and
 * what the platform layer (ot_platform.c) gives the rest.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#ifndef OT_INTERNAL_H
#define OT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <exec/types.h>
#include <exec/libraries.h>
#include <utility/hooks.h>
#include <libraries/gfopentls.h>

#include "bearssl.h"

#define OT_LIB_VERSION   1
#define OT_LIB_REVISION  8          /* 1.1: OT_GetPeerName; 1.2: S:GFOpenTLS/ca-bundle.pem, ENVARC:GFOpenTLS/certs/;
                                       1.3: TLS 1.3, OT_SetVersion, OT_SessionHasTicket;
                                       1.4: all maths in gfopencrypto.library 2.3, none of BearSSL's;
                                       1.5: OTV_REPORT, the whole chain, certificate fields, group and MAC names;
                                       1.6: TLS 1.2 with ECDHE and AEAD suites by our own client;
                                       1.7: the key work on the services card (OTACC_SERVICE);
                                       1.8: our own certificate checks, not BearSSL's */

#define OT_HOST_MAX      255
#define OT_ALPN_MAX      8          /* protocols offered at once */
#define OT_TEXT_MAX      200
#define OT_LEAF_MAX      16384      /* the server's certificate kept for the caller */
#define OT_OUT_MAX       4096       /* small records gathered into one send */
#define OT_IOBUF_SMALL   (5 + 16384 + 320)               /* one record in (OT13_RX_MAX) */
#define OT_IOBUF_LARGE   (OT_IOBUF_SMALL + 5 + 16384 + 80 + 64)  /* and one whole record out */
#define OT_CHAIN_MAX     10         /* certificates kept from the server's chain */
#define OT_CHAIN_BYTES   65536      /* and their bytes together */

/* Our own engine error codes, past BearSSL's X.509 range (32..63). */
#define OT_X509_PINNED     70       /* OTV_PINNED_ONLY and not the pin */
#define OT_X509_IP         71       /* the certificate does not name the address */

/* ---- platform (ot_platform.c) ---- */
void *ot_alloc(size_t size);            /* zeroed; NULL when out of memory */
void ot_free(void *p);
void *ot_lock_new(void);
void ot_lock(void *lock);
void ot_unlock(void *lock);
void ot_lock_free(void *lock);
/* the whole file in a fresh ot_alloc()ed buffer, NUL after it; 0 if unreadable */
int ot_read_file(const char *path, unsigned char **data, size_t *length);
/* calls fn(path, ctx) for each file in dir whose name ends in suffix */
int ot_each_file(const char *dir, const char *suffix,
                 void (*fn)(const char *path, void *ctx), void *ctx);
/* the time for certificate dates: days since 1 January of year 0, seconds
 * into the day; 0 when the clock is unknown */
int ot_now(uint32_t *days, uint32_t *seconds);
/* local days and seconds (as above) to UTC; west: minutes west of GMT */
void ot_local_to_utc(uint32_t days, uint32_t seconds, long west,
                     uint32_t *udays, uint32_t *useconds);
/* TLS 1.3: records sent under one key before a KeyUpdate (the tests make
 * it small) */
#define OT_KEY_UPDATE_AFTER (1UL << 23)
uint32_t ot_key_update_after(void);
LONG ot_sock_read(LONG fd, struct Library *socketbase, void *buf, LONG len);
LONG ot_sock_write(LONG fd, struct Library *socketbase, const void *buf, LONG len);
LONG ot_hook_call(struct Hook *hook, void *object, struct OTIOMessage *msg);
/* entropy for the generator (ot_random.c): fills out, answers 1 when the
 * platform's source is good on its own */
int ot_platform_entropy(unsigned char *out, size_t len);
/* system trust store locations, in order: the i-th of a kind into buf;
 * 0 past the last */
#define OT_TRUST_BUNDLE   0     /* the CA bundle: the first readable one */
#define OT_TRUST_DIR      1     /* directories of local additions (*.pem) */
#define OT_TRUST_FALLBACK 2     /* other programs' bundles, when no bundle */
int ot_trust_location(int kind, int i, char *buf, size_t size);

/* ---- random (ot_random.c) ---- */
int ot_random_init(void);
void ot_random_cleanup(void);
LONG ot_random(void *buf, size_t len);

/* ---- GFOpenCrypto glue (ot_glue.c) ---- */
ULONG ot_glue_accelerated(void);        /* OTACC_* */
void ot_glue_cleanup(void);             /* library expunge */
int ot_glue_ready(void);               /* gfopencrypto.library 2.3+ is there (Amiga) */
struct ot_impls {
    const br_hash_class *sha256, *sha384, *sha512;
    br_rsa_pkcs1_vrfy rsa_vrfy;
    br_rsa_public rsa_pub;
    br_ecdsa_vrfy ecdsa_vrfy;
    const br_ec_impl *ec;
    const br_block_cbcenc_class *aes_cbcenc;
    const br_block_cbcdec_class *aes_cbcdec;
    const br_block_ctr_class *aes_ctr;
    br_ghash ghash;
    br_chacha20_run chacha20;
    br_poly1305_run poly1305;
};
/* the implementations a connection uses: GFOpenCrypto's where it is
 * accelerated (or everywhere, in the host tests), BearSSL's otherwise */
void ot_glue_select(struct ot_impls *impls, int offload);
/* RSA-PSS (MGF1 with the same hash) of a hash with a salt of salt bytes: 1 valid (ot_tls13.c) */
int ot_rsa_pss(const struct ot_impls *m, const br_rsa_public_key *pk, const br_hash_class *h,
               const unsigned char *hash, size_t salt, const unsigned char *sig, size_t siglen);
/* Ed25519 (TLS 1.3 certificates): whether there is one, and the check (1 valid) */
int ot_glue_has_ed25519(void);
int ot_glue_ed25519(const unsigned char *sig, const unsigned char *pk, const void *msg, size_t len);

/* ---- HMAC and HMAC-DRBG (ot_hmac.c) ---- */
struct ot_hmac_key {
    const br_hash_class *h;
    unsigned char key[128];          /* the key, padded to the hash's block */
};
struct ot_hmac {
    const struct ot_hmac_key *key;
    br_hash_compat_context inner;
};
void ot_hmac_key_init(struct ot_hmac_key *k, const br_hash_class *h, const void *key, size_t len);
void ot_hmac_init(struct ot_hmac *m, const struct ot_hmac_key *k);
void ot_hmac_update(struct ot_hmac *m, const void *data, size_t len);
size_t ot_hmac_out(struct ot_hmac *m, void *out);   /* the hash's output length */
struct ot_drbg {
    unsigned char k[32], v[32];
};
void ot_drbg_init(struct ot_drbg *d, const void *seed, size_t len);
void ot_drbg_update(struct ot_drbg *d, const void *data, size_t len);
void ot_drbg_generate(struct ot_drbg *d, void *out, size_t len);

/* ---- the services card: gfopenservice.device's opentls.key/1 (ot_service.c) ---- */
#define OTK_VERIFY    1
#define OTK_KEYGEN    2
#define OTK_DERIVE    3
#define OTK_RSA_PKCS1 1             /* OTK_VERIFY: arg */
#define OTK_RSA_PSS   2
#define OTK_ECDSA     3
#define OTK_ED25519   4
#define OTK_SHA1      1             /* OTK_VERIFY: extra[0] */
#define OTK_SHA256    2
#define OTK_SHA384    3
#define OTK_SHA512    4
#define OTK_X25519    1             /* OTK_KEYGEN, OTK_DERIVE: arg */
#define OTK_P256      2
#define OTK_P384      3
#define OTSVC_WHERE_CARD 1          /* OSWHERE_CARD: this machine's host */
struct ot_sbuf {
    const unsigned char *in;
    unsigned char *out;
    ULONG length;
    ULONG written;
};
/* one opentls.key/1 request: the service's status (0 done) */
typedef LONG (*ot_svc_transport)(UWORD op, ULONG arg, const ULONG extra[4], struct ot_sbuf buf[4],
                                 ULONG *result, ULONG *aux);
/**
 * Whether the services card can take this kind of work.
 *
 * @param keys                          the key exchange too, not only signature checks: those
 *                                      give the host the session keys, so a card in this machine only
 * @return                              1 when it can
 */
int ot_svc_ready(int keys);
/* a signature check (salt: RSA-PSS's, 0 the digest's length): 1 good, 0 bad, -1 not done (do it here) */
int ot_svc_verify(ULONG alg, ULONG digest, ULONG salt, const unsigned char *spki, size_t spki_len,
                  const unsigned char *data, size_t data_len, const unsigned char *sig, size_t sig_len);
/* a key pair: the public key's length, 0 when not done */
size_t ot_svc_keygen(ULONG curve, unsigned char *priv, size_t priv_len, unsigned char *pub, size_t pub_room);
/* the shared secret: its length, 0 when not done */
size_t ot_svc_derive(ULONG curve, const unsigned char *priv, size_t priv_len,
                     const unsigned char *peer, size_t peer_len, unsigned char *out, size_t room);
ULONG ot_svc_calls(void);               /* requests the card answered */
void ot_svc_install(ot_svc_transport fn, ULONG where);  /* the host tests' card */
int ot_svc_init(void);                  /* library init: the lock */
void ot_svc_cleanup(void);              /* library expunge */

/* ---- trust (ot_trust.c) ---- */
struct ot_anchors {
    br_x509_trust_anchor *ta;
    size_t count, cap;
};
LONG ot_anchors_add_pem(struct ot_anchors *a, const unsigned char *pem, size_t len);
LONG ot_anchors_add_file(struct ot_anchors *a, const char *path);
void ot_anchors_free(struct ot_anchors *a);
/* the system's trust store, loaded once and shared; NULL when none */
const struct ot_anchors *ot_system_anchors(void);
void ot_system_anchors_free(void);
int ot_trust_init(void);                /* library init: the store's lock */

/* ---- X.509 wrapper (ot_x509.c) ---- */
/* a public key as the certificate checks use it */
#define OT_KEY_ED25519 3
struct ot_key {
    unsigned type;                   /* BR_KEYTYPE_RSA, BR_KEYTYPE_EC or OT_KEY_ED25519 */
    br_x509_pkey pk;                 /* RSA and EC */
    const unsigned char *ed;         /* Ed25519: 32 bytes */
    const unsigned char *spki;       /* the SubjectPublicKeyInfo (for the card), or NULL */
    size_t spki_len;
};
struct ot_x509 {
    const br_x509_class *vtable;
    br_sha256_context leaf_hash;
    struct OTConnection *conn;
    const struct ot_impls *impls;
    const br_x509_trust_anchor *ta;
    size_t ta_count;
    int tls13;                       /* the TLS 1.3 client feeds it: Ed25519 leaves too */
    int leaf_ed25519;                /* the leaf's key is Ed25519, in ed25519 */
    unsigned char ed25519[32];
    int cert_index;
    int accepted;                    /* checked, pinned or OTV_NONE: leaf_key is the server's */
    int leaf_ok;
    unsigned char *leaf;
    size_t leaf_len, leaf_cap;
    struct ot_key leaf_key;          /* points into leaf or chain */
    int leaf_key_ok;
    unsigned leaf_usages;            /* BR_KEYTYPE_KEYX, BR_KEYTYPE_SIGN */
    unsigned char fingerprint[32];
    int have_fingerprint;
    unsigned char *chain;            /* the server's certificates, one after another */
    size_t chain_len, chain_cap;
    size_t chain_off[OT_CHAIN_MAX], chain_end[OT_CHAIN_MAX], chain_want[OT_CHAIN_MAX];
    int chain_count;
    int chain_ok;                    /* every certificate so far fitted */
    int verdict;                     /* the checks' answer (engine code, 0 passed; -1 not yet) */
};
void ot_x509_init(struct ot_x509 *x, struct OTConnection *conn,
                  const struct ot_impls *impls,
                  const br_x509_trust_anchor *ta, size_t ta_count);
void ot_x509_free(struct ot_x509 *x);
/* the first DNS name (or CN) of a certificate, for messages */
void ot_cert_name(const unsigned char *der, size_t len, char *out, size_t outlen);
int ot_cert_has_ip(const unsigned char *der, size_t len, const unsigned char *ip, size_t iplen);
/* a certificate as a trust anchor takes it: the subject (whole DER) and
 * the RSA or EC key, pointing into der, and whether it is a CA; 1, or 0
 * when it cannot be one (ot_x509.c) */
int ot_cert_anchor(const unsigned char *der, size_t len, const unsigned char **dn, size_t *dn_len,
                   br_x509_pkey *pk, int *ca);
/* the server certificate's SubjectPublicKeyInfo (DER, whole); 0 when it is not kept */
int ot_x509_spki(const struct ot_x509 *x, const unsigned char **spki, size_t *len);

/* ---- the objects ---- */
struct OTContext {
    ULONG flags;
    LONG min_version, max_version;
    char *alpn;                      /* default list, or NULL */
    struct ot_anchors extra;         /* CAFile and OT_AddTrust*() */
    void *lock;
    br_x509_trust_anchor *merged;    /* system + extra, made at first need */
    size_t merged_count;
    int merged_ok;
    int system_missing;
};

struct ot13_ticket;
struct ot13;

/* a TLS 1.2 session: what resuming it by its ID takes */
struct ot12_session {
    unsigned char session_id[32];
    unsigned char session_id_len;
    uint16_t version;                        /* 0 until the handshake has its master secret */
    uint16_t cipher_suite;
    unsigned char master_secret[48];
};

struct OTSession {
    struct ot12_session params;              /* TLS 1.2 */
    char host[OT_HOST_MAX + 1];
    struct ot13_ticket *t13;                 /* TLS 1.3: the newest ticket, or NULL */
    struct OTConnection *source;             /* still waiting for one from it */
    struct OTSession *next_waiting;
};
/* the lock over sessions waiting for a ticket (ot_core.c) */
int ot_session_init(void);
void ot_session_cleanup(void);
void ot_session_lock(void);
void ot_session_unlock(void);

enum { OTS_NEW, OTS_HANDSHAKE, OTS_OPEN, OTS_CLOSED, OTS_FAILED };

struct OTConnection {
    struct ot_x509 x509;
    struct ot_impls impls;
    struct OTContext *ctx;
    unsigned char *iobuf;
    size_t iobuf_len;
    unsigned char *out;              /* records gathered to go in one send */
    size_t out_len, out_sent;
    char host[OT_HOST_MAX + 1];
    unsigned char ip[16];
    int ip_len;                      /* 4 or 16 for an address, else 0 */
    LONG fd;
    struct Library *socketbase;
    struct Hook *hook;
    int have_io;
    char *alpn;                      /* copy of the list; names point into it */
    const char *alpn_names[OT_ALPN_MAX];
    int alpn_count;
    char alpn_selected[64];
    LONG verify;
    int pinned;
    unsigned char pin[32];
    int offer_session;
    struct ot12_session offered;
    struct ot12_session session12;   /* this connection's TLS 1.2 session */
    struct ot13_ticket *offer13;     /* a TLS 1.3 ticket to offer, or NULL */
    LONG min_version, max_version;   /* the context's, or OT_SetVersion's */
    struct ot13 *t13;                /* the TLS 1.3 client (ot_tls13.c), once started */
    int resumed;
    int state;
    int clean_close;                 /* close_notify received */
    LONG error, detail;
    char text[OT_TEXT_MAX];
    char peer_name[96];
    int peer_name_done;
};

/* error text helpers (ot_core.c) */
void ot_set_error(struct OTConnection *c, LONG code, LONG detail, const char *a,
                  const char *b, const char *d);
size_t ot_strlcpy(char *dst, const char *src, size_t size);

#endif
