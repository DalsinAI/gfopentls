/* GFOpenTLS: the TLS client, written from RFC 8446 (TLS 1.3) and RFC 5246
 * (TLS 1.2, with RFC 8422's ECDHE, 5288's AES-GCM and 7905's
 * ChaCha20-Poly1305).
 *
 * One ClientHello offers what the caller's range allows, TLS 1.3, TLS 1.2
 * or both, and this file does the rest of the connection in either.
 *
 * What is supported: X25519 (the key share sent at once) and P-256 (after
 * a HelloRetryRequest), the three cipher suites, certificates with ECDSA
 * (P-256, P-384, P-521), RSA-PSS (rsa_pss_rsae_*) and Ed25519 keys, ALPN,
 * resumption with tickets (psk_dhe_ke), KeyUpdate in both directions and
 * the middlebox compatibility mode (RFC 8446 appendix D.4). No 0-RTT, no
 * client certificates (a CertificateRequest gets an empty Certificate).
 *
 * Buffers: records come into the connection's buffer and, until the
 * handshake keys are on, leave from the small gathering buffer. After
 * that, when the buffer is large (not OTCF_SMALL_BUFFERS), its second half
 * holds the records being written.
 *
 * MIT licensed and free. Copyright (c) 2026 The AmiCradle Team. */
#include "ot_tls13.h"
#include <clib/gfopentls_protos.h>

#define HS_CLIENT_HELLO       1
#define HS_SERVER_HELLO       2
#define HS_NEW_SESSION_TICKET 4
#define HS_ENCRYPTED_EXT      8
#define HS_CERTIFICATE        11
#define HS_HELLO_REQUEST      0
#define HS_SERVER_KEY_EXCH    12
#define HS_CERT_REQUEST       13
#define HS_SERVER_HELLO_DONE  14
#define HS_CERT_VERIFY        15
#define HS_CLIENT_KEY_EXCH    16
#define HS_FINISHED           20
#define HS_KEY_UPDATE         24
#define HS_MESSAGE_HASH       254

#define EXT_SERVER_NAME       0
#define EXT_GROUPS            10
#define EXT_POINT_FORMATS     11
#define EXT_SIGALGS           13
#define EXT_ALPN              16
#define EXT_EMS               23
#define EXT_SESSION_TICKET    35
#define EXT_PSK               41
#define EXT_VERSIONS          43
#define EXT_COOKIE            44
#define EXT_PSK_MODES         45
#define EXT_KEY_SHARE         51
#define EXT_RENEGOTIATION     0xFF01

#define GROUP_P256            23
#define GROUP_P384            24
#define GROUP_P521            25
#define GROUP_X25519          29

#define ALERT_CLOSE_NOTIFY        0
#define ALERT_UNEXPECTED_MESSAGE  10
#define ALERT_BAD_RECORD_MAC      20
#define ALERT_RECORD_OVERFLOW     22
#define ALERT_HANDSHAKE_FAILURE   40
#define ALERT_BAD_CERTIFICATE     42
#define ALERT_UNSUPPORTED_CERT    43
#define ALERT_CERT_EXPIRED        45
#define ALERT_ILLEGAL_PARAMETER   47
#define ALERT_UNKNOWN_CA          48
#define ALERT_DECODE_ERROR        50
#define ALERT_DECRYPT_ERROR       51
#define ALERT_PROTOCOL_VERSION    70
#define ALERT_INTERNAL_ERROR      80
#define ALERT_USER_CANCELED       90
#define ALERT_MISSING_EXTENSION   109
#define ALERT_UNSUPPORTED_EXT     110
#define ALERT_NO_APP_PROTOCOL     120

/* SHA-256 of "HelloRetryRequest": a ServerHello with this random is one */
static const unsigned char hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

/* the signature schemes offered, most wanted first */
static const uint16_t sigalgs[] = {
    0x0403, 0x0503, 0x0603,          /* ECDSA P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 */
    0x0807,                          /* Ed25519 (when the glue has it) */
    0x0804, 0x0805, 0x0806,          /* RSA-PSS with an rsaEncryption key */
    0x0401, 0x0501, 0x0601,          /* RSA PKCS #1 v1.5: certificates and TLS 1.2 only */
    0x0203, 0x0201                   /* SHA-1: old certificates and TLS 1.2 only */
};

static const uint16_t suites13[] = {
    OT13_CHACHA20_POLY1305_SHA256, OT13_AES_128_GCM_SHA256, OT13_AES_256_GCM_SHA384
};

/* the TLS 1.2 suites, in the order offered (DESIGN.md section 15). The
 * shape is TLS 1.3's: hash is the PRF's and the transcript's. */
static const struct ot13_suite suites12[] = {
    { 0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", 1, 32, &ot_sha256_vtable, 32, NULL, 0, 0, 1 },
    { 0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", 1, 32, &ot_sha256_vtable, 32, NULL, 0, 0, 0 },
    { 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", 0, 16, &ot_sha256_vtable, 32, NULL, 0, 0, 1 },
    { 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", 0, 16, &ot_sha256_vtable, 32, NULL, 0, 0, 0 },
    { 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", 0, 32, &ot_sha384_vtable, 48, NULL, 0, 0, 1 },
    { 0xC030, "ECDHE-RSA-AES256-GCM-SHA384", 0, 32, &ot_sha384_vtable, 48, NULL, 0, 0, 0 },
    { 0xC023, "ECDHE-ECDSA-AES128-SHA256", 0, 16, &ot_sha256_vtable, 32, &ot_sha256_vtable, 32, 0, 1 },
    { 0xC027, "ECDHE-RSA-AES128-SHA256", 0, 16, &ot_sha256_vtable, 32, &ot_sha256_vtable, 32, 0, 0 },
    { 0xC024, "ECDHE-ECDSA-AES256-SHA384", 0, 32, &ot_sha384_vtable, 48, &ot_sha384_vtable, 48, 0, 1 },
    { 0xC028, "ECDHE-RSA-AES256-SHA384", 0, 32, &ot_sha384_vtable, 48, &ot_sha384_vtable, 48, 0, 0 },
    { 0xC009, "ECDHE-ECDSA-AES128-SHA", 0, 16, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 0, 1 },
    { 0xC013, "ECDHE-RSA-AES128-SHA", 0, 16, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 0, 0 },
    { 0xC00A, "ECDHE-ECDSA-AES256-SHA", 0, 32, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 0, 1 },
    { 0xC014, "ECDHE-RSA-AES256-SHA", 0, 32, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 0, 0 },
    { 0x009C, "AES128-GCM-SHA256", 0, 16, &ot_sha256_vtable, 32, NULL, 0, 1, 0 },
    { 0x009D, "AES256-GCM-SHA384", 0, 32, &ot_sha384_vtable, 48, NULL, 0, 1, 0 },
    { 0x003C, "AES128-SHA256", 0, 16, &ot_sha256_vtable, 32, &ot_sha256_vtable, 32, 1, 0 },
    { 0x003D, "AES256-SHA256", 0, 32, &ot_sha256_vtable, 32, &ot_sha256_vtable, 32, 1, 0 },
    { 0x002F, "AES128-SHA", 0, 16, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 1, 0 },
    { 0x0035, "AES256-SHA", 0, 32, &ot_sha256_vtable, 32, &ot_sha1_vtable, 20, 1, 0 }
};
#define SUITES12_COUNT (sizeof suites12 / sizeof suites12[0])

static const struct ot13_suite *suite12(unsigned id)
{
    size_t i;
    for (i = 0; i < SUITES12_COUNT; ++i)
        if (suites12[i].id == id) return &suites12[i];
    return NULL;
}

struct OTConnection;
static LONG t12_server_hello(struct OTConnection *c, const unsigned char *msg, size_t mlen);
struct rd;
static LONG t12_message(struct OTConnection *c, const unsigned char *msg, size_t len, struct rd *r, int last);

/* ---- small helpers ---- */

static unsigned get16(const unsigned char *p) { return ((unsigned)p[0] << 8) | p[1]; }
static size_t get24(const unsigned char *p) { return ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2]; }
static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void put16(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void put24(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 16); put16(p + 1, v); }
static void put32(unsigned char *p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v & 0xFFFF); }

static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char d = 0;
    size_t i;
    for (i = 0; i < n; ++i) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static size_t hlen_of(const ot_hash_class *h)
{
    return (h->desc >> OT_HASHDESC_OUT_OFF) & OT_HASHDESC_OUT_MASK;
}

/* the services card may have this connection's key work: OTCF_NO_OFFLOAD keeps it here */
static int svc_on(const struct OTConnection *c)
{
    return c && !(c->ctx->flags & OTCF_NO_OFFLOAD);
}

/**
 * A server signature checked on the services card, against the server certificate's key.
 *
 * @param alg                           OTK_RSA_PKCS1, OTK_RSA_PSS, OTK_ECDSA or OTK_ED25519
 * @param hc                            the hash of data, NULL for Ed25519
 * @param data                          the hash, or the whole message for Ed25519
 * @return                              1 good, 0 bad, -1 not done (check it here)
 */
static int svc_check(struct OTConnection *c, ULONG alg, const ot_hash_class *hc,
                     const unsigned char *data, size_t dlen, const unsigned char *sig, size_t siglen)
{
    static const ULONG digests[] = { 0, OTK_SHA1, OTK_SHA256, OTK_SHA384, OTK_SHA512 };
    const unsigned char *spki;
    size_t slen, hl = hc ? hlen_of(hc) : 0;
    ULONG digest = digests[hl == 20 ? 1 : hl == 32 ? 2 : hl == 48 ? 3 : hl == 64 ? 4 : 0];
    if (!svc_on(c) || (hc && !digest) || !ot_x509_spki(&c->x509, &spki, &slen)) return -1;
    return ot_svc_verify(alg, digest, 0, spki, slen, data, dlen, sig, siglen);
}

/* a reader over a message: every get checks the length, and a short read
 * sets bad, so a parser checks once at its end */
struct rd { const unsigned char *p; size_t n; int bad; };

static unsigned rd8(struct rd *r)
{
    if (r->n < 1) { r->bad = 1; return 0; }
    --r->n;
    return *r->p++;
}
static unsigned rd16(struct rd *r)
{
    unsigned v;
    if (r->n < 2) { r->bad = 1; r->n = 0; return 0; }
    v = get16(r->p); r->p += 2; r->n -= 2;
    return v;
}
static size_t rd24(struct rd *r)
{
    size_t v;
    if (r->n < 3) { r->bad = 1; r->n = 0; return 0; }
    v = get24(r->p); r->p += 3; r->n -= 3;
    return v;
}
/* the next len bytes as a sub-reader */
static struct rd rdsub(struct rd *r, size_t len)
{
    struct rd s;
    if (r->n < len) { r->bad = 1; len = r->n; }
    s.p = r->p; s.n = len; s.bad = r->bad;
    r->p += len; r->n -= len;
    return s;
}

/* ---- the transcript ---- */

static void th_update(struct ot13 *t, const void *data, size_t len)
{
    if (!t->hash || t->hash == &ot_sha256_vtable) ot_sha256_update(&t->th256, data, len);
    if (!t->hash || t->hash == &ot_sha384_vtable) ot_sha384_update(&t->th384, data, len);
}

/* the hash of the messages so far, in h (the suite's, or a PSK's) */
static void th_out(struct ot13 *t, const ot_hash_class *h, unsigned char *out)
{
    if (h == &ot_sha384_vtable) ot_sha384_out(&t->th384, out);
    else ot_sha256_out(&t->th256, out);
}

/* ---- errors and alerts ---- */

static LONG tx_flush(struct OTConnection *c);

static void queue_alert(struct OTConnection *c, int level, int desc);

/* ends the handshake or connection: sends the alert (when it can go at
 * once) and fails with code and the text */
static LONG abort13(struct OTConnection *c, int alert, LONG code, const char *what)
{
    struct ot13 *t = c->t13;
    if (alert >= 0 && t && !t->close_sent) {
        queue_alert(c, 2, alert);
        tx_flush(c);
    }
    if (code == OTERR_PROTOCOL)
        return ot_fail(c, code, alert, t && t->v12 ? "The server broke the TLS 1.2 protocol: "
                                                   : "The server broke the TLS 1.3 protocol: ", what, ".");
    return ot_fail(c, code, alert, what, NULL, NULL);
}

/* ---- records out ---- */

static LONG tx_flush(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    while (t->tx_sent < t->tx_len) {
        LONG n = ot_io(c, 1, t->tx + t->tx_sent, t->tx_len - t->tx_sent);
        if (n == OTERR_WOULDBLOCK)
            return ot_fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
        if (n <= 0) return ot_fail(c, OTERR_IO, 0, "Sending to the server failed.", NULL, NULL);
        t->tx_sent += (size_t)n;
    }
    t->tx_len = t->tx_sent = 0;
    return OTERR_OK;
}

/* room for a record of len bytes of content, sealed; NULL when there is none */
static unsigned char *tx_room(struct ot13 *t, size_t len)
{
    if (t->tx_sent == t->tx_len) t->tx_len = t->tx_sent = 0;
    if (t->tx_len + 5 + len + OT12_OVERHEAD > t->tx_cap) return NULL;  /* TLS 1.2's IV, MAC, padding, or 1.3's type and tag */
    return t->tx + t->tx_len;
}

/* puts a record of len bytes (already at rec + 5) in the queue: sealed
 * once the keys are on, else in the clear */
static void tx_record(struct ot13 *t, unsigned char *rec, int type, size_t len)
{
    if (t->wr_on) {
        t->tx_len += t->v12 ? ot12_seal(&t->wr, rec, type, len) : ot13_seal(&t->wr, rec, type, len);
    } else {
        rec[0] = (unsigned char)type;
        rec[1] = 3;
        rec[2] = 3;
        put16(rec + 3, len);
        t->tx_len += 5 + len;
    }
}

static void queue_alert(struct OTConnection *c, int level, int desc)
{
    struct ot13 *t = c->t13;
    unsigned char *rec = tx_room(t, 2);
    if (!rec) {            /* full: drop what is waiting, the alert matters more */
        t->tx_len = t->tx_sent = 0;
        rec = tx_room(t, 2);
        if (!rec) return;
    }
    rec[5] = (unsigned char)level;
    rec[6] = (unsigned char)desc;
    tx_record(t, rec, OT_SSL_ALERT, 2);
    if (desc == ALERT_CLOSE_NOTIFY || level == 2) t->close_sent = 1;
}

/* the middlebox compatibility mode's ChangeCipherSpec, once */
static void queue_ccs(struct ot13 *t)
{
    unsigned char *rec;
    if (t->ccs_sent || !(rec = tx_room(t, 1))) return;
    rec[0] = OT_SSL_CHANGE_CIPHER_SPEC;
    rec[1] = 3;
    rec[2] = 3;
    put16(rec + 3, 1);
    rec[5] = 1;
    t->tx_len += 6;
    t->ccs_sent = 1;
}

/* ---- key shares ---- */

static LONG make_x25519(struct OTConnection *c, unsigned char *pub)
{
    struct ot13 *t = c->t13;
    if (svc_on(c) && ot_svc_keygen(OTK_X25519, t->x25519, 32, pub, 32) == 32) return OTERR_OK;
    if (ot_random(t->x25519, 32) != OTERR_OK) return OTERR_RANDOM;
    t->x25519[0] &= 0xF8;
    t->x25519[31] &= 0x7F;
    t->x25519[31] |= 0x40;
    if (c->impls.ec->mulgen(pub, t->x25519, 32, OT_EC_curve25519) != 32) return OTERR_INTERNAL;
    return OTERR_OK;
}

static LONG make_p256(struct OTConnection *c, unsigned char *pub)
{
    struct ot13 *t = c->t13;
    const unsigned char *order;
    size_t olen, i;
    if (svc_on(c) && ot_svc_keygen(OTK_P256, t->p256, 32, pub, 65) == 65) return OTERR_OK;
    do {        /* 0 < k < n; the first draw is almost always right */
        int below = 0, zero = 1;
        if (ot_random(t->p256, 32) != OTERR_OK) return OTERR_RANDOM;
        order = c->impls.ec->order(OT_EC_secp256r1, &olen);
        for (i = 0; i < 32; ++i) {
            if (t->p256[i]) zero = 0;
            if (t->p256[i] != order[i]) { below = t->p256[i] < order[i]; break; }
        }
        if (below && !zero) break;
    } while (1);
    if (c->impls.ec->mulgen(pub, t->p256, 32, OT_EC_secp256r1) != 65) return OTERR_INTERNAL;
    return OTERR_OK;
}

/* a key share on curve (P-384 or P-521, TLS 1.2): the private half in
 * t->ecpriv, the point in pub; its length, or 0 */
static size_t make_ec(struct OTConnection *c, int curve, unsigned char *pub)
{
    struct ot13 *t = c->t13;
    const unsigned char *order;
    size_t olen, i;
    if (curve == OT_EC_secp384r1 && svc_on(c) && ot_svc_keygen(OTK_P384, t->ecpriv, 48, pub, 97) == 97) {
        t->ecpriv_len = 48;
        return 97;
    }
    order = c->impls.ec->order(curve, &olen);
    if (olen > sizeof t->ecpriv) return 0;
    do {
        int below = 0, zero = 1;
        unsigned char top = order[0];
        if (ot_random(t->ecpriv, olen) != OTERR_OK) return 0;
        while (top & (top + 1)) top |= (unsigned char)(top >> 1);   /* the order's top bits */
        t->ecpriv[0] &= top;
        for (i = 0; i < olen; ++i) {
            if (t->ecpriv[i]) zero = 0;
            if (t->ecpriv[i] != order[i]) { below = t->ecpriv[i] < order[i]; break; }
        }
        if (below && !zero) break;
    } while (1);
    t->ecpriv_len = olen;
    return c->impls.ec->mulgen(pub, t->ecpriv, olen, curve);
}

/* the shared secret with the server's share; its length, 0 if refused */
static size_t ecdhe(struct OTConnection *c, unsigned group, const unsigned char *share, size_t len,
                    unsigned char *out)
{
    struct ot13 *t = c->t13;
    unsigned char g[65], acc = 0;
    size_t xlen, xoff, i;
    if (group == GROUP_X25519) {
        if (len != 32) return 0;
        memcpy(g, share, 32);
        if ((!svc_on(c) || ot_svc_derive(OTK_X25519, t->x25519, 32, share, 32, g, 32) != 32)
            && !c->impls.ec->mul(g, 32, t->x25519, 32, OT_EC_curve25519)) return 0;
        for (i = 0; i < 32; ++i) acc |= g[i];
        if (!acc) return 0;             /* a small-order point */
        memcpy(out, g, 32);
        return 32;
    }
    if (group == GROUP_P384 || group == GROUP_P521) {
        unsigned char gg[133];
        int curve = group == GROUP_P384 ? OT_EC_secp384r1 : OT_EC_secp521r1;
        size_t plen = group == GROUP_P384 ? 97 : 133;
        if (len != plen || share[0] != 4 || !t->ecpriv_len) return 0;
        if (curve == OT_EC_secp384r1 && svc_on(c)
            && ot_svc_derive(OTK_P384, t->ecpriv, t->ecpriv_len, share, plen, out, 48) == 48)
            return 48;
        memcpy(gg, share, plen);
        if (!c->impls.ec->mul(gg, plen, t->ecpriv, t->ecpriv_len, curve)) return 0;
        xoff = c->impls.ec->xoff(curve, &xlen);
        memcpy(out, gg + xoff, xlen);
        memset(gg, 0, sizeof gg);
        return xlen;
    }
    if (len != 65 || share[0] != 4) return 0;
    if (svc_on(c) && ot_svc_derive(OTK_P256, t->p256, 32, share, 65, out, 32) == 32) return 32;
    memcpy(g, share, 65);
    if (!c->impls.ec->mul(g, 65, t->p256, 32, OT_EC_secp256r1)) return 0;
    xoff = c->impls.ec->xoff(OT_EC_secp256r1, &xlen);
    memcpy(out, g + xoff, xlen);
    return xlen;
}

/* ---- the ClientHello ---- */

static int offer_ticket(struct OTConnection *c, uint32_t *age)
{
    const struct ot13_ticket *k = c->offer13;
    uint32_t days, secs;
    if (!k || !ot13_suite(k->suite)) return 0;
    *age = 0;
    if (ot_now(&days, &secs) && k->days) {
        uint32_t now = days * 86400UL + secs, then = k->days * 86400UL + k->seconds;
        uint32_t s = now >= then ? now - then : 0;
        if (s > k->lifetime || s > 7 * 86400UL) return 0;
        *age = s * 1000UL;
    }
    return 1;
}

/* writes the ClientHello as a record at t->tx; the record's length, or a
 * negative error */
static LONG build_client_hello(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTContext *x = c->ctx;
    unsigned char *rec, *m, *p, *ext, *binders = NULL;
    const struct ot13_suite *ps = NULL;
    uint32_t age = 0;
    size_t i, hl;
    LONG rc;
    int k, v13 = ot13_wanted(c);
    /* what it can take at most, without the ticket: it must fit (a long
     * cookie from the server may not), and the ticket is left out when
     * it would not */
    size_t most = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 2 * (3 + SUITES12_COUNT) + 2 + 2
                + 9 + strlen(c->host) + 5 + 8 + 14 + 6 + 6 + 2 * 12 + 6 + 5 + 10 + 65 + 6
                + (t->cookie ? 6 + t->cookie_len : 0) + 22;

    (void)x;
    for (k = 0; k < c->alpn_count; ++k) most += 1 + strlen(c->alpn_names[k]);
    if (most > t->tx_cap) return OTERR_INTERNAL;
    t->tx_len = t->tx_sent = 0;
    rec = t->tx;
    m = rec + 5;
    p = m + 4;
    *p++ = 3; *p++ = 3;                         /* legacy_version: TLS 1.2 */
    memcpy(p, t->random, 32); p += 32;
    *p++ = (unsigned char)t->sid_len;
    memcpy(p, t->sid, t->sid_len); p += t->sid_len;
    /* cipher suites: TLS 1.3's, then TLS 1.2's */
    {
        size_t n = (v13 ? sizeof suites13 / sizeof suites13[0] : 0) + (t->offer12 ? SUITES12_COUNT : 0);
        put16(p, 2 * n); p += 2;
        if (v13)
            for (i = 0; i < sizeof suites13 / sizeof suites13[0]; ++i) { put16(p, suites13[i]); p += 2; }
        if (t->offer12)
            for (i = 0; i < SUITES12_COUNT; ++i) { put16(p, suites12[i].id); p += 2; }
    }
    *p++ = 1; *p++ = 0;                         /* compression: none */
    ext = p;
    p += 2;
    if (!c->ip_len) {                           /* server_name */
        size_t hl2 = strlen(c->host);
        put16(p, EXT_SERVER_NAME); put16(p + 2, hl2 + 5); put16(p + 4, hl2 + 3);
        p[6] = 0; put16(p + 7, hl2);
        memcpy(p + 9, c->host, hl2);
        p += 9 + hl2;
    }
    if (v13) {                                  /* supported_versions: 1.3, and 1.2 when allowed */
        unsigned char *l = p + 4;
        put16(p, EXT_VERSIONS);
        p += 5;
        put16(p, OT_TLS13); p += 2;
        if (t->offer12) { put16(p, OT_TLS12); p += 2; }
        *l = (unsigned char)(p - l - 1);
        put16(l - 2, (size_t)(p - l));
    }
    put16(p, EXT_GROUPS);                       /* supported_groups */
    put16(p + 2, t->offer12 ? 10 : 8);
    put16(p + 4, t->offer12 ? 8 : 6);
    put16(p + 6, GROUP_X25519); put16(p + 8, GROUP_P256); put16(p + 10, GROUP_P384);
    p += 12;
    if (t->offer12) { put16(p, GROUP_P521); p += 2; }
    if (t->offer12) {                           /* ec_point_formats: uncompressed */
        put16(p, EXT_POINT_FORMATS); put16(p + 2, 2); p[4] = 1; p[5] = 0;
        p += 6;
    }
    {                                           /* signature_algorithms */
        unsigned char *l = p + 2;
        put16(p, EXT_SIGALGS);
        p += 6;
        for (i = 0; i < sizeof sigalgs / sizeof sigalgs[0]; ++i) {
            if (sigalgs[i] == 0x0807 && (!t->sigalgs_ed25519 || !v13)) continue;
            put16(p, sigalgs[i]); p += 2;
        }
        put16(l, (size_t)(p - l - 2));
        put16(l + 2, (size_t)(p - l - 4));
    }
    if (c->alpn_count) {                        /* ALPN */
        unsigned char *l = p + 2;
        put16(p, EXT_ALPN);
        p += 6;
        for (k = 0; k < c->alpn_count; ++k) {
            size_t n = strlen(c->alpn_names[k]);
            *p++ = (unsigned char)n;
            memcpy(p, c->alpn_names[k], n);
            p += n;
        }
        put16(l, (size_t)(p - l - 2));
        put16(l + 2, (size_t)(p - l - 4));
    }
    if (t->offer12) {                           /* renegotiation_info: empty */
        put16(p, EXT_RENEGOTIATION); put16(p + 2, 1); p[4] = 0;
        p += 5;
    }
    if (v13) {                                  /* key_share: one share */
        size_t kl = t->group == GROUP_X25519 ? 32 : 65;
        put16(p, EXT_KEY_SHARE); put16(p + 2, kl + 6); put16(p + 4, kl + 4);
        put16(p + 6, t->group); put16(p + 8, kl);
        rc = t->group == GROUP_X25519 ? make_x25519(c, p + 10) : make_p256(c, p + 10);
        if (rc != OTERR_OK) return rc;
        p += 10 + kl;
    }
    if (v13) {
        put16(p, EXT_PSK_MODES); put16(p + 2, 2); p[4] = 1; p[5] = 1;   /* psk_dhe_ke */
        p += 6;
    }
    if (t->cookie) {
        put16(p, EXT_COOKIE); put16(p + 2, t->cookie_len + 2); put16(p + 4, t->cookie_len);
        memcpy(p + 6, t->cookie, t->cookie_len);
        p += 6 + t->cookie_len;
    }
    /* pre_shared_key, last: a ticket whose hash suits the HelloRetryRequest's suite */
    if (v13 && offer_ticket(c, &age) && most + 8 + c->offer13->len + 4 + 3 + OT13_HASH_MAX <= t->tx_cap) {
        ps = ot13_suite(c->offer13->suite);
        if (t->hrr && ps->hash != t->hash) ps = NULL;
    }
    if (ps) {
        const struct ot13_ticket *k = c->offer13;
        hl = ps->hash_len;
        put16(p, EXT_PSK);
        put16(p + 2, 2 + 2 + k->len + 4 + 2 + 1 + hl);
        put16(p + 4, 2 + k->len + 4);
        put16(p + 6, k->len);
        memcpy(p + 8, k->data, k->len);
        put32(p + 8 + k->len, age + k->age_add);
        p += 8 + k->len + 4;
        binders = p;
        put16(p, 1 + hl);
        p[2] = (unsigned char)hl;
        p += 3 + hl;
    }
    put16(ext, (size_t)(p - ext - 2));
    m[0] = HS_CLIENT_HELLO;
    put24(m + 1, (size_t)(p - m - 4));
    if (ps) {
        /* the binder: HMAC over the transcript up to the identities */
        unsigned char early[OT13_HASH_MAX], bkey[OT13_HASH_MAX], th[OT13_HASH_MAX];
        ot_sha256_context s256 = t->th256;
        ot_sha384_context s384 = t->th384;
        ot13_extract(ps->hash, NULL, c->offer13->psk, ps->hash_len, early);
        ot13_derive(ps->hash, early, "res binder", NULL, bkey);
        if (ps->hash == &ot_sha384_vtable) {
            ot_sha384_update(&s384, m, (size_t)(binders - m));
            ot_sha384_out(&s384, th);
        } else {
            ot_sha256_update(&s256, m, (size_t)(binders - m));
            ot_sha256_out(&s256, th);
        }
        ot13_finished(ps->hash, bkey, th, binders + 3);
        memset(early, 0, sizeof early);
        memset(bkey, 0, sizeof bkey);
        t->offer = c->offer13;
    } else {
        t->offer = NULL;
    }
    rec[0] = OT_SSL_HANDSHAKE;
    rec[1] = 3;
    rec[2] = t->hrr ? 3 : 1;                    /* the first one says TLS 1.0, as is usual */
    put16(rec + 3, (size_t)(p - m));
    th_update(t, m, (size_t)(p - m));
    t->tx_len = (size_t)(p - rec);
    return (LONG)t->tx_len;
}

/* ---- set-up ---- */

int ot13_wanted(struct OTConnection *c)
{
    return c->max_version >= OT_TLS13;
}

int ot13_active(struct OTConnection *c)
{
    return c->t13 && c->t13->st == T13_OPEN;
}

LONG ot13_start(struct OTConnection *c)
{
    struct ot13 *t = ot_alloc(sizeof *t);
    LONG rc;
    if (!t) return ot_fail(c, OTERR_NOMEM, 0, "Out of memory.", NULL, NULL);
    c->t13 = t;
    t->offer12 = c->min_version <= OT_TLS12;
    t->group = GROUP_X25519;
    t->sigalgs_ed25519 = ot_glue_has_ed25519();
    t->update_after = ot_key_update_after();
    ot_sha256_init(&t->th256);
    ot_sha384_init(&t->th384);
    t->rx = c->iobuf;
    t->tx = c->out;
    t->tx_cap = OT_OUT_MAX;
    if (ot_random(t->random, 32) != OTERR_OK)
        return ot_fail(c, OTERR_RANDOM, 0, "No random numbers for the handshake.", NULL, NULL);
    memset(&c->session12, 0, sizeof c->session12);
    if (t->offer12 && c->offer_session && c->offered.session_id_len) {
        /* a TLS 1.2 session offered: its ID, kept to see whether it is resumed */
        c->session12 = c->offered;
        t->sid_len = c->offered.session_id_len;
        memcpy(t->sid, c->offered.session_id, t->sid_len);
    }
    if (!t->sid_len && ot13_wanted(c)) {   /* compatibility mode: a session ID of our own */
        if (ot_random(t->sid, 32) != OTERR_OK)
            return ot_fail(c, OTERR_RANDOM, 0, "No random numbers for the handshake.", NULL, NULL);
        t->sid_len = 32;
    }
    rc = build_client_hello(c);
    if (rc < 0) {
        if (rc == OTERR_RANDOM) return ot_fail(c, rc, 0, "No random numbers for the handshake.", NULL, NULL);
        return ot_fail(c, rc, 0, "The ClientHello could not be made.", NULL, NULL);
    }
    t->st = T13_WAIT_SH;
    return OTERR_OK;
}

/* ---- records in ---- */

/* reads one whole record into t->rx; OTERR_OK, OTERR_WOULDBLOCK or an error */
static LONG read_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    for (;;) {
        size_t need = 5;
        LONG n;
        if (t->rx_have >= 5) {
            size_t len = get16(t->rx + 3);
            if (t->rx[1] != 3 || len > (t->rd_on ? OT13_RX_MAX - 5 : 16384) || len == 0)
                return abort13(c, len ? ALERT_RECORD_OVERFLOW : ALERT_DECODE_ERROR, OTERR_PROTOCOL,
                               "a malformed record");
            need = 5 + len;
            if (t->rx_have == need) return OTERR_OK;
        }
        n = ot_io(c, 0, t->rx + t->rx_have, need - t->rx_have);
        if (n == OTERR_WOULDBLOCK)
            return ot_fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
        if (n == 0)
            return ot_fail(c, OTERR_CLOSED, 0, t->st < T13_OPEN
                ? "The server closed the connection during the handshake."
                : "The server closed the connection without close_notify.", NULL, NULL);
        if (n < 0) return ot_fail(c, OTERR_IO, 0, "Receiving from the server failed.", NULL, NULL);
        t->rx_have += (size_t)n;
    }
}

/* the record in t->rx, opened: t->pt, t->pt_len, t->pt_type */
static LONG open_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    size_t len = get16(t->rx + 3);
    int type = t->rx[0];
    t->rx_have = 0;           /* the next read starts a new record */
    if (t->v12) {
        if (type == OT_SSL_CHANGE_CIPHER_SPEC) {
            if (len != 1 || t->rx[5] != 1 || t->st != T12_WAIT_CCS || t->hs_len)
                return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected ChangeCipherSpec");
            t->rd_on = 1;                      /* the keys were made with the master secret */
            t->st = T12_WAIT_FIN;
            t->pt_len = 0;
            t->pt_type = type;
            return OTERR_OK;
        }
        if (type != OT_SSL_HANDSHAKE && type != OT_SSL_ALERT && type != OT_SSL_APPLICATION_DATA)
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected record");
        if (t->rd_on) {
            int err = ot12_open(&t->rd, t->rx, 5 + len, &len);
            if (err == OT_ERR_BAD_MAC)
                return abort13(c, ALERT_BAD_RECORD_MAC, OTERR_PROTOCOL, "a record does not decrypt");
            if (err)
                return abort13(c, err == OT_ERR_TOO_LARGE ? ALERT_RECORD_OVERFLOW : ALERT_DECODE_ERROR,
                               OTERR_PROTOCOL, "a malformed record");
        }
        t->pt = t->rx + 5;
        t->pt_len = len;
        t->pt_type = type;
        if (type == OT_SSL_APPLICATION_DATA && t->st != T13_OPEN)
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "application data before Finished");
        if (type != OT_SSL_HANDSHAKE && t->hs_len)
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a handshake message cut short");
        return OTERR_OK;
    }
    if (type == OT_SSL_APPLICATION_DATA && t->rd_on) {
        int err = ot13_open(&t->rd, t->rx, 5 + len, &type, &len);
        if (err == OT_ERR_BAD_MAC)
            return abort13(c, ALERT_BAD_RECORD_MAC, OTERR_PROTOCOL, "a record does not decrypt");
        if (err)
            return abort13(c, err == OT_ERR_TOO_LARGE ? ALERT_RECORD_OVERFLOW : ALERT_UNEXPECTED_MESSAGE,
                           OTERR_PROTOCOL, "a malformed record");
        if (type == OT_SSL_CHANGE_CIPHER_SPEC)
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an encrypted ChangeCipherSpec");
    } else if (type == OT_SSL_CHANGE_CIPHER_SPEC) {
        /* the compatibility mode's: one byte 1, between the ServerHello and Finished */
        if (len != 1 || t->rx[5] != 1 || t->st < T13_WAIT_SH || t->st >= T13_OPEN
            || (t->st == T13_WAIT_SH && !t->hrr))
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected ChangeCipherSpec");
        t->pt_len = 0;
        t->pt_type = type;
        return OTERR_OK;
    } else if (t->rd_on && type != OT_SSL_ALERT) {
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a record in the clear");
    } else if (type != OT_SSL_HANDSHAKE && type != OT_SSL_ALERT) {
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected record");
    }
    t->pt = t->rx + 5;
    t->pt_len = len;
    t->pt_type = type;
    if (type == OT_SSL_APPLICATION_DATA && t->st != T13_OPEN)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "application data before Finished");
    if (type != OT_SSL_HANDSHAKE && t->hs_len)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a handshake message cut short");
    return OTERR_OK;
}

static LONG handle_alert(struct OTConnection *c, const unsigned char *p, size_t len)
{
    if (len != 2) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed alert");
    if (p[1] == ALERT_CLOSE_NOTIFY) {
        c->clean_close = 1;
        c->state = OTS_CLOSED;
        return OTERR_CLOSED;
    }
    if (p[1] == ALERT_USER_CANCELED) return OTERR_OK;    /* close_notify follows */
    return ot_engine_error(c, OT_ERR_RECV_FATAL_ALERT + p[1]);
}

/* ---- certificate checks and signatures ---- */

static void hash_once(const ot_hash_class *h, const void *d, size_t n, unsigned char *out)
{
    ot_hash_compat_context hc;
    h->init(&hc.vtable);
    h->update(&hc.vtable, d, n);
    h->out(&hc.vtable, out);
}
static void pss_sha256(const void *d, size_t n, uint8_t *o) { hash_once(&ot_sha256_vtable, d, n, o); }
static void pss_sha384(const void *d, size_t n, uint8_t *o) { hash_once(&ot_sha384_vtable, d, n, o); }
static void pss_sha512(const void *d, size_t n, uint8_t *o) { hash_once(&ot_sha512_vtable, d, n, o); }

int ot13_rsa_pss(const struct ot_impls *m, const ot_rsa_public_key *pk, const ot_hash_class *h,
                 const unsigned char *hash, const unsigned char *sig, size_t siglen)
{
    return ot_rsa_pss(m, pk, h, hash, hlen_of(h), sig, siglen);
}

int ot_rsa_pss(const struct ot_impls *m, const ot_rsa_public_key *pk, const ot_hash_class *h,
               const unsigned char *hash, size_t salt, const unsigned char *sig, size_t siglen)
{
    unsigned char *em;
    const unsigned char *n = pk->n;
    size_t nlen = pk->nlen, bits, hl = hlen_of(h);
    int ok;
    oc_hash_fn fn = h == &ot_sha384_vtable ? pss_sha384 : h == &ot_sha512_vtable ? pss_sha512 : pss_sha256;
    if (h != &ot_sha256_vtable && h != &ot_sha384_vtable && h != &ot_sha512_vtable) return 0;
    while (nlen && !n[0]) { ++n; --nlen; }
    if (!nlen || siglen != nlen || nlen > OC_RSA_MAX_BYTES) return 0;
    for (bits = 8 * nlen; !(n[0] & (0x80 >> (8 * nlen - bits))); --bits) {}
    em = ot_alloc(nlen);
    if (!em) return 0;
    memcpy(em, sig, nlen);
    ok = m->rsa_pub(em, nlen, pk) && oc_emsa_pss_verify(em, nlen, bits, hash, hl, (long)salt, fn);
    ot_free(em);
    return ok;
}

int ot13_verify_cv(struct OTConnection *c, const struct ot_impls *m, unsigned scheme, const ot_x509_pkey *pk,
                   const unsigned char *ed25519, const unsigned char *thash, size_t thlen,
                   const unsigned char *sig, size_t siglen)
{
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    unsigned char content[64 + sizeof ctx + OT13_HASH_MAX], h[64];
    const ot_hash_class *hc;
    size_t cl = 64 + sizeof ctx + thlen;       /* sizeof includes the 0 separator */
    int sv;
    memset(content, 0x20, 64);
    memcpy(content + 64, ctx, sizeof ctx);
    memcpy(content + 64 + sizeof ctx, thash, thlen);
    if (scheme == 0x0807) {
        if (!ed25519 || siglen != 64) return OT_ERR_INVALID_ALGORITHM;
        if ((sv = svc_check(c, OTK_ED25519, NULL, content, cl, sig, siglen)) >= 0)
            return sv ? 0 : OT_ERR_BAD_SIGNATURE;
        return ot_glue_ed25519(sig, ed25519, content, cl) == 1 ? 0 : OT_ERR_BAD_SIGNATURE;
    }
    if (!pk) return OT_ERR_INVALID_ALGORITHM;
    switch (scheme) {
    case 0x0403: case 0x0804: hc = &ot_sha256_vtable; break;
    case 0x0503: case 0x0805: hc = &ot_sha384_vtable; break;
    case 0x0603: case 0x0806: hc = &ot_sha512_vtable; break;
    default: return OT_ERR_INVALID_ALGORITHM;
    }
    hash_once(hc, content, cl, h);
    if ((scheme & 0xFF) == 3) {
        int curve = scheme == 0x0403 ? OT_EC_secp256r1 : scheme == 0x0503 ? OT_EC_secp384r1 : OT_EC_secp521r1;
        if (pk->key_type != OT_KEYTYPE_EC || pk->key.ec.curve != curve) return OT_ERR_INVALID_ALGORITHM;
        if ((sv = svc_check(c, OTK_ECDSA, hc, h, hlen_of(hc), sig, siglen)) >= 0)
            return sv ? 0 : OT_ERR_BAD_SIGNATURE;
        return m->ecdsa_vrfy(m->ec, h, hlen_of(hc), &pk->key.ec, sig, siglen) ? 0 : OT_ERR_BAD_SIGNATURE;
    }
    if (pk->key_type != OT_KEYTYPE_RSA) return OT_ERR_INVALID_ALGORITHM;
    if ((sv = svc_check(c, OTK_RSA_PSS, hc, h, hlen_of(hc), sig, siglen)) >= 0)
        return sv ? 0 : OT_ERR_BAD_SIGNATURE;
    return ot13_rsa_pss(m, &pk->key.rsa, hc, h, sig, siglen) ? 0 : OT_ERR_BAD_SIGNATURE;
}

static int cert_alert(int err)
{
    switch (err) {
    case OT_ERR_X509_NOT_TRUSTED: return ALERT_UNKNOWN_CA;
    case OT_ERR_X509_EXPIRED: return ALERT_CERT_EXPIRED;
    case OT_ERR_X509_UNSUPPORTED: return ALERT_UNSUPPORTED_CERT;
    default: return ALERT_BAD_CERTIFICATE;
    }
}

static LONG cert_failed(struct OTConnection *c, int err)
{
    queue_alert(c, 2, cert_alert(err));
    tx_flush(c);
    return ot_engine_error(c, err);
}

/* ---- the handshake messages ---- */

static LONG derive_handshake_keys(struct OTConnection *c, const unsigned char *shared, size_t slen)
{
    struct ot13 *t = c->t13;
    const ot_hash_class *h = t->hash;
    unsigned char early[OT13_HASH_MAX], derived[OT13_HASH_MAX], th[OT13_HASH_MAX];
    ot13_extract(h, NULL, t->psk_used ? t->offer->psk : NULL, t->suite->hash_len, early);
    ot13_derive(h, early, "derived", NULL, derived);
    ot13_extract(h, derived, shared, slen, t->hs_secret);
    th_out(t, h, th);
    ot13_derive(h, t->hs_secret, "c hs traffic", th, t->c_hs);
    ot13_derive(h, t->hs_secret, "s hs traffic", th, t->s_hs);
    memset(early, 0, sizeof early);
    memset(derived, 0, sizeof derived);
    if (ot13_keys_set(&t->rd, t->suite, &c->impls, t->s_hs) || ot13_keys_set(&t->wr, t->suite, &c->impls, t->c_hs))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    t->rd_on = t->wr_on = 1;
    return OTERR_OK;
}

/* when the connection's buffer is large (not OTCF_SMALL_BUFFERS), whole
 * records go out from the part the records coming in do not use */
static void big_tx(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    if (t->tx_len == 0 && c->iobuf_len >= OT13_RX_MAX + 5 + OT13_RECORD_MAX + OT12_OVERHEAD + OT13_TX_SPARE) {
        t->tx = c->iobuf + OT13_RX_MAX;
        t->tx_cap = c->iobuf_len - OT13_RX_MAX;
    }
}

static int offered_suite(unsigned id)
{
    size_t i;
    for (i = 0; i < sizeof suites13 / sizeof suites13[0]; ++i)
        if (suites13[i] == id) return 1;
    return 0;
}

/* ServerHello or HelloRetryRequest. msg is the whole message (header
 * included); rest and rest_len what follows it in the record. */
static LONG server_hello(struct OTConnection *c, const unsigned char *msg, size_t mlen,
                         const unsigned char *rest, size_t rest_len)
{
    struct ot13 *t = c->t13;
    struct rd r, ex;
    const unsigned char *random, *share = NULL;
    unsigned version = 0, suite, group = 0, sel_psk = 0xFFFF;
    size_t sid_len, share_len = 0, i;
    int hrr, have_versions = 0, have_share = 0, have_psk = 0;
    const unsigned char *cookie = NULL;
    size_t cookie_len = 0;
    unsigned char shared[66];
    size_t slen;
    LONG rc;

    (void)rest;
    r.p = msg + 4; r.n = mlen - 4; r.bad = 0;
    rd16(&r);                                  /* legacy_version */
    random = r.p;
    rdsub(&r, 32);
    sid_len = rd8(&r);
    {
        struct rd sid = rdsub(&r, sid_len);
        if (!r.bad && (sid_len != t->sid_len || memcmp(sid.p, t->sid, sid_len))) {
            /* a TLS 1.2 server answers with its own session ID */
            sid_len = (size_t)-1;
        }
    }
    suite = rd16(&r);
    if (rd8(&r) != 0) r.bad = 1;               /* compression */
    hrr = !r.bad && !memcmp(random, hrr_random, 32);
    if (!r.bad && r.n) {
        ex = rdsub(&r, rd16(&r));
        while (ex.n && !ex.bad) {
            unsigned type = rd16(&ex);
            struct rd d = rdsub(&ex, rd16(&ex));
            switch (type) {
            case EXT_VERSIONS:
                version = rd16(&d);
                have_versions = 1;
                break;
            case EXT_KEY_SHARE:
                group = rd16(&d);
                if (!hrr) {
                    share_len = rd16(&d);
                    share = d.p;
                    rdsub(&d, share_len);
                }
                have_share = 1;
                break;
            case EXT_PSK:
                if (hrr) { r.bad = 2; break; }
                sel_psk = rd16(&d);
                have_psk = 1;
                break;
            case EXT_COOKIE:
                if (!hrr) { r.bad = 2; break; }
                cookie_len = rd16(&d);
                cookie = d.p;
                rdsub(&d, cookie_len);
                if (!cookie_len) d.bad = 1;
                break;
            default:
                /* a TLS 1.2 ServerHello may carry its own; BearSSL judges those */
                if (have_versions || hrr) r.bad = 2;
                d.n = 0;
                break;
            }
            if (d.bad || d.n) ex.bad = 1;
        }
        if (ex.bad) r.bad = 1;
    }
    if (r.bad == 1) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed ServerHello");

    if (!have_versions) {
        /* TLS 1.2 or older */
        if (hrr || t->hrr)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "TLS 1.2 after a HelloRetryRequest");
        if (!t->offer12)
            return abort13(c, ALERT_PROTOCOL_VERSION, OTERR_VERSION,
                           "The server does not speak TLS 1.3, and the connection allows nothing older.");
        /* RFC 8446 section 4.1.3: a TLS 1.3 server that is made to answer
         * with 1.2 or less says so in the last 8 bytes of its random */
        if (ot13_wanted(c) && !memcmp(random + 24, "DOWNGRD", 7) && (random[31] == 0 || random[31] == 1))
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_VERSION,
                           "The connection was pushed down from TLS 1.3 (an attack, or a broken middlebox).");
        if (get16(msg + 4) != OT_TLS12)
            return abort13(c, ALERT_PROTOCOL_VERSION, OTERR_VERSION,
                           "The server wants TLS 1.1 or older, which GFOpenTLS no longer speaks.");
        if (!suite12(suite))
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                           "The server chose a cipher suite GFOpenTLS did not offer.");
        return t12_server_hello(c, msg, mlen);
    }
    if (!ot13_wanted(c))
        return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
    if (r.bad == 2) return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
    if (version != OT_TLS13)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a version it was not offered");
    if (sid_len == (size_t)-1)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a session ID that is not ours");
    if (!offered_suite(suite) || (t->hrr && suite != t->hrr_suite))
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server chose a cipher suite GFOpenTLS did not offer.");
    if (rest_len)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a message after the ServerHello");

    if (hrr) {
        unsigned char ch1[OT13_HASH_MAX + 4];
        const struct ot13_suite *s = ot13_suite(suite);
        if (t->hrr) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a second HelloRetryRequest");
        if (have_share && ((group != GROUP_X25519 && group != GROUP_P256) || group == t->group))
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                           "The server asked for a key exchange group GFOpenTLS did not offer.");
        if (!have_share && !cookie)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a HelloRetryRequest that changes nothing");
        t->hrr = 1;
        t->hrr_suite = (uint16_t)suite;
        t->suite = s;
        t->hash = s->hash;
        /* the transcript starts again from message_hash(ClientHello1) */
        ch1[0] = HS_MESSAGE_HASH;
        put24(ch1 + 1, s->hash_len);
        th_out(t, t->hash, ch1 + 4);
        if (t->hash == &ot_sha384_vtable) ot_sha384_init(&t->th384);
        else ot_sha256_init(&t->th256);
        th_update(t, ch1, 4 + s->hash_len);
        th_update(t, msg, mlen);
        if (have_share) t->group = group;
        if (cookie) {
            ot_free(t->cookie);
            t->cookie = ot_alloc(cookie_len);
            if (!t->cookie) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_NOMEM, "Out of memory.");
            memcpy(t->cookie, cookie, cookie_len);
            t->cookie_len = cookie_len;
        }
        queue_ccs(t);
        {
            size_t at = t->tx_len;
            unsigned char *save = t->tx;
            t->tx += at;                       /* the ClientHello after the CCS */
            t->tx_cap -= at;
            rc = build_client_hello(c);
            t->tx = save;
            t->tx_cap += at;
            if (rc < 0) return abort13(c, ALERT_INTERNAL_ERROR, rc, "The second ClientHello could not be made.");
            t->tx_len = at + (size_t)rc;
        }
        return OTERR_OK;
    }

    if (!have_share || group != t->group)
        return abort13(c, have_share ? ALERT_ILLEGAL_PARAMETER : ALERT_MISSING_EXTENSION, OTERR_PROTOCOL,
                       "no key share, or one for a group it was not sent");
    if (have_psk) {
        const struct ot13_suite *ps = t->offer ? ot13_suite(t->offer->suite) : NULL;
        if (!ps || sel_psk != 0 || ps->hash != ot13_suite(suite)->hash)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a ticket it was not offered");
        t->psk_used = 1;
    }
    t->suite = ot13_suite(suite);
    t->hash = t->suite->hash;
    th_update(t, msg, mlen);
    slen = ecdhe(c, group, share, share_len, shared);
    for (i = 0; i < sizeof t->x25519; ++i) t->x25519[i] = t->p256[i] = 0;
    if (!slen) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a bad key share");
    rc = derive_handshake_keys(c, shared, slen);
    memset(shared, 0, sizeof shared);
    if (rc != OTERR_OK) return rc;
    big_tx(c);
    t->st = T13_WAIT_EE;
    return OTERR_OK;
}

static int offered_alpn(struct OTConnection *c, const unsigned char *p, size_t n)
{
    int k;
    for (k = 0; k < c->alpn_count; ++k)
        if (strlen(c->alpn_names[k]) == n && !memcmp(c->alpn_names[k], p, n)) return 1;
    return 0;
}

static LONG encrypted_extensions(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    struct rd ex = rdsub(r, rd16(r));
    unsigned seen = 0;
    while (ex.n && !ex.bad) {
        unsigned type = rd16(&ex);
        struct rd d = rdsub(&ex, rd16(&ex));
        unsigned bit = type == EXT_ALPN ? 1 : type == EXT_SERVER_NAME ? 2 : type == EXT_GROUPS ? 4 : 0;
        if (!bit) return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
        if (seen & bit) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an extension twice");
        seen |= bit;
        if (type == EXT_ALPN) {
            struct rd l = rdsub(&d, rd16(&d));
            size_t n = rd8(&l);
            const unsigned char *name = l.p;
            rdsub(&l, n);
            if (l.bad || l.n || !n || !c->alpn_count) d.bad = 1;
            else if (!offered_alpn(c, name, n))
                return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an application protocol it was not offered");
            else {
                memcpy(c->alpn_selected, name, n < sizeof c->alpn_selected ? n : sizeof c->alpn_selected - 1);
                c->alpn_selected[n < sizeof c->alpn_selected ? n : sizeof c->alpn_selected - 1] = 0;
            }
        } else if (type == EXT_SERVER_NAME) {
            if (d.n || c->ip_len) d.bad = 1;
        } else {
            d.n = 0;            /* the server's preference among the groups: noted, not used */
        }
        if (d.bad || d.n) ex.bad = 1;
    }
    if (ex.bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "malformed EncryptedExtensions");
    t->st = t->psk_used ? T13_WAIT_FIN : T13_WAIT_CERT_CR;
    return OTERR_OK;
}

static LONG certificate_request(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    size_t n = rd8(r);
    struct rd ctx = rdsub(r, n);
    rdsub(r, rd16(r));                         /* extensions: we answer with no certificate */
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed CertificateRequest");
    memcpy(t->cr_ctx, ctx.p, n);
    t->cr_ctx_len = n;
    t->cert_req = 1;
    t->st = T13_WAIT_CERT;
    return OTERR_OK;
}

static LONG certificate(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    const ot_x509_class **xc = &c->x509.vtable;
    struct rd list;
    unsigned err;
    int count = 0;
    if (rd8(r) != 0) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a certificate context");
    list = rdsub(r, rd24(r));
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Certificate");
    c->x509.tls13 = 1;
    (*xc)->start_chain(xc, c->host);
    while (list.n && !list.bad) {
        size_t len = rd24(&list);
        struct rd der = rdsub(&list, len);
        rdsub(&list, rd16(&list));             /* the entry's extensions (OCSP, SCT): not used */
        if (list.bad || !len) break;
        (*xc)->start_cert(xc, (uint32_t)len);
        (*xc)->append(xc, der.p, len);
        (*xc)->end_cert(xc);
        ++count;
    }
    if (list.bad || !count)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, count ? "a malformed Certificate" : "no certificate");
    err = (*xc)->end_chain(xc);
    if (err) return cert_failed(c, (int)err);
    if (!c->x509.leaf_ed25519) {
        unsigned usages = 0;
        if (!(*xc)->get_pkey(xc, &usages)) return cert_failed(c, OT_ERR_X509_UNSUPPORTED);
        if (!(usages & OT_KEYTYPE_SIGN)) return cert_failed(c, OT_ERR_WRONG_KEY_USAGE);
    }
    t->have_cert = 1;
    t->st = T13_WAIT_CV;
    return OTERR_OK;
}

static LONG certificate_verify(struct OTConnection *c, struct rd *r, const unsigned char *thash)
{
    struct ot13 *t = c->t13;
    const ot_x509_class **xc = &c->x509.vtable;
    unsigned scheme = rd16(r);
    size_t n = rd16(r), i;
    const unsigned char *sig = r->p;
    int err, offered = 0;
    rdsub(r, n);
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed CertificateVerify");
    for (i = 0; i < 7; ++i)                    /* the first seven: TLS 1.3's own */
        if (sigalgs[i] == scheme && (scheme != 0x0807 || t->sigalgs_ed25519)) offered = 1;
    if (!offered)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server signed with a scheme GFOpenTLS did not offer.");
    err = ot13_verify_cv(c, &c->impls, scheme,
                         c->x509.leaf_ed25519 ? NULL : (*xc)->get_pkey(xc, NULL),
                         c->x509.leaf_ed25519 ? c->x509.ed25519 : NULL,
                         thash, t->suite->hash_len, sig, n);
    if (err == OT_ERR_INVALID_ALGORITHM)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server's signature scheme does not suit its key.");
    if (err) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_engine_error(c, OT_ERR_BAD_SIGNATURE);
    }
    t->st = T13_WAIT_FIN;
    return OTERR_OK;
}

/* the client's second flight: [Certificate], Finished; then the
 * application keys */
static LONG client_finished(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    const ot_hash_class *h = t->hash;
    size_t hl = t->suite->hash_len;
    unsigned char th[OT13_HASH_MAX], *rec;
    queue_ccs(t);
    if (t->cert_req) {                         /* no certificate of ours */
        rec = tx_room(t, 4 + 1 + t->cr_ctx_len + 3);
        if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for the Certificate.");
        rec[5] = HS_CERTIFICATE;
        put24(rec + 6, 1 + t->cr_ctx_len + 3);
        rec[9] = (unsigned char)t->cr_ctx_len;
        memcpy(rec + 10, t->cr_ctx, t->cr_ctx_len);
        put24(rec + 10 + t->cr_ctx_len, 0);
        th_update(t, rec + 5, 4 + 1 + t->cr_ctx_len + 3);
        tx_record(t, rec, OT_SSL_HANDSHAKE, 4 + 1 + t->cr_ctx_len + 3);
    }
    rec = tx_room(t, 4 + hl);
    if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for Finished.");
    th_out(t, h, th);
    rec[5] = HS_FINISHED;
    put24(rec + 6, hl);
    ot13_finished(h, t->c_hs, th, rec + 9);
    th_update(t, rec + 5, 4 + hl);
    tx_record(t, rec, OT_SSL_HANDSHAKE, 4 + hl);
    th_out(t, h, th);
    ot13_derive(h, t->master, "res master", th, t->res_master);
    if (ot13_keys_set(&t->wr, t->suite, &c->impls, t->c_ap))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    memset(t->hs_secret, 0, sizeof t->hs_secret);
    memset(t->c_hs, 0, sizeof t->c_hs);
    memset(t->s_hs, 0, sizeof t->s_hs);
    memset(t->master, 0, sizeof t->master);
    t->st = T13_OPEN;
    return OTERR_OK;
}

static LONG server_finished(struct OTConnection *c, struct rd *r, const unsigned char *thash)
{
    struct ot13 *t = c->t13;
    const ot_hash_class *h = t->hash;
    size_t hl = t->suite->hash_len;
    unsigned char want[OT13_HASH_MAX];
    if (r->n != hl) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Finished");
    ot13_finished(h, t->s_hs, thash, want);
    if (!ct_equal(want, r->p, hl)) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_fail(c, OTERR_PROTOCOL, OT_ERR_BAD_FINISHED,
                       "The server's Finished message does not verify.", NULL, NULL);
    }
    return OTERR_OK;
}

/* after the server's Finished is in the transcript */
static LONG application_keys(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    const ot_hash_class *h = t->hash;
    unsigned char derived[OT13_HASH_MAX], th[OT13_HASH_MAX];
    ot13_derive(h, t->hs_secret, "derived", NULL, derived);
    ot13_extract(h, derived, NULL, 0, t->master);
    th_out(t, h, th);
    ot13_derive(h, t->master, "c ap traffic", th, t->c_ap);
    ot13_derive(h, t->master, "s ap traffic", th, t->s_ap);
    memset(derived, 0, sizeof derived);
    if (ot13_keys_set(&t->rd, t->suite, &c->impls, t->s_ap))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    return client_finished(c);
}

/* fills the sessions that wait for a ticket (OT_GetSession before one came) */
static void tickets_out(struct OTConnection *c);

static LONG new_session_ticket(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    uint32_t lifetime, age_add, days = 0, secs = 0;
    size_t nlen, tlen;
    const unsigned char *nonce, *ticket;
    struct ot13_ticket *k;
    if (r->n < 8) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed NewSessionTicket");
    lifetime = get32(r->p);
    age_add = get32(r->p + 4);
    rdsub(r, 8);
    nlen = rd8(r);
    nonce = r->p;
    rdsub(r, nlen);
    tlen = rd16(r);
    ticket = r->p;
    rdsub(r, tlen);
    rdsub(r, rd16(r));                         /* extensions: early_data, not used */
    if (r->bad || r->n || !tlen || lifetime > 7 * 86400UL)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed NewSessionTicket");
    if (!lifetime || tlen > OT13_TICKET_MAX) return OTERR_OK;     /* not kept */
    k = ot_alloc(sizeof *k + tlen);
    if (!k) return OTERR_OK;
    k->suite = t->suite->id;
    ot13_expand_label(t->hash, t->res_master, "resumption", nonce, nlen, k->psk, t->suite->hash_len);
    k->age_add = age_add;
    k->lifetime = lifetime;
    if (ot_now(&days, &secs)) { k->days = days; k->seconds = secs; }
    k->len = tlen;
    memcpy(k->data, ticket, tlen);
    if (t->ticket) {
        memset(t->ticket, 0, sizeof *t->ticket);
        ot_free(t->ticket);
    }
    t->ticket = k;
    tickets_out(c);
    return OTERR_OK;
}

static LONG key_update(struct OTConnection *c, struct rd *r, int last)
{
    struct ot13 *t = c->t13;
    unsigned req = rd8(r);
    if (r->bad || r->n || req > 1) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed KeyUpdate");
    if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after a KeyUpdate");
    if (ot13_keys_next(&t->rd))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    if (req && !t->close_sent) {
        /* answer with ours, under the old key, then move on */
        unsigned char *rec = tx_room(t, 5);
        if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for KeyUpdate.");
        rec[5] = HS_KEY_UPDATE;
        put24(rec + 6, 1);
        rec[9] = 0;
        tx_record(t, rec, OT_SSL_HANDSHAKE, 5);
        if (ot13_keys_next(&t->wr))
            return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
        t->updates_sent++;
    }
    t->updates_received++;
    return OTERR_OK;
}

/* ---- TLS 1.2, our own (RFC 5246, 4492/8422, 5288, 7905, 5746) ---- */

static LONG t12_alpn(struct OTConnection *c, struct rd *d)
{
    struct rd l = rdsub(d, rd16(d));
    size_t n = rd8(&l);
    const unsigned char *name = l.p;
    rdsub(&l, n);
    if (l.bad || l.n || !n || !c->alpn_count) return -1;
    if (!offered_alpn(c, name, n))
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an application protocol it was not offered");
    if (n >= sizeof c->alpn_selected) n = sizeof c->alpn_selected - 1;
    memcpy(c->alpn_selected, name, n);
    c->alpn_selected[n] = 0;
    return OTERR_OK;
}

/* the connection's keys from the master secret (section 6.3) */
static LONG t12_keys(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    const struct ot13_suite *s = t->suite;
    unsigned char seed[64], kb[2 * 48 + 2 * 32 + 2 * 12];
    size_t ml = s->mac_len, kl = s->key_len, il = s->mac ? 0 : s->chacha ? 12 : 4;
    int bad;
    memcpy(seed, t->srandom, 32);
    memcpy(seed + 32, t->random, 32);
    /* client MAC key, server MAC key, client key, server key, client IV, server IV */
    ot12_prf(s->hash, t->master12, 48, "key expansion", seed, 64, kb, 2 * ml + 2 * kl + 2 * il);
    bad = ot12_keys_set(&t->wr, s, &c->impls, kb, kb + 2 * ml, kb + 2 * ml + 2 * kl, 1)
       || ot12_keys_set(&t->rd, s, &c->impls, kb + ml, kb + 2 * ml + kl, kb + 2 * ml + 2 * kl + il, 0);
    memset(kb, 0, sizeof kb);
    if (bad) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    return OTERR_OK;
}

/* a ServerHello for TLS 1.2 with one of suites12 */
static LONG t12_server_hello(struct OTConnection *c, const unsigned char *msg, size_t mlen)
{
    struct ot13 *t = c->t13;
    struct ot12_session *sp = &c->session12;
    struct rd r, ex;
    const unsigned char *sid;
    size_t sid_len;
    unsigned suite, seen = 0;
    LONG rc;
    r.p = msg + 4; r.n = mlen - 4; r.bad = 0;
    rd16(&r);
    if (r.n >= 32) memcpy(t->srandom, r.p, 32);
    rdsub(&r, 32);
    sid_len = rd8(&r);
    sid = r.p;
    rdsub(&r, sid_len);
    suite = rd16(&r);
    if (rd8(&r) != 0) r.bad = 1;
    if (!r.bad && r.n) {
        ex = rdsub(&r, rd16(&r));
        while (ex.n && !ex.bad) {
            unsigned type = rd16(&ex);
            struct rd d = rdsub(&ex, rd16(&ex));
            unsigned bit = type == EXT_RENEGOTIATION ? 1 : type == EXT_SERVER_NAME ? 2
                         : type == EXT_POINT_FORMATS ? 4 : type == EXT_ALPN ? 8 : 0;
            if (!bit) return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
            if (seen & bit) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an extension twice");
            seen |= bit;
            if (type == EXT_RENEGOTIATION) {
                /* RFC 5746: empty on the first handshake; we never renegotiate */
                if (rd8(&d) != 0)
                    return abort13(c, ALERT_HANDSHAKE_FAILURE, OTERR_PROTOCOL, "renegotiation data on a new connection");
            } else if (type == EXT_SERVER_NAME) {
                if (d.n || c->ip_len) d.bad = 1;
            } else if (type == EXT_POINT_FORMATS) {
                struct rd l = rdsub(&d, rd8(&d));
                int uncompressed = 0;
                while (l.n && !l.bad) if (rd8(&l) == 0) uncompressed = 1;
                if (!uncompressed)
                    return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "no uncompressed points");
            } else {
                rc = t12_alpn(c, &d);
                if (rc == -1) d.bad = 1;
                else if (rc != OTERR_OK) return rc;
            }
            if (d.bad || d.n) ex.bad = 1;
        }
        if (ex.bad) r.bad = 1;
    }
    if (r.bad || r.n || sid_len > 32)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed ServerHello");
    t->v12 = 1;
    t->suite = suite12(suite);
    t->hash = t->suite->hash;
    th_update(t, msg, mlen);
    if (sid_len && sp->session_id_len == sid_len && !memcmp(sid, sp->session_id, sid_len)) {
        /* the session offered is resumed (section 7.3, the abbreviated handshake) */
        if (sp->version != OT_TLS12 || sp->cipher_suite != suite)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a session resumed with other parameters");
        memcpy(t->master12, sp->master_secret, 48);
        t->resumed12 = 1;
        t->psk_used = 1;
        if ((rc = t12_keys(c)) != OTERR_OK) return rc;
        t->st = T12_WAIT_CCS;
        return OTERR_OK;
    }
    /* a new session, kept for OT_GetSession once the master secret is known */
    memset(sp, 0, sizeof *sp);
    sp->session_id_len = (unsigned char)sid_len;
    memcpy(sp->session_id, sid, sid_len);
    t->st = T12_WAIT_CERT;
    return OTERR_OK;
}

static LONG t12_certificate(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    const ot_x509_class **xc = &c->x509.vtable;
    const ot_x509_pkey *pk;
    struct rd list = rdsub(r, rd24(r));
    unsigned err, usages = 0;
    int count = 0;
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Certificate");
    c->x509.tls13 = 0;
    (*xc)->start_chain(xc, c->host);
    while (list.n && !list.bad) {
        size_t len = rd24(&list);
        struct rd der = rdsub(&list, len);
        if (list.bad || !len) break;
        (*xc)->start_cert(xc, (uint32_t)len);
        (*xc)->append(xc, der.p, len);
        (*xc)->end_cert(xc);
        ++count;
    }
    if (list.bad || !count)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, count ? "a malformed Certificate" : "no certificate");
    err = (*xc)->end_chain(xc);
    if (err) return cert_failed(c, (int)err);
    pk = (*xc)->get_pkey(xc, &usages);
    if (!pk) return cert_failed(c, OT_ERR_X509_UNSUPPORTED);
    if (!(usages & (t->suite->rsa_kx ? OT_KEYTYPE_KEYX : OT_KEYTYPE_SIGN)))
        return cert_failed(c, OT_ERR_WRONG_KEY_USAGE);
    if (pk->key_type != (t->suite->ecdsa ? OT_KEYTYPE_EC : OT_KEYTYPE_RSA))
        return cert_failed(c, OT_ERR_WRONG_KEY_USAGE);
    t->have_cert = 1;
    t->st = t->suite->rsa_kx ? T12_WAIT_SHD : T12_WAIT_SKE;
    return OTERR_OK;
}

/* the ServerKeyExchange: the server's ECDHE share, signed (RFC 8422 section 5.4) */
static LONG t12_server_key_exchange(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    const ot_x509_class **xc = &c->x509.vtable;
    const ot_x509_pkey *pk = (*xc)->get_pkey(xc, NULL);
    const unsigned char *params = r->p, *point, *sig;
    const ot_hash_class *hc;
    const unsigned char *oid;
    ot_hash_compat_context hctx;
    unsigned char h[64], hout[64], shared[66], pms[66];
    unsigned group, scheme;
    size_t plen, params_len, siglen, hl, i, slen;
    int ok = 0, offered = 0;
    LONG rc;
    if (rd8(r) != 3)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER, "a key exchange that is not a named curve");
    group = rd16(r);
    plen = rd8(r);
    point = r->p;
    rdsub(r, plen);
    params_len = (size_t)(r->p - params);
    scheme = rd16(r);
    siglen = rd16(r);
    sig = r->p;
    rdsub(r, siglen);
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed ServerKeyExchange");
    if (group != GROUP_X25519 && group != GROUP_P256 && group != GROUP_P384 && group != GROUP_P521)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER, "a curve GFOpenTLS did not offer");
    for (i = 0; i < sizeof sigalgs / sizeof sigalgs[0]; ++i)
        if (sigalgs[i] == scheme && scheme != 0x0807) offered = 1;
    if (!offered || !pk)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER, "The server signed with a scheme GFOpenTLS did not offer.");
    switch (scheme >> 8) {
    case 2: hc = &ot_sha1_vtable; oid = OT_HASH_OID_SHA1; break;
    case 4: hc = &ot_sha256_vtable; oid = OT_HASH_OID_SHA256; break;
    case 5: hc = &ot_sha384_vtable; oid = OT_HASH_OID_SHA384; break;
    case 6: hc = &ot_sha512_vtable; oid = OT_HASH_OID_SHA512; break;
    case 8:
        hc = scheme == 0x0804 ? &ot_sha256_vtable : scheme == 0x0805 ? &ot_sha384_vtable : &ot_sha512_vtable;
        oid = NULL;
        break;
    default:
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER, "The server signed with a scheme GFOpenTLS did not offer.");
    }
    hl = hlen_of(hc);
    hc->init(&hctx.vtable);
    hc->update(&hctx.vtable, t->random, 32);
    hc->update(&hctx.vtable, t->srandom, 32);
    hc->update(&hctx.vtable, params, params_len);
    hc->out(&hctx.vtable, h);
    if ((scheme >> 8) == 8) {                         /* RSA-PSS with an rsaEncryption key */
        if (pk->key_type == OT_KEYTYPE_RSA && (ok = svc_check(c, OTK_RSA_PSS, hc, h, hl, sig, siglen)) < 0)
            ok = ot13_rsa_pss(&c->impls, &pk->key.rsa, hc, h, sig, siglen);
    } else if ((scheme & 0xFF) == 1) {                /* RSA PKCS #1 v1.5 */
        if (pk->key_type == OT_KEYTYPE_RSA && (ok = svc_check(c, OTK_RSA_PKCS1, hc, h, hl, sig, siglen)) < 0)
            ok = c->impls.rsa_vrfy(sig, siglen, oid, hl, &pk->key.rsa, hout) && ct_equal(hout, h, hl);
    } else if ((scheme & 0xFF) == 3) {                /* ECDSA */
        if (pk->key_type == OT_KEYTYPE_EC && (ok = svc_check(c, OTK_ECDSA, hc, h, hl, sig, siglen)) < 0)
            ok = c->impls.ecdsa_vrfy(c->impls.ec, h, hl, &pk->key.ec, sig, siglen) ? 1 : 0;
    }
    if (!ok) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_engine_error(c, OT_ERR_BAD_SIGNATURE);
    }
    /* our share and the premaster secret */
    t->group = group;
    if (group == GROUP_X25519) {
        rc = make_x25519(c, t->kx_pub);
        t->kx_len = 32;
    } else if (group == GROUP_P256) {
        rc = make_p256(c, t->kx_pub);
        t->kx_len = 65;
    } else {
        t->kx_len = make_ec(c, group == GROUP_P384 ? OT_EC_secp384r1 : OT_EC_secp521r1, t->kx_pub);
        rc = t->kx_len ? OTERR_OK : OTERR_RANDOM;
    }
    if (rc != OTERR_OK) return abort13(c, ALERT_INTERNAL_ERROR, rc, "No key share could be made.");
    slen = ecdhe(c, group, point, plen, shared);
    memset(t->x25519, 0, sizeof t->x25519);
    memset(t->p256, 0, sizeof t->p256);
    memset(t->ecpriv, 0, sizeof t->ecpriv);
    if (!slen) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a bad key share");
    {
        unsigned char seed[64];
        memcpy(pms, shared, slen);
        memcpy(seed, t->random, 32);
        memcpy(seed + 32, t->srandom, 32);
        ot12_prf(t->hash, pms, slen, "master secret", seed, 64, t->master12, 48);
    }
    memset(shared, 0, sizeof shared);
    memset(pms, 0, sizeof pms);
    t->st = T12_WAIT_SHD;
    return OTERR_OK;
}

static LONG t12_cert_request(struct OTConnection *c, struct rd *r)
{
    rdsub(r, rd8(r));                                  /* certificate types */
    rdsub(r, rd16(r));                                 /* signature algorithms */
    rdsub(r, rd16(r));                                 /* authorities: we answer with no certificate */
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed CertificateRequest");
    c->t13->cert_req = 1;
    return OTERR_OK;
}

/* a handshake message of ours, into the transcript and out */
static LONG t12_send(struct OTConnection *c, int type, const unsigned char *body, size_t len)
{
    struct ot13 *t = c->t13;
    unsigned char *rec = tx_room(t, 4 + len);
    if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for a handshake message.");
    rec[5] = (unsigned char)type;
    put24(rec + 6, len);
    if (len) memcpy(rec + 9, body, len);
    th_update(t, rec + 5, 4 + len);
    tx_record(t, rec, OT_SSL_HANDSHAKE, 4 + len);
    return OTERR_OK;
}

/* ChangeCipherSpec and Finished from us (section 7.4.9) */
static LONG t12_client_finished(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    unsigned char th[OT13_HASH_MAX], vd[12];
    LONG rc;
    queue_ccs(t);
    t->wr_on = 1;
    th_out(t, t->hash, th);
    ot12_prf(t->hash, t->master12, 48, "client finished", th, t->suite->hash_len, vd, 12);
    rc = t12_send(c, HS_FINISHED, vd, 12);
    return rc;
}

/* RSA key exchange (section 7.4.7.1): a premaster secret of ours,
 * encrypted to the server's key with PKCS #1 v1.5 padding, sent in cke;
 * the master secret from it */
static LONG t12_rsa_key_exchange(struct OTConnection *c, unsigned char *cke)
{
    struct ot13 *t = c->t13;
    const ot_x509_class **xc = &c->x509.vtable;
    const ot_x509_pkey *pk = (*xc)->get_pkey(xc, NULL);
    unsigned char pms[48], seed[64], *em = cke + 2;
    size_t nlen, i;
    LONG rc;
    if (!pk || pk->key_type != OT_KEYTYPE_RSA) return cert_failed(c, OT_ERR_WRONG_KEY_USAGE);
    nlen = pk->key.rsa.nlen;
    if (nlen < 48 + 11 || nlen > OC_RSA_MAX_BYTES)
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_CIPHER, "The server's RSA key does not suit a key exchange.");
    pms[0] = 3;
    pms[1] = 3;                                         /* the version offered */
    if (ot_random(pms + 2, 46) != OTERR_OK || ot_random(em + 2, nlen - 48 - 3) != OTERR_OK)
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_RANDOM, "No random numbers for the handshake.");
    em[0] = 0;
    em[1] = 2;
    for (i = 2; i < nlen - 48 - 1; ++i)                 /* the padding has no zero byte */
        while (!em[i])
            if (ot_random(em + i, 1) != OTERR_OK)
                return abort13(c, ALERT_INTERNAL_ERROR, OTERR_RANDOM, "No random numbers for the handshake.");
    em[nlen - 48 - 1] = 0;
    memcpy(em + nlen - 48, pms, 48);
    if (!c->impls.rsa_pub(em, nlen, &pk->key.rsa)) {
        memset(pms, 0, sizeof pms);
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_CIPHER, "The server's RSA key does not suit a key exchange.");
    }
    put16(cke, nlen);
    rc = t12_send(c, HS_CLIENT_KEY_EXCH, cke, 2 + nlen);
    memcpy(seed, t->random, 32);
    memcpy(seed + 32, t->srandom, 32);
    ot12_prf(t->hash, pms, 48, "master secret", seed, 64, t->master12, 48);
    memset(pms, 0, sizeof pms);
    return rc;
}

static LONG t12_server_hello_done(struct OTConnection *c, struct rd *r, int last)
{
    struct ot13 *t = c->t13;
    struct ot12_session *sp = &c->session12;
    unsigned char cke[2 + OC_RSA_MAX_BYTES];
    LONG rc;
    if (r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed ServerHelloDone");
    if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after ServerHelloDone");
    if (t->cert_req) {                                 /* no certificate of ours */
        static const unsigned char none[3] = { 0, 0, 0 };
        if ((rc = t12_send(c, HS_CERTIFICATE, none, 3)) != OTERR_OK) return rc;
    }
    if (t->suite->rsa_kx) {
        if ((rc = t12_rsa_key_exchange(c, cke)) != OTERR_OK) return rc;
    } else {
        cke[0] = (unsigned char)t->kx_len;
        memcpy(cke + 1, t->kx_pub, t->kx_len);
        if ((rc = t12_send(c, HS_CLIENT_KEY_EXCH, cke, 1 + t->kx_len)) != OTERR_OK) return rc;
    }
    if ((rc = t12_keys(c)) != OTERR_OK) return rc;
    if ((rc = t12_client_finished(c)) != OTERR_OK) return rc;
    sp->version = OT_TLS12;
    sp->cipher_suite = t->suite->id;
    memcpy(sp->master_secret, t->master12, 48);
    t->st = T12_WAIT_CCS;
    return OTERR_OK;
}

static LONG t12_finished(struct OTConnection *c, struct rd *r, const unsigned char *msg, size_t len, int last)
{
    struct ot13 *t = c->t13;
    unsigned char th[OT13_HASH_MAX], want[12];
    LONG rc;
    if (r->n != 12) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Finished");
    if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after Finished");
    th_out(t, t->hash, th);
    ot12_prf(t->hash, t->master12, 48, "server finished", th, t->suite->hash_len, want, 12);
    if (!ct_equal(want, r->p, 12)) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_fail(c, OTERR_PROTOCOL, OT_ERR_BAD_FINISHED,
                       "The server's Finished message does not verify.", NULL, NULL);
    }
    th_update(t, msg, len);
    if (t->resumed12 && (rc = t12_client_finished(c)) != OTERR_OK) return rc;
    memset(t->master12, 0, sizeof t->master12);
    t->st = T13_OPEN;
    return OTERR_OK;
}

static LONG t12_message(struct OTConnection *c, const unsigned char *msg, size_t len, struct rd *r, int last)
{
    struct ot13 *t = c->t13;
    unsigned type = msg[0];
    if (type == HS_HELLO_REQUEST && len == 4) return OTERR_OK;   /* no renegotiation: ignored */
    switch (t->st) {
    case T12_WAIT_CERT:
        if (type != HS_CERTIFICATE) break;
        th_update(t, msg, len);
        return t12_certificate(c, r);
    case T12_WAIT_SKE:
        if (type != HS_SERVER_KEY_EXCH) break;
        th_update(t, msg, len);
        return t12_server_key_exchange(c, r);
    case T12_WAIT_SHD:
        th_update(t, msg, len);
        if (type == HS_CERT_REQUEST && !t->cert_req) return t12_cert_request(c, r);
        if (type == HS_SERVER_HELLO_DONE) return t12_server_hello_done(c, r, last);
        break;
    case T12_WAIT_FIN:
        if (type != HS_FINISHED) break;
        return t12_finished(c, r, msg, len, last);
    default:
        break;
    }
    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a message out of order");
}

/* one whole handshake message; last says it ends its record */
static LONG handshake_message(struct OTConnection *c, const unsigned char *msg, size_t len, int last)
{
    struct ot13 *t = c->t13;
    struct rd r;
    unsigned type = msg[0];
    unsigned char th[OT13_HASH_MAX];
    LONG rc;
    r.p = msg + 4; r.n = len - 4; r.bad = 0;
    if (t->v12) return t12_message(c, msg, len, &r, last);
    if (t->st == T13_OPEN) {
        if (type == HS_NEW_SESSION_TICKET) return new_session_ticket(c, &r);
        if (type == HS_KEY_UPDATE) return key_update(c, &r, last);
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected message after the handshake");
    }
    /* the transcript before this message, for CertificateVerify and Finished */
    if (type == HS_CERT_VERIFY || type == HS_FINISHED) th_out(t, t->hash, th);
    switch (t->st) {
    case T13_WAIT_EE:
        if (type != HS_ENCRYPTED_EXT) goto unexpected;
        th_update(t, msg, len);
        return encrypted_extensions(c, &r);
    case T13_WAIT_CERT_CR:
        if (type == HS_CERT_REQUEST) {
            th_update(t, msg, len);
            return certificate_request(c, &r);
        }
        /* fall through */
    case T13_WAIT_CERT:
        if (type != HS_CERTIFICATE) goto unexpected;
        th_update(t, msg, len);
        return certificate(c, &r);
    case T13_WAIT_CV:
        if (type != HS_CERT_VERIFY) goto unexpected;
        if ((rc = certificate_verify(c, &r, th)) != OTERR_OK) return rc;
        th_update(t, msg, len);
        return OTERR_OK;
    case T13_WAIT_FIN:
        if (type != HS_FINISHED) goto unexpected;
        if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after Finished");
        if ((rc = server_finished(c, &r, th)) != OTERR_OK) return rc;
        th_update(t, msg, len);
        return application_keys(c);
    default:
        break;
    }
unexpected:
    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a message out of order");
}

/* the handshake bytes of the current record, message by message; those of
 * a message that goes on in the next record wait in t->hs */
static LONG handshake_bytes(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    while (t->pt_len) {
        const unsigned char *p = t->pt;
        size_t avail = t->pt_len, need, take;
        LONG rc;
        if (!t->hs_len && avail >= 4 && avail >= 4 + get24(p + 1)) {
            /* a whole message in the record: handled where it is */
            need = 4 + get24(p + 1);
            t->pt += need;
            t->pt_len -= need;
            if (t->st == T13_WAIT_SH) {
                if (p[0] != HS_SERVER_HELLO)
                    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "no ServerHello");
                rc = server_hello(c, p, need, t->pt, t->pt_len);
                if (!t->v12) t->pt_len = 0;    /* TLS 1.2 ours: the server's next messages follow */
            } else {
                rc = handshake_message(c, p, need, t->pt_len == 0);
            }
            if (rc != OTERR_OK) return rc;
            continue;
        }
        /* part of a message: collect it */
        need = t->hs_len < 4 ? 4 : 4 + get24(t->hs + 1);
        if (t->hs_len >= 4 && need > OT13_HS_MAX)
            return abort13(c, ALERT_RECORD_OVERFLOW, OTERR_PROTOCOL, "a handshake message too long");
        if (need > t->hs_cap) {
            size_t cap = need < 4096 ? 4096 : need;
            unsigned char *n = ot_alloc(cap);
            if (!n) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_NOMEM, "Out of memory.");
            if (t->hs_len) memcpy(n, t->hs, t->hs_len);
            ot_free(t->hs);
            t->hs = n;
            t->hs_cap = cap;
        }
        take = need - t->hs_len < avail ? need - t->hs_len : avail;
        memcpy(t->hs + t->hs_len, p, take);
        t->hs_len += take;
        t->pt += take;
        t->pt_len -= take;
        if (t->hs_len >= 4 && t->hs_len == 4 + get24(t->hs + 1)) {
            t->hs_len = 0;
            if (t->st == T13_WAIT_SH) {
                if (t->hs[0] != HS_SERVER_HELLO)
                    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "no ServerHello");
                rc = server_hello(c, t->hs, need, t->pt, t->pt_len);
                if (!t->v12) t->pt_len = 0;
            } else {
                rc = handshake_message(c, t->hs, need, t->pt_len == 0);
            }
            if (rc != OTERR_OK) return rc;
        }
    }
    return OTERR_OK;
}

/* reads and handles one record */
static LONG one_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc = read_record(c);
    if (rc != OTERR_OK) return rc;
    if ((rc = open_record(c)) != OTERR_OK) return rc;
    switch (t->pt_type) {
    case OT_SSL_CHANGE_CIPHER_SPEC:
        return OTERR_OK;
    case OT_SSL_ALERT:
        return handle_alert(c, t->pt, t->pt_len);
    case OT_SSL_HANDSHAKE:
        if (!t->pt_len) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an empty record");
        return handshake_bytes(c);
    default:                                   /* application data */
        t->app = t->pt;
        t->app_len = t->pt_len;
        return OTERR_OK;
    }
}

/* ---- the calls ---- */

LONG ot13_handshake(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc;
    for (;;) {
        if (t->tx_sent < t->tx_len && (rc = tx_flush(c)) != OTERR_OK) return rc;
        if (t->st == T13_OPEN) return OTERR_OK;
        rc = one_record(c);
        if (rc == OTERR_CLOSED && c->clean_close)
            return ot_fail(c, OTERR_CLOSED, 0, "The server closed the connection during the handshake.", NULL, NULL);
        if (rc != OTERR_OK) return rc;
        if (t->app_len) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "early application data");
    }
}

LONG ot13_read(struct OTConnection *c, unsigned char *buf, LONG len)
{
    struct ot13 *t = c->t13;
    LONG rc;
    for (;;) {
        if (t->app_len) {
            size_t n = (size_t)len < t->app_len ? (size_t)len : t->app_len;
            memcpy(buf, t->app, n);
            t->app += n;
            t->app_len -= n;
            return (LONG)n;
        }
        if (c->state == OTS_CLOSED) return c->clean_close ? 0 : OTERR_STATE;
        /* records still going out (the rest of a write the socket refused,
         * a KeyUpdate's answer): they go first, since the server may be
         * waiting for them before it answers */
        if (t->tx_sent < t->tx_len) {
            rc = tx_flush(c);
            if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
            if (rc != OTERR_OK) return rc;
        }
        rc = one_record(c);
        if (rc == OTERR_CLOSED && c->clean_close) return 0;
        if (rc != OTERR_OK) return rc;
    }
}

LONG ot13_write(struct OTConnection *c, const unsigned char *buf, LONG len)
{
    struct ot13 *t = c->t13;
    LONG total = 0, rc;
    if (t->tx_sent < t->tx_len) {
        rc = tx_flush(c);
        if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
        if (rc != OTERR_OK) return rc;
    }
    if (t->close_sent) return ot_fail(c, OTERR_STATE, 0, "The connection is closing.", NULL, NULL);
    if (t->tx == c->out) big_tx(c);
    while (total < len) {
        size_t n = (size_t)(len - total), room;
        unsigned char *rec;
        /* new keys long before AES-GCM's limit (RFC 8446 section 5.5) */
        if (!t->v12 && t->wr.seq >= t->update_after) {
            rec = tx_room(t, 5);
            if (rec) {
                rec[5] = HS_KEY_UPDATE;
                put24(rec + 6, 1);
                rec[9] = 0;
                tx_record(t, rec, OT_SSL_HANDSHAKE, 5);
                if (ot13_keys_next(&t->wr))
                    return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
                t->updates_sent++;
            }
        }
        room = t->tx_cap - t->tx_len;
        room = room > 5 + OT12_OVERHEAD + OT13_TX_SPARE ? room - 5 - OT12_OVERHEAD - OT13_TX_SPARE : 0;
        if (room > OT13_RECORD_MAX) room = OT13_RECORD_MAX;
        if (n > room) n = room;
        if (n) {
            rec = t->tx + t->tx_len;
            memcpy(rec + 5, buf + total, n);
            tx_record(t, rec, OT_SSL_APPLICATION_DATA, n);
            total += (LONG)n;
        }
        rc = tx_flush(c);
        if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; c->error = OTERR_OK; return total ? total : rc; }
        if (rc != OTERR_OK) return rc;
    }
    return total;
}

LONG ot13_pending(struct OTConnection *c)
{
    return c->t13 ? (LONG)c->t13->app_len : 0;
}

LONG ot13_close(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc;
    if (!t->close_sent) queue_alert(c, 1, ALERT_CLOSE_NOTIFY);
    rc = tx_flush(c);
    if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
    return rc;
}

/* ---- tickets and sessions ---- */

struct ot13_ticket *ot13_ticket_copy(const struct ot13_ticket *k)
{
    struct ot13_ticket *n;
    if (!k) return NULL;
    n = ot_alloc(sizeof *n + k->len);
    if (n) memcpy(n, k, sizeof *n + k->len);
    return n;
}

static void tickets_out(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTSession *s;
    ot_session_lock();
    for (s = t->waiting; s; s = s->next_waiting) {
        struct ot13_ticket *n = ot13_ticket_copy(t->ticket);
        if (!n) continue;
        if (s->t13) { memset(s->t13, 0, sizeof *s->t13); ot_free(s->t13); }
        s->t13 = n;
    }
    ot_session_unlock();
}

void ot13_session_wait(struct OTConnection *c, struct OTSession *s)
{
    struct ot13 *t = c->t13;
    ot_session_lock();
    s->source = c;
    s->next_waiting = t->waiting;
    t->waiting = s;
    ot_session_unlock();
}

void ot13_session_unwait(struct OTSession *s)
{
    struct OTSession **pp;
    ot_session_lock();
    if (s->source && s->source->t13) {
        for (pp = &s->source->t13->waiting; *pp; pp = &(*pp)->next_waiting)
            if (*pp == s) { *pp = s->next_waiting; break; }
    }
    s->source = NULL;
    s->next_waiting = NULL;
    ot_session_unlock();
}

void ot13_free(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTSession *s, *n;
    if (!t) return;
    ot_session_lock();
    for (s = t->waiting; s; s = n) {          /* they keep what they have */
        n = s->next_waiting;
        s->source = NULL;
        s->next_waiting = NULL;
    }
    t->waiting = NULL;
    ot_session_unlock();
    if (t->ticket) { memset(t->ticket, 0, sizeof *t->ticket); ot_free(t->ticket); }
    if (t->hs) { memset(t->hs, 0, t->hs_cap); ot_free(t->hs); }
    ot_free(t->cookie);
    memset(t, 0, sizeof *t);
    ot_free(t);
    c->t13 = NULL;
}
