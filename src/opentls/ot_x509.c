/* GFOpenTLS: certificate checks. BearSSL's "minimal" X.509 engine does the
 * chain, the dates and DNS names; this wrapper around it adds what GFOpenTLS
 * promises on top: the server's certificate and its SHA-256 fingerprint
 * kept for the caller, pinned certificates, the verify modes, and
 * certificates for IP addresses (which the minimal engine does not match),
 * and for TLS 1.3 server certificates with Ed25519 keys (which it cannot
 * read at all; 20 October 2026).
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"

#define INNER(x) (&(x)->minimal.vtable)

/* ---- a small DER reader, for the subjectAltName and CN ---- */

struct der { const unsigned char *p; size_t len; };

/* the next element of d: its tag and contents; 0 at the end or on an error */
static int der_next(struct der *d, unsigned *tag, struct der *content)
{
    size_t i = 2, l, n;
    if (d->len < 2) return 0;
    *tag = d->p[0];
    l = d->p[1];
    if (l & 0x80) {
        n = l & 0x7F;
        if (n == 0 || n > 3 || d->len < 2 + n) return 0;
        for (l = 0; n; --n) l = (l << 8) | d->p[i++];
    }
    if (l > d->len - i) return 0;
    content->p = d->p + i;
    content->len = l;
    d->p += i + l;
    d->len -= i + l;
    return 1;
}

/* the contents of the TBSCertificate */
static int der_tbs(const unsigned char *der, size_t len, struct der *tbs)
{
    struct der d = { der, len }, cert;
    unsigned tag;
    if (!der_next(&d, &tag, &cert) || tag != 0x30) return 0;
    if (!der_next(&cert, &tag, tbs) || tag != 0x30) return 0;
    return 1;
}

static int der_san(const unsigned char *der, size_t len, struct der *names)
{
    static const unsigned char oid_san[] = { 0x55, 0x1D, 0x11 };
    struct der tbs, e, exts, seq, x;
    unsigned tag;
    if (!der_tbs(der, len, &tbs)) return 0;
    while (der_next(&tbs, &tag, &e)) {
        if (tag != 0xA3) continue;
        if (!der_next(&e, &tag, &exts) || tag != 0x30) return 0;
        while (der_next(&exts, &tag, &seq)) {
            if (tag != 0x30 || !der_next(&seq, &tag, &x) || tag != 0x06) continue;
            if (x.len != sizeof oid_san || memcmp(x.p, oid_san, sizeof oid_san)) continue;
            if (!der_next(&seq, &tag, &x)) return 0;
            if (tag == 0x01 && !der_next(&seq, &tag, &x)) return 0;
            if (tag != 0x04) return 0;
            if (!der_next(&x, &tag, names) || tag != 0x30) return 0;
            return 1;
        }
    }
    return 0;
}

int ot_cert_has_ip(const unsigned char *der, size_t len, const unsigned char *ip, size_t iplen)
{
    struct der names, n;
    unsigned tag;
    if (!der || !der_san(der, len, &names)) return 0;
    while (der_next(&names, &tag, &n))
        if (tag == 0x87 && n.len == iplen && !memcmp(n.p, ip, iplen)) return 1;
    return 0;
}

static void copy_name(const struct der *n, char *out, size_t outlen)
{
    size_t l = n->len < outlen - 1 ? n->len : outlen - 1, i;
    for (i = 0; i < l; ++i) {
        unsigned char ch = n->p[i];
        out[i] = (ch >= 32 && ch < 127) ? (char)ch : '?';
    }
    out[l] = 0;
}

void ot_cert_name(const unsigned char *der, size_t len, char *out, size_t outlen)
{
    static const unsigned char oid_cn[] = { 0x55, 0x04, 0x03 };
    struct der names, n, tbs, e, set, atv, x;
    unsigned tag;
    int field = 0;
    if (!outlen) return;
    out[0] = 0;
    if (!der) return;
    if (der_san(der, len, &names))
        while (der_next(&names, &tag, &n))
            if (tag == 0x82) { copy_name(&n, out, outlen); return; }
    /* the subject's CN: version [0] (optional), serial, algorithm,
     * issuer, validity, subject */
    if (!der_tbs(der, len, &tbs)) return;
    while (der_next(&tbs, &tag, &e)) {
        if (tag == 0xA0) continue;
        if (++field != 5) continue;
        while (der_next(&e, &tag, &set)) {
            while (der_next(&set, &tag, &atv)) {
                if (!der_next(&atv, &tag, &x) || tag != 0x06) continue;
                if (x.len != sizeof oid_cn || memcmp(x.p, oid_cn, sizeof oid_cn)) continue;
                if (der_next(&atv, &tag, &x)) { copy_name(&x, out, outlen); return; }
            }
        }
        return;
    }
}

/* ---- an Ed25519 leaf (TLS 1.3) ----
 *
 * BearSSL's minimal engine knows RSA and EC keys only. When the server's
 * certificate has an Ed25519 key, the engine is given the chain from the
 * second certificate on (treated as its end entity, with no name check),
 * which takes that certificate to a trusted CA as usual; the leaf is
 * checked here: that the certificate after it is a CA, that its issuer
 * name is that CA's subject, its signature under the CA's key, its dates,
 * and the host name or address. A leaf issued straight by a trust anchor
 * is checked against the anchor. */

/* the next element whole (tag and length too): where it starts and ends */
static int der_whole(struct der *d, unsigned *tag, struct der *content, struct der *whole)
{
    const unsigned char *start = d->p;
    if (!der_next(d, tag, content)) return 0;
    whole->p = start;
    whole->len = (size_t)(d->p - start);
    return 1;
}

struct leaf_parts {
    struct der tbs;          /* whole, for the signature */
    struct der issuer;       /* whole */
    struct der validity;     /* contents */
    struct der subject;      /* whole */
    struct der spki;         /* contents */
    struct der exts;         /* contents of [3], or empty */
    struct der sigalg;       /* the outer algorithm's OID */
    struct der sig;          /* the BIT STRING's bytes, past the unused-bits count */
};

static int leaf_parse(const unsigned char *der, size_t len, struct leaf_parts *lp)
{
    struct der d = { der, len }, cert, tbs, e, w, alg, oid;
    unsigned tag;
    int field = 0;
    memset(lp, 0, sizeof *lp);
    if (!der_next(&d, &tag, &cert) || tag != 0x30) return 0;
    if (!der_whole(&cert, &tag, &tbs, &lp->tbs) || tag != 0x30) return 0;
    while (der_whole(&tbs, &tag, &e, &w)) {
        if (tag == 0xA0 && field == 0) continue;            /* version */
        switch (field++) {
        case 2: lp->issuer = w; break;
        case 3: lp->validity = e; break;
        case 4: lp->subject = w; break;
        case 5: lp->spki = e; break;
        default:
            if (tag == 0xA3) {
                struct der x;
                if (!der_next(&e, &tag, &x) || tag != 0x30) return 0;
                lp->exts = x;
            }
            break;
        }
    }
    if (field < 6) return 0;
    if (!der_next(&cert, &tag, &alg) || tag != 0x30) return 0;
    if (!der_next(&alg, &tag, &oid) || tag != 0x06) return 0;
    lp->sigalg = oid;
    if (!der_next(&cert, &tag, &lp->sig) || tag != 0x03 || lp->sig.len < 2 || lp->sig.p[0]) return 0;
    ++lp->sig.p;
    --lp->sig.len;
    return 1;
}

/* the key, when the SubjectPublicKeyInfo is Ed25519's (1.3.101.112) */
static int spki_ed25519(const struct der *spki, unsigned char *key)
{
    static const unsigned char oid[] = { 0x2B, 0x65, 0x70 };
    struct der s = *spki, alg, o, bits;
    unsigned tag;
    if (!der_next(&s, &tag, &alg) || tag != 0x30) return 0;
    if (!der_next(&alg, &tag, &o) || tag != 0x06 || o.len != 3 || memcmp(o.p, oid, 3)) return 0;
    if (!der_next(&s, &tag, &bits) || tag != 0x03 || bits.len != 33 || bits.p[0]) return 0;
    memcpy(key, bits.p + 1, 32);
    return 1;
}

/* an extension's value (inside its OCTET STRING), by the last byte of
 * its 2.5.29.x OID */
static int find_ext(const struct der *exts, unsigned char id, struct der *value)
{
    struct der all = *exts, ext, oid, v;
    unsigned tag;
    while (der_next(&all, &tag, &ext)) {
        if (tag != 0x30 || !der_next(&ext, &tag, &oid) || tag != 0x06) continue;
        if (oid.len != 3 || oid.p[0] != 0x55 || oid.p[1] != 0x1D || oid.p[2] != id) continue;
        if (!der_next(&ext, &tag, &v)) return 0;
        if (tag == 0x01 && !der_next(&ext, &tag, &v)) return 0;
        if (tag != 0x04) return 0;
        *value = v;
        return 1;
    }
    return 0;
}

/* a CA: basicConstraints with cA true, and keyCertSign if keyUsage is there */
static int is_ca(const unsigned char *der, size_t len)
{
    struct leaf_parts lp;
    struct der v, seq, b;
    unsigned tag;
    if (!leaf_parse(der, len, &lp) || !find_ext(&lp.exts, 19, &v)) return 0;
    if (!der_next(&v, &tag, &seq) || tag != 0x30) return 0;
    if (!der_next(&seq, &tag, &b) || tag != 0x01 || b.len != 1 || !b.p[0]) return 0;
    if (find_ext(&lp.exts, 15, &v)) {
        if (!der_next(&v, &tag, &b) || tag != 0x03 || b.len < 2 || !(b.p[1] & 0x04)) return 0;
    }
    return 1;
}

/* days since 1 January of year 0 (proleptic Gregorian), as ot_now() */
static uint32_t days_of(uint32_t y, uint32_t m, uint32_t d)
{
    static const uint16_t before[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    uint32_t leaps = y ? (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400 + 1 : 0;
    uint32_t n = 365 * y + leaps + before[m - 1] + d - 1;
    if (m > 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) ++n;
    return n;
}

static int read_time(struct der *v, uint32_t *days, uint32_t *secs)
{
    struct der t;
    unsigned tag, i, n[7];
    const unsigned char *p;
    size_t digits;
    if (!der_next(v, &tag, &t)) return 0;
    digits = tag == 0x17 ? 12 : tag == 0x18 ? 14 : 0;
    if (!digits || t.len != digits + 1 || t.p[digits] != 'Z') return 0;
    for (i = 0; i < digits; ++i)
        if (t.p[i] < '0' || t.p[i] > '9') return 0;
    p = t.p;
    if (tag == 0x17) {
        n[0] = (unsigned)((p[0] - '0') * 10 + (p[1] - '0'));
        n[0] += n[0] < 50 ? 2000 : 1900;
        p += 2;
    } else {
        n[0] = (unsigned)((p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0'));
        p += 4;
    }
    for (i = 1; i < 6; ++i, p += 2) n[i] = (unsigned)((p[0] - '0') * 10 + (p[1] - '0'));
    if (n[1] < 1 || n[1] > 12 || n[2] < 1 || n[2] > 31 || n[3] > 23 || n[4] > 59 || n[5] > 60) return 0;
    *days = days_of(n[0], n[1], n[2]);
    *secs = n[3] * 3600UL + n[4] * 60UL + n[5];
    return 1;
}

static int lowerc(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

/* a DNS name in a certificate against the host: no case, and "*" only as
 * the whole first label, standing for exactly one label */
static int name_matches(const unsigned char *pat, size_t plen, const char *host)
{
    size_t hlen = strlen(host), i;
    if (plen >= 2 && pat[0] == '*' && pat[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot || dot == host) return 0;
        pat += 1; plen -= 1;
        hlen -= (size_t)(dot - host);
        host = dot;
    }
    if (plen != hlen) return 0;
    for (i = 0; i < plen; ++i)
        if (lowerc(pat[i]) != lowerc((unsigned char)host[i])) return 0;
    return 1;
}

static int leaf_names(const unsigned char *der, size_t len, const char *host)
{
    struct der names, n;
    unsigned tag;
    if (!der_san(der, len, &names)) return 0;
    while (der_next(&names, &tag, &n))
        if (tag == 0x82 && name_matches(n.p, n.len, host)) return 1;
    return 0;
}

/* the leaf's signature under the issuer's key */
static unsigned leaf_signature(struct ot_x509 *x, const struct leaf_parts *lp, const br_x509_pkey *pk)
{
    static const unsigned char ecdsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03 };
    static const unsigned char rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01 };
    const struct ot_impls *m = x->impls;
    const br_hash_class *h = NULL;
    const unsigned char *oid = NULL;
    unsigned char hv[64], got[64];
    br_hash_compat_context hc;
    size_t hl;
    unsigned last = lp->sigalg.len ? lp->sigalg.p[lp->sigalg.len - 1] : 0;
    int is_ec = lp->sigalg.len == 8 && !memcmp(lp->sigalg.p, ecdsa, 7);
    int is_rsa = lp->sigalg.len == 9 && !memcmp(lp->sigalg.p, rsa, 8);
    if (is_ec) {
        h = last == 2 ? m->sha256 : last == 3 ? m->sha384 : last == 4 ? m->sha512 : NULL;
    } else if (is_rsa) {
        h = last == 11 ? m->sha256 : last == 12 ? m->sha384 : last == 13 ? m->sha512 : NULL;
        oid = last == 11 ? BR_HASH_OID_SHA256 : last == 12 ? BR_HASH_OID_SHA384 : BR_HASH_OID_SHA512;
    }
    if (!h) return BR_ERR_X509_UNSUPPORTED;
    hl = (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    h->init(&hc.vtable);
    h->update(&hc.vtable, lp->tbs.p, lp->tbs.len);
    h->out(&hc.vtable, hv);
    if (is_ec) {
        if (pk->key_type != BR_KEYTYPE_EC) return BR_ERR_X509_WRONG_KEY_TYPE;
        return m->ecdsa_vrfy(m->ec, hv, hl, &pk->key.ec, lp->sig.p, lp->sig.len)
            ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    }
    if (pk->key_type != BR_KEYTYPE_RSA) return BR_ERR_X509_WRONG_KEY_TYPE;
    if (!m->rsa_vrfy(lp->sig.p, lp->sig.len, oid, hl, &pk->key.rsa, got) || memcmp(got, hv, hl))
        return BR_ERR_X509_BAD_SIGNATURE;
    return 0;
}

static unsigned ed25519_leaf_check(struct ot_x509 *x)
{
    struct OTConnection *c = x->conn;
    struct leaf_parts lp, ip;
    struct der v;
    uint32_t nb_d, nb_s, na_d, na_s, days, secs;
    const br_x509_pkey *pk = NULL;
    unsigned err;
    size_t i;

    if (!leaf_parse(x->leaf, x->leaf_len, &lp)) return BR_ERR_X509_INVALID_VALUE;
    if (x->cert_index == 0) {
        /* no other certificate: the leaf's issuer must be a trust anchor */
        for (i = 0; i < x->ta_count; ++i) {
            const br_x509_trust_anchor *ta = &x->ta[i];
            if ((ta->flags & BR_X509_TA_CA) && ta->dn.len == lp.issuer.len
                && !memcmp(ta->dn.data, lp.issuer.p, lp.issuer.len)) {
                pk = &ta->pkey;
                break;
            }
        }
        if (!pk) return BR_ERR_X509_NOT_TRUSTED;
    } else {
        err = (*INNER(x))->end_chain(INNER(x));
        if (err) return err;
        if (!x->issuer_ok || !leaf_parse(x->issuer, x->issuer_len, &ip)) return BR_ERR_X509_INVALID_VALUE;
        if (!is_ca(x->issuer, x->issuer_len)) return BR_ERR_X509_NOT_CA;
        if (ip.subject.len != lp.issuer.len || memcmp(ip.subject.p, lp.issuer.p, lp.issuer.len))
            return BR_ERR_X509_DN_MISMATCH;
        pk = (*INNER(x))->get_pkey((const br_x509_class *const *)INNER(x), NULL);
        if (!pk) return BR_ERR_X509_NOT_TRUSTED;
    }
    if ((err = leaf_signature(x, &lp, pk)) != 0) return err;
    v = lp.validity;
    if (!read_time(&v, &nb_d, &nb_s) || !read_time(&v, &na_d, &na_s)) return BR_ERR_X509_BAD_TIME;
    if (!ot_now(&days, &secs)) return BR_ERR_X509_TIME_UNKNOWN;
    if (days < nb_d || (days == nb_d && secs < nb_s) || days > na_d || (days == na_d && secs > na_s))
        return BR_ERR_X509_EXPIRED;
    if (c->verify == OTV_FULL || c->verify == OTV_REPORT) {
        if (c->ip_len) {
            if (!ot_cert_has_ip(x->leaf, x->leaf_len, c->ip, (size_t)c->ip_len)) return OT_X509_IP;
        } else if (!leaf_names(x->leaf, x->leaf_len, c->host)) {
            return BR_ERR_X509_BAD_SERVER_NAME;
        }
    }
    return 0;
}

/* ---- the wrapper engine ---- */

#define CHECKS_NAME(c) ((c)->verify == OTV_FULL || (c)->verify == OTV_REPORT)
#define INNER_NAME(x) (CHECKS_NAME((x)->conn) && !(x)->conn->ip_len ? (x)->conn->host : NULL)

static void xw_start_chain(const br_x509_class **ctx, const char *server_name)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    (void)server_name;
    x->cert_index = -1;
    x->accepted = 0;
    x->leaf_ok = 0;
    x->leaf_len = 0;
    x->have_fingerprint = 0;
    x->deferred = 0;
    x->leaf_ed25519 = 0;
    x->issuer_ok = 0;
    x->issuer_len = 0;
    x->inner_started = 0;
    x->chain_count = 0;
    x->chain_len = 0;
    x->chain_ok = 1;
    x->verdict = -1;
    c->peer_name_done = 0;
}

/* every certificate the server sent, kept for OT_GetPeerCertificateN() */
static void chain_start(struct ot_x509 *x, uint32_t length)
{
    size_t need;
    if (!x->chain_ok || x->chain_count >= OT_CHAIN_MAX || length > OT_CHAIN_BYTES) {
        x->chain_ok = 0;
        return;
    }
    need = x->chain_len + length;
    if (need > OT_CHAIN_BYTES) {
        x->chain_ok = 0;
        return;
    }
    if (need > x->chain_cap) {
        size_t cap = x->chain_cap ? x->chain_cap : 8192;
        unsigned char *n;
        while (cap < need) cap *= 2;
        if (cap > OT_CHAIN_BYTES) cap = OT_CHAIN_BYTES;
        if (!(n = ot_alloc(cap))) {
            x->chain_ok = 0;
            return;
        }
        if (x->chain_len) memcpy(n, x->chain, x->chain_len);
        ot_free(x->chain);
        x->chain = n;
        x->chain_cap = cap;
    }
    x->chain_off[x->chain_count] = x->chain_len;
    x->chain_end[x->chain_count] = x->chain_len;
    x->chain_want[x->chain_count] = length;
    ++x->chain_count;
}

static void chain_append(struct ot_x509 *x, const unsigned char *buf, size_t len)
{
    int i = x->chain_count - 1;
    if (!x->chain_ok || i < 0) return;
    if (x->chain_end[i] - x->chain_off[i] + len > x->chain_want[i]) {
        x->chain_ok = 0;
        return;
    }
    memcpy(x->chain + x->chain_end[i], buf, len);
    x->chain_end[i] += len;
    x->chain_len = x->chain_end[i];
}

/* the minimal engine checks DNS names only: none for an address, none
 * when the caller turned the check off, none for an Ed25519 leaf's CA */
static void inner_start(struct ot_x509 *x, const char *name)
{
    if (x->inner_started) return;
    (*INNER(x))->start_chain(INNER(x), name);
    x->inner_started = 1;
}

static void xw_start_cert(const br_x509_class **ctx, uint32_t length)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    chain_start(x, length);
    if (++x->cert_index == 0) {
        br_x509_decoder_init(&x->leaf_decoder, NULL, NULL);
        br_sha256_init(&x->leaf_hash);
        x->leaf_len = 0;
        x->leaf_ok = 1;
        if (length > x->leaf_cap) {
            ot_free(x->leaf);
            x->leaf = NULL;
            x->leaf_cap = 0;
            if (length <= OT_LEAF_MAX && (x->leaf = ot_alloc(length)))
                x->leaf_cap = length;
        }
        if (length > x->leaf_cap) x->leaf_ok = 0;
        /* a leaf kept whole goes to the engine at its end, once its key
         * type is known (TLS 1.3 only: BearSSL's handshake wants it streamed) */
        x->deferred = x->tls13 && x->leaf_ok;
        if (x->deferred) return;
        inner_start(x, INNER_NAME(x));
    } else if (x->cert_index == 1 && x->leaf_ed25519) {
        x->issuer_len = 0;
        x->issuer_ok = 0;
        if (length > x->issuer_cap) {
            ot_free(x->issuer);
            x->issuer_cap = 0;
            if (length <= OT_LEAF_MAX && (x->issuer = ot_alloc(length))) x->issuer_cap = length;
        }
        x->issuer_ok = length <= x->issuer_cap;
    }
    (*INNER(x))->start_cert(INNER(x), length);
}

static void xw_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    chain_append(x, buf, len);
    if (x->cert_index == 0) {
        br_sha256_update(&x->leaf_hash, buf, len);
        br_x509_decoder_push(&x->leaf_decoder, buf, len);
        if (x->leaf_ok && x->leaf_len + len <= x->leaf_cap) {
            memcpy(x->leaf + x->leaf_len, buf, len);
            x->leaf_len += len;
        } else {
            x->leaf_ok = 0;
        }
        if (x->deferred) return;
    } else if (x->cert_index == 1 && x->leaf_ed25519) {
        if (x->issuer_ok && x->issuer_len + len <= x->issuer_cap) {
            memcpy(x->issuer + x->issuer_len, buf, len);
            x->issuer_len += len;
        } else {
            x->issuer_ok = 0;
        }
    }
    (*INNER(x))->append(INNER(x), buf, len);
}

static void xw_end_cert(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->cert_index == 0) {
        struct leaf_parts lp;
        br_sha256_out(&x->leaf_hash, x->fingerprint);
        x->have_fingerprint = 1;
        if (x->deferred) {
            if (x->leaf_ok && leaf_parse(x->leaf, x->leaf_len, &lp) && spki_ed25519(&lp.spki, x->ed25519)) {
                x->leaf_ed25519 = 1;
                inner_start(x, NULL);          /* from the next certificate */
                return;
            }
            inner_start(x, INNER_NAME(x));
            (*INNER(x))->start_cert(INNER(x), (uint32_t)x->leaf_len);
            (*INNER(x))->append(INNER(x), x->leaf, x->leaf_len);
        }
    }
    (*INNER(x))->end_cert(INNER(x));
}

/* the verdict of the full checks (chain, dates, name), 0 when they pass */
static unsigned full_checks(struct ot_x509 *x)
{
    struct OTConnection *c = x->conn;
    unsigned err;
    if (x->leaf_ed25519) return ed25519_leaf_check(x);
    err = (*INNER(x))->end_chain(INNER(x));
    if (err) return err;
    if (c->ip_len && CHECKS_NAME(c)
        && !(x->leaf_ok && ot_cert_has_ip(x->leaf, x->leaf_len, c->ip, (size_t)c->ip_len)))
        return OT_X509_IP;
    return 0;
}

static unsigned xw_end_chain(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    unsigned err;
    int leaf_key, pin_ok;

    inner_start(x, INNER_NAME(x));
    leaf_key = x->have_fingerprint
        && (x->leaf_ed25519 || br_x509_decoder_get_pkey(&x->leaf_decoder) != NULL);
    pin_ok = c->pinned && leaf_key && !memcmp(x->fingerprint, c->pin, 32);

    /* OTV_REPORT: the checks OTV_FULL makes, kept for OT_GetVerifyResult();
     * the handshake goes on with the server's key whatever they say */
    if (c->verify == OTV_REPORT) {
        err = pin_ok ? 0 : full_checks(x);
        x->verdict = (int)err;
        if (!leaf_key) return err ? err : BR_ERR_X509_INVALID_VALUE;
        x->accepted = 1;
        return 0;
    }
    if (pin_ok) {
        x->accepted = 1;     /* the caller trusts exactly this certificate */
        x->verdict = 0;
        return 0;
    }
    if (c->verify == OTV_PINNED_ONLY) {
        x->verdict = OT_X509_PINNED;
        return OT_X509_PINNED;
    }
    if (c->verify == OTV_NONE) {
        if (!x->leaf_ed25519) err = (*INNER(x))->end_chain(INNER(x));
        else err = 0;
        if (!leaf_key) {
            x->verdict = (int)(err ? err : BR_ERR_X509_INVALID_VALUE);
            return (unsigned)x->verdict;
        }
        x->accepted = 1;
        x->verdict = 0;
        return 0;
    }
    err = full_checks(x);
    x->verdict = (int)err;
    return err;
}

static const br_x509_pkey *xw_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->leaf_ed25519) {
        if (usages) *usages = BR_KEYTYPE_SIGN;
        return NULL;            /* the key is x->ed25519 */
    }
    if (x->accepted) {
        if (usages) *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
        return br_x509_decoder_get_pkey(&x->leaf_decoder);
    }
    return (*INNER(x))->get_pkey((const br_x509_class *const *)INNER(x), usages);
}

static const br_x509_class ot_x509_vtable = {
    sizeof(struct ot_x509),
    xw_start_chain, xw_start_cert, xw_append, xw_end_cert, xw_end_chain, xw_get_pkey
};

void ot_x509_init(struct ot_x509 *x, struct OTConnection *conn,
                  const struct ot_impls *m,
                  const br_x509_trust_anchor *ta, size_t ta_count)
{
    uint32_t days, seconds;
    x->vtable = &ot_x509_vtable;
    x->conn = conn;
    x->impls = m;
    x->ta = ta;
    x->ta_count = ta_count;
    x->tls13 = 0;
    br_x509_minimal_init(&x->minimal, m->sha256, ta, ta_count);
    br_x509_minimal_set_hash(&x->minimal, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(&x->minimal, br_sha224_ID, &br_sha224_vtable);
    br_x509_minimal_set_hash(&x->minimal, br_sha256_ID, m->sha256);
    br_x509_minimal_set_hash(&x->minimal, br_sha384_ID, m->sha384);
    br_x509_minimal_set_hash(&x->minimal, br_sha512_ID, m->sha512);
    br_x509_minimal_set_rsa(&x->minimal, m->rsa_vrfy);
    br_x509_minimal_set_ecdsa(&x->minimal, m->ec, m->ecdsa_vrfy);
    if (ot_now(&days, &seconds)) br_x509_minimal_set_time(&x->minimal, days, seconds);
}

void ot_x509_free(struct ot_x509 *x)
{
    ot_free(x->leaf);
    x->leaf = NULL;
    x->leaf_cap = x->leaf_len = 0;
    ot_free(x->issuer);
    x->issuer = NULL;
    x->issuer_cap = x->issuer_len = 0;
    ot_free(x->chain);
    x->chain = NULL;
    x->chain_cap = x->chain_len = 0;
    x->chain_count = 0;
}

/* ---- certificate fields (OT_CertInfo, OT_CertAltName), 6 November 2026 ----
 * What a program shows of a certificate: names (RFC 4514 strings), dates,
 * serial, key and signature algorithms, alternative names, fingerprints.
 * Reading only: nothing here decides trust. */

struct sbuf { char *p; size_t size, len; };

static void sb_putc(struct sbuf *b, char ch)
{
    if (b->len + 1 < b->size) {
        b->p[b->len++] = ch;
        b->p[b->len] = 0;
    }
}

static void sb_puts(struct sbuf *b, const char *s)
{
    while (*s) sb_putc(b, *s++);
}

static void sb_hex(struct sbuf *b, unsigned v)
{
    static const char hx[] = "0123456789abcdef";
    sb_putc(b, hx[(v >> 4) & 15]);
    sb_putc(b, hx[v & 15]);
}

static void sb_num(struct sbuf *b, unsigned long v)
{
    char t[12];
    int i = 0;
    do { t[i++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (i) sb_putc(b, t[--i]);
}

/* an OID's dotted form */
static void sb_oid(struct sbuf *b, const struct der *o)
{
    size_t i;
    unsigned long v = 0;
    int first = 1;
    for (i = 0; i < o->len; ++i) {
        v = (v << 7) | (o->p[i] & 0x7F);
        if (o->p[i] & 0x80) continue;
        if (first) {
            unsigned long a = v < 40 ? 0 : v < 80 ? 1 : 2;
            sb_num(b, a);
            sb_putc(b, '.');
            sb_num(b, v - 40 * a);
            first = 0;
        } else {
            sb_putc(b, '.');
            sb_num(b, v);
        }
        v = 0;
    }
}

static int oid_is(const struct der *o, const unsigned char *id, size_t n)
{
    return o->len == n && !memcmp(o->p, id, n);
}

/* a code point as UTF-8 */
static void sb_utf8(struct sbuf *b, unsigned long cp)
{
    if (cp < 0x80) sb_putc(b, (char)cp);
    else if (cp < 0x800) { sb_putc(b, (char)(0xC0 | cp >> 6)); sb_putc(b, (char)(0x80 | (cp & 63))); }
    else if (cp < 0x10000) {
        sb_putc(b, (char)(0xE0 | cp >> 12)); sb_putc(b, (char)(0x80 | ((cp >> 6) & 63)));
        sb_putc(b, (char)(0x80 | (cp & 63)));
    } else {
        sb_putc(b, (char)(0xF0 | cp >> 18)); sb_putc(b, (char)(0x80 | ((cp >> 12) & 63)));
        sb_putc(b, (char)(0x80 | ((cp >> 6) & 63))); sb_putc(b, (char)(0x80 | (cp & 63)));
    }
}

/* an attribute value, escaped as RFC 4514 section 2.4 says */
static void sb_value(struct sbuf *b, unsigned tag, const struct der *v)
{
    size_t i, start = b->len, step = tag == 0x1E ? 2 : tag == 0x1C ? 4 : 1;
    if (tag & 0x100 || (tag != 0x0C && tag != 0x13 && tag != 0x16 && tag != 0x14 && tag != 0x1E
        && tag != 0x1C && tag != 0x1A)) {
        sb_putc(b, '#');                    /* RFC 4514: an unknown type's value as hex DER */
        sb_hex(b, tag & 0xFF);
        sb_hex(b, (unsigned)v->len);
        for (i = 0; i < v->len; ++i) sb_hex(b, v->p[i]);
        return;
    }
    for (i = 0; i + step <= v->len; i += step) {
        unsigned long cp;
        if (step == 2) cp = (unsigned long)v->p[i] << 8 | v->p[i + 1];
        else if (step == 4) cp = (unsigned long)v->p[i] << 24 | (unsigned long)v->p[i + 1] << 16
                               | (unsigned long)v->p[i + 2] << 8 | v->p[i + 3];
        else cp = v->p[i];
        if (step == 1 && tag == 0x14 && cp >= 0x80) {    /* T61String: taken as Latin-1 */
            sb_utf8(b, cp);
            continue;
        }
        if (cp == 0) { sb_puts(b, "\\00"); continue; }
        if (cp == ',' || cp == '+' || cp == '"' || cp == '\\' || cp == '<' || cp == '>' || cp == ';'
            || ((cp == '#' || cp == ' ') && b->len == start)
            || (cp == ' ' && i + step >= v->len))
            sb_putc(b, '\\');
        if (step == 1) sb_putc(b, (char)cp);        /* UTF-8 bytes pass through */
        else sb_utf8(b, cp);
    }
}

static const struct { unsigned char oid[10]; unsigned char len; const char *name; } attr_names[] = {
    { { 0x55, 0x04, 0x03 }, 3, "CN" },
    { { 0x55, 0x04, 0x07 }, 3, "L" },
    { { 0x55, 0x04, 0x08 }, 3, "ST" },
    { { 0x55, 0x04, 0x0A }, 3, "O" },
    { { 0x55, 0x04, 0x0B }, 3, "OU" },
    { { 0x55, 0x04, 0x06 }, 3, "C" },
    { { 0x55, 0x04, 0x09 }, 3, "STREET" },
    { { 0x55, 0x04, 0x05 }, 3, "serialNumber" },
    { { 0x55, 0x04, 0x2A }, 3, "GN" },
    { { 0x55, 0x04, 0x04 }, 3, "SN" },
    { { 0x55, 0x04, 0x0C }, 3, "title" },
    { { 0x55, 0x04, 0x61 }, 3, "organizationIdentifier" },
    { { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 }, 10, "DC" },
    { { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01 }, 10, "UID" },
    { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 }, 9, "EMAIL" },
};

/* a Name (whole: tag and length too) as RFC 4514: the last RDN first */
static void name_string(const struct der *whole, char *out, size_t size)
{
    struct der d = *whole, seq, rdns[32];
    struct sbuf b;
    unsigned tag;
    int n = 0, i;
    b.p = out; b.size = size; b.len = 0;
    if (size) out[0] = 0;
    if (!der_next(&d, &tag, &seq) || tag != 0x30) return;
    while (n < 32 && der_next(&seq, &tag, &rdns[n]))
        if (tag == 0x31) ++n;
    for (i = n - 1; i >= 0; --i) {
        struct der set = rdns[i], atv, oid, val;
        int first = 1;
        if (i != n - 1) sb_putc(&b, ',');
        while (der_next(&set, &tag, &atv)) {
            size_t k;
            const char *nm = NULL;
            if (tag != 0x30 || !der_next(&atv, &tag, &oid) || tag != 0x06) continue;
            if (!der_next(&atv, &tag, &val)) continue;
            if (!first) sb_putc(&b, '+');
            first = 0;
            for (k = 0; k < sizeof attr_names / sizeof attr_names[0]; ++k)
                if (oid_is(&oid, attr_names[k].oid, attr_names[k].len)) nm = attr_names[k].name;
            if (nm) sb_puts(&b, nm);
            else sb_oid(&b, &oid);
            sb_putc(&b, '=');
            sb_value(&b, nm ? tag : 0x100 | tag, &val);
        }
    }
}

static int two(const unsigned char *p) { return (p[0] - '0') * 10 + (p[1] - '0'); }

static int cert_time(const struct der *v, unsigned tag, struct OTCertTime *t)
{
    const unsigned char *p = v->p;
    size_t i, n = tag == 0x17 ? 12 : 14;
    int year;
    if ((tag != 0x17 && tag != 0x18) || v->len < n + 1 || p[n] != 'Z') return 0;
    for (i = 0; i < n; ++i) if (p[i] < '0' || p[i] > '9') return 0;
    if (tag == 0x17) {
        year = two(p);
        year += year < 50 ? 2000 : 1900;
        p += 2;
    } else {
        year = two(p) * 100 + two(p + 2);
        p += 4;
    }
    t->Year = (UWORD)year;
    t->Month = (UBYTE)two(p);
    t->Day = (UBYTE)two(p + 2);
    t->Hour = (UBYTE)two(p + 4);
    t->Minute = (UBYTE)two(p + 6);
    t->Second = (UBYTE)two(p + 8);
    t->Pad = 0;
    return t->Month >= 1 && t->Month <= 12 && t->Day >= 1 && t->Day <= 31;
}

/* a big-endian INTEGER's bit length */
static LONG int_bits(const struct der *v)
{
    size_t i = 0;
    LONG bits;
    unsigned top;
    while (i < v->len && !v->p[i]) ++i;
    if (i == v->len) return 0;
    bits = (LONG)(8 * (v->len - i - 1));
    for (top = v->p[i]; top; top >>= 1) ++bits;
    return bits;
}

static void key_info(const struct der *spki, struct OTCertInfo *info)
{
    static const unsigned char rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    static const unsigned char rsapss[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
    static const unsigned char ecpk[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    static const unsigned char dsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };
    static const unsigned char p256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const unsigned char p384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
    static const unsigned char p521[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };
    static const unsigned char ed25519[] = { 0x2B, 0x65, 0x70 };
    static const unsigned char ed448[] = { 0x2B, 0x65, 0x71 };
    struct der s = *spki, alg, oid, param, bits;
    unsigned tag;
    struct sbuf b;
    b.p = info->KeyAlgorithm; b.size = sizeof info->KeyAlgorithm; b.len = 0;
    info->KeyAlgorithm[0] = 0;
    info->KeyCurve[0] = 0;
    info->KeyBits = 0;
    if (!der_next(&s, &tag, &alg) || tag != 0x30 || !der_next(&alg, &tag, &oid) || tag != 0x06) return;
    if (!der_next(&s, &tag, &bits) || tag != 0x03 || bits.len < 1) return;
    ++bits.p; --bits.len;                       /* past the unused-bits count */
    if (oid_is(&oid, rsa, sizeof rsa) || oid_is(&oid, rsapss, sizeof rsapss)) {
        struct der k = bits, seq, n;
        sb_puts(&b, oid_is(&oid, rsa, sizeof rsa) ? "RSA" : "RSA-PSS");
        if (der_next(&k, &tag, &seq) && tag == 0x30 && der_next(&seq, &tag, &n) && tag == 0x02)
            info->KeyBits = int_bits(&n);
    } else if (oid_is(&oid, ecpk, sizeof ecpk)) {
        sb_puts(&b, "ECDSA");
        if (der_next(&alg, &tag, &param) && tag == 0x06) {
            const char *cv = oid_is(&param, p256, sizeof p256) ? "secp256r1"
                           : oid_is(&param, p384, sizeof p384) ? "secp384r1"
                           : oid_is(&param, p521, sizeof p521) ? "secp521r1" : NULL;
            ot_strlcpy(info->KeyCurve, cv ? cv : "", sizeof info->KeyCurve);
            info->KeyBits = cv ? (cv[4] == '2' && cv[5] == '5' ? 256 : cv[4] == '3' ? 384 : 521) : 0;
            if (!cv) {
                struct sbuf cb;
                cb.p = info->KeyCurve; cb.size = sizeof info->KeyCurve; cb.len = 0;
                sb_oid(&cb, &param);
            }
        }
    } else if (oid_is(&oid, ed25519, sizeof ed25519)) {
        sb_puts(&b, "Ed25519");
        info->KeyBits = 256;
    } else if (oid_is(&oid, ed448, sizeof ed448)) {
        sb_puts(&b, "Ed448");
        info->KeyBits = 456;
    } else if (oid_is(&oid, dsa, sizeof dsa)) {
        struct der pq, p;
        sb_puts(&b, "DSA");
        if (der_next(&alg, &tag, &pq) && tag == 0x30 && der_next(&pq, &tag, &p) && tag == 0x02)
            info->KeyBits = int_bits(&p);
    } else {
        sb_oid(&b, &oid);
    }
}

static void sig_name(const struct der *oid, char *out, size_t size)
{
    static const struct { unsigned char oid[9]; unsigned char len; const char *name; } sigs[] = {
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 }, 9, "RSA-MD5" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 }, 9, "RSA-SHA1" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }, 9, "RSA-SHA256" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C }, 9, "RSA-SHA384" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D }, 9, "RSA-SHA512" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E }, 9, "RSA-SHA224" },
        { { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A }, 9, "RSA-PSS" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01 }, 7, "ECDSA-SHA1" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01 }, 8, "ECDSA-SHA224" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 }, 8, "ECDSA-SHA256" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 }, 8, "ECDSA-SHA384" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 }, 8, "ECDSA-SHA512" },
        { { 0x2B, 0x65, 0x70 }, 3, "Ed25519" },
        { { 0x2B, 0x65, 0x71 }, 3, "Ed448" },
        { { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03 }, 7, "DSA-SHA1" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02 }, 9, "DSA-SHA256" },
    };
    size_t i;
    struct sbuf b;
    for (i = 0; i < sizeof sigs / sizeof sigs[0]; ++i)
        if (oid_is(oid, sigs[i].oid, sigs[i].len)) {
            ot_strlcpy(out, sigs[i].name, size);
            return;
        }
    b.p = out; b.size = size; b.len = 0;
    if (size) out[0] = 0;
    sb_oid(&b, oid);
}

/* the serial and version: TBSCertificate's first fields */
static void serial_version(const unsigned char *der, size_t len, struct OTCertInfo *info)
{
    struct der tbs, e, v;
    unsigned tag;
    info->Version = 1;
    info->SerialLength = 0;
    if (!der_tbs(der, len, &tbs) || !der_next(&tbs, &tag, &e)) return;
    if (tag == 0xA0) {
        if (der_next(&e, &tag, &v) && tag == 0x02 && v.len == 1) info->Version = v.p[0] + 1;
        if (!der_next(&tbs, &tag, &e)) return;
    }
    if (tag != 0x02) return;
    if (e.len > 1 && !e.p[0]) { ++e.p; --e.len; }   /* the sign byte */
    if (e.len > sizeof info->Serial) e.len = sizeof info->Serial;
    memcpy(info->Serial, e.p, e.len);
    info->SerialLength = (LONG)e.len;
}

/* the subjectAltName's GeneralNames: the index-th of the kinds shown */
static LONG alt_name(const unsigned char *der, size_t len, LONG index, struct sbuf *b)
{
    struct der names, g;
    unsigned tag;
    LONG i = 0;
    if (!der_san(der, len, &names)) return 0;
    while (der_next(&names, &tag, &g)) {
        LONG kind = tag == 0x82 ? OT_ALT_DNS : tag == 0x87 ? OT_ALT_IP
                  : tag == 0x81 ? OT_ALT_EMAIL : tag == 0x86 ? OT_ALT_URI : 0;
        size_t k;
        if (!kind || (kind == OT_ALT_IP && g.len != 4 && g.len != 16)) continue;
        if (i++ != index) continue;
        if (!b) return kind;
        if (kind == OT_ALT_IP && g.len == 4) {
            for (k = 0; k < 4; ++k) {
                if (k) sb_putc(b, '.');
                sb_num(b, g.p[k]);
            }
        } else if (kind == OT_ALT_IP) {
            /* RFC 5952: the longest run of two or more zero words (the first, on a tie) as "::" */
            unsigned w[8];
            int best = -1, bestlen = 1, run, j, sh;
            static const char hx[] = "0123456789abcdef";
            for (j = 0; j < 8; ++j) w[j] = (unsigned)g.p[2 * j] << 8 | g.p[2 * j + 1];
            for (j = 0; j < 8; j += run ? run : 1) {
                for (run = 0; j + run < 8 && !w[j + run]; ++run) {}
                if (run > bestlen) { best = j; bestlen = run; }
            }
            for (j = 0; j < 8; ++j) {
                int started = 0;
                if (j == best) {
                    sb_puts(b, "::");
                    j += bestlen - 1;
                    continue;
                }
                if (j && j != best + bestlen) sb_putc(b, ':');
                for (sh = 12; sh >= 0; sh -= 4) {
                    unsigned d = (w[j] >> sh) & 15;
                    if (d || started || !sh) { sb_putc(b, hx[d]); started = 1; }
                }
            }
        } else {
            for (k = 0; k < g.len; ++k) sb_putc(b, (char)g.p[k]);
        }
        return kind;
    }
    return 0;
}

LONG OT_CertInfo(CONST_APTR der, LONG length, struct OTCertInfo *info)
{
    struct leaf_parts lp;
    struct der val;
    unsigned tag;
    const unsigned char *d = (const unsigned char *)der;
    size_t len = (size_t)length;
    LONG n;
    if (!der || length <= 0 || !info || info->Size < sizeof(struct OTCertInfo)) return OTERR_ARGS;
    memset((char *)info + sizeof info->Size, 0, sizeof *info - sizeof info->Size);
    if (!leaf_parse(d, len, &lp)) return OTERR_BADCERT;
    serial_version(d, len, info);
    name_string(&lp.subject, info->Subject, sizeof info->Subject);
    name_string(&lp.issuer, info->Issuer, sizeof info->Issuer);
    val = lp.validity;
    {
        struct der t;
        if (!der_next(&val, &tag, &t) || !cert_time(&t, tag, &info->NotBefore)) return OTERR_BADCERT;
        if (!der_next(&val, &tag, &t) || !cert_time(&t, tag, &info->NotAfter)) return OTERR_BADCERT;
    }
    key_info(&lp.spki, info);
    sig_name(&lp.sigalg, info->SignatureAlgorithm, sizeof info->SignatureAlgorithm);
    info->SelfSigned = lp.subject.len == lp.issuer.len && !memcmp(lp.subject.p, lp.issuer.p, lp.subject.len);
    for (n = 0; alt_name(d, len, n, NULL); ++n) {}
    info->AltNameCount = n;
    {
        br_sha256_context h2;
        br_sha1_context h1;
        br_sha256_init(&h2);
        br_sha256_update(&h2, d, len);
        br_sha256_out(&h2, info->SHA256);
        br_sha1_init(&h1);
        br_sha1_update(&h1, d, len);
        br_sha1_out(&h1, info->SHA1);
    }
    return OTERR_OK;
}

LONG OT_CertAltName(CONST_APTR der, LONG length, LONG index, STRPTR buffer, LONG size)
{
    struct sbuf b;
    if (!der || length <= 0 || index < 0 || !buffer || size < 1) return OTERR_ARGS;
    b.p = (char *)buffer; b.size = (size_t)size; b.len = 0;
    buffer[0] = 0;
    return alt_name((const unsigned char *)der, (size_t)length, index, &b);
}
