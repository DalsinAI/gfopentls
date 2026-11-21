/* GFOpenTLS: certificate checks, our own since 1.8 (the chain, the
 * signatures, dates, constraints, names and addresses), and what GFOpenTLS
 * promises on top: the server's certificate and its SHA-256 fingerprint
 * kept for the caller, pinned certificates and the verify modes.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"
#include <gfopencrypto/gfopencrypto.h>

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

/* ---- the chain check ----
 *
 * RFC 5280's path validation, as far as a TLS client needs it. From the
 * server's certificate, each issuer is looked for first among the trust
 * anchors (by name, then its key checks the signature), then among the
 * other certificates the server sent, in any order. A CA on the way
 * needs basicConstraints with cA, a pathLenConstraint that allows the
 * CAs below it, keyCertSign when it has a keyUsage, and its dates. The
 * server's certificate needs its dates, serverAuth when it has an
 * extendedKeyUsage, and the host name (subjectAltName dNSName, or the
 * subject's CN when there are none) or the address. An unknown critical
 * extension fails, as do name and policy constraints, which are not
 * implemented. Signatures: RSA PKCS #1 v1.5 (SHA-1, SHA-256, SHA-384,
 * SHA-512), RSA-PSS, ECDSA on P-256, P-384 and P-521, and Ed25519; on the
 * services card when there is one. RSA keys from 1024 to 8192 bits. */

/* the next element whole (tag and length too): where it starts and ends */
static int der_whole(struct der *d, unsigned *tag, struct der *content, struct der *whole)
{
    const unsigned char *start = d->p;
    if (!der_next(d, tag, content)) return 0;
    whole->p = start;
    whole->len = (size_t)(d->p - start);
    return 1;
}

static int same(const struct der *d, const unsigned char *p, size_t n)
{
    return d->len == n && !memcmp(d->p, p, n);
}

struct leaf_parts {
    struct der tbs;          /* whole, for the signature */
    struct der issuer;       /* whole */
    struct der validity;     /* contents */
    struct der subject;      /* whole */
    struct der spki;         /* whole */
    struct der exts;         /* contents of the SEQUENCE in [3], or empty */
    struct der sigalg;       /* the outer AlgorithmIdentifier's contents: OID, parameters */
    struct der sig;          /* the BIT STRING's bytes, past the unused-bits count */
};

static int leaf_parse(const unsigned char *der, size_t len, struct leaf_parts *lp)
{
    struct der d, cert, tbs, e, w;
    unsigned tag;
    int field = 0;
    memset(lp, 0, sizeof *lp);
    d.p = der;
    d.len = len;
    if (!der_next(&d, &tag, &cert) || tag != 0x30 || d.len) return 0;
    if (!der_whole(&cert, &tag, &tbs, &lp->tbs) || tag != 0x30) return 0;
    while (der_whole(&tbs, &tag, &e, &w)) {
        if (tag == 0xA0 && field == 0) continue;            /* version */
        switch (field++) {
        case 2: lp->issuer = w; break;
        case 3: lp->validity = e; break;
        case 4: lp->subject = w; break;
        case 5: lp->spki = w; break;
        default:
            if (tag == 0xA3) {
                struct der x;
                if (!der_next(&e, &tag, &x) || tag != 0x30) return 0;
                lp->exts = x;
            }
            break;
        }
    }
    if (field < 6 || tbs.len) return 0;
    if (!der_next(&cert, &tag, &lp->sigalg) || tag != 0x30) return 0;
    if (!der_next(&cert, &tag, &lp->sig) || tag != 0x03 || lp->sig.len < 2 || lp->sig.p[0]) return 0;
    ++lp->sig.p;
    --lp->sig.len;
    return !cert.len;
}

static const unsigned char oid_rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const unsigned char oid_ec[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const unsigned char oid_p256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const unsigned char oid_p384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const unsigned char oid_p521[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };
static const unsigned char oid_ed25519[] = { 0x2B, 0x65, 0x70 };

/* an INTEGER's value without its leading zeros */
static int read_uint(struct der *d, struct der *v)
{
    unsigned tag;
    if (!der_next(d, &tag, v) || tag != 0x02 || !v->len || (v->p[0] & 0x80)) return 0;
    while (v->len && !v->p[0]) { ++v->p; --v->len; }
    return v->len != 0;
}

static unsigned key_read(const struct der *spki, struct ot_key *k)
{
    struct der d = *spki, s, alg, oid, bits, curve;
    unsigned tag;
    memset(k, 0, sizeof *k);
    if (!der_next(&d, &tag, &s) || tag != 0x30) return BR_ERR_X509_INVALID_VALUE;
    if (!der_next(&s, &tag, &alg) || tag != 0x30 || !der_next(&alg, &tag, &oid) || tag != 0x06)
        return BR_ERR_X509_INVALID_VALUE;
    if (!der_next(&s, &tag, &bits) || tag != 0x03 || bits.len < 2 || bits.p[0]) return BR_ERR_X509_INVALID_VALUE;
    ++bits.p;
    --bits.len;
    k->spki = spki->p;
    k->spki_len = spki->len;
    if (same(&oid, oid_ed25519, sizeof oid_ed25519)) {
        if (bits.len != 32) return BR_ERR_X509_INVALID_VALUE;
        k->type = OT_KEY_ED25519;
        k->ed = bits.p;
        return 0;
    }
    if (same(&oid, oid_rsa, sizeof oid_rsa)) {
        struct der seq, n, e;
        if (!der_next(&bits, &tag, &seq) || tag != 0x30 || !read_uint(&seq, &n) || !read_uint(&seq, &e))
            return BR_ERR_X509_INVALID_VALUE;
        if (n.len < 128) return BR_ERR_X509_WEAK_PUBLIC_KEY;
        if (n.len > OC_RSA_MAX_BYTES || e.len > 8) return BR_ERR_X509_LIMIT_EXCEEDED;
        k->type = BR_KEYTYPE_RSA;
        k->pk.key_type = BR_KEYTYPE_RSA;
        k->pk.key.rsa.n = (unsigned char *)n.p;
        k->pk.key.rsa.nlen = n.len;
        k->pk.key.rsa.e = (unsigned char *)e.p;
        k->pk.key.rsa.elen = e.len;
        return 0;
    }
    if (same(&oid, oid_ec, sizeof oid_ec)) {
        int c;
        size_t plen;
        if (!der_next(&alg, &tag, &curve) || tag != 0x06) return BR_ERR_X509_UNSUPPORTED;
        if (same(&curve, oid_p256, sizeof oid_p256)) { c = BR_EC_secp256r1; plen = 65; }
        else if (same(&curve, oid_p384, sizeof oid_p384)) { c = BR_EC_secp384r1; plen = 97; }
        else if (same(&curve, oid_p521, sizeof oid_p521)) { c = BR_EC_secp521r1; plen = 133; }
        else return BR_ERR_X509_UNSUPPORTED;
        if (bits.len != plen || bits.p[0] != 4) return BR_ERR_X509_INVALID_VALUE;
        k->type = BR_KEYTYPE_EC;
        k->pk.key_type = BR_KEYTYPE_EC;
        k->pk.key.ec.curve = c;
        k->pk.key.ec.q = (unsigned char *)bits.p;
        k->pk.key.ec.qlen = plen;
        return 0;
    }
    return BR_ERR_X509_UNSUPPORTED;
}

/* DER: a tag and length at p (when p), and their size */
static size_t put_head(unsigned char *p, unsigned tag, size_t len)
{
    size_t n = len < 0x80 ? 2 : len < 0x100 ? 3 : 4;
    if (p) {
        p[0] = (unsigned char)tag;
        if (n == 2) p[1] = (unsigned char)len;
        else if (n == 3) { p[1] = 0x81; p[2] = (unsigned char)len; }
        else { p[1] = 0x82; p[2] = (unsigned char)(len >> 8); p[3] = (unsigned char)len; }
    }
    return n;
}

static size_t put_bytes(unsigned char *p, const unsigned char *d, size_t len)
{
    if (p) memcpy(p, d, len);
    return len;
}

static size_t put_uint(unsigned char *p, const unsigned char *v, size_t len)
{
    size_t pad = v[0] & 0x80 ? 1 : 0, n = put_head(p, 0x02, len + pad);
    if (p && pad) p[n] = 0;
    put_bytes(p ? p + n + pad : NULL, v, len);
    return n + pad + len;
}

/* an anchor's key as a SubjectPublicKeyInfo (to out when out; its length) */
static size_t anchor_spki(const br_x509_pkey *pk, unsigned char *out)
{
    unsigned char *p = out;
    size_t keylen, alglen, inner, n;
#define AT(o) (out ? out + (o) : NULL)
    if (pk->key_type == BR_KEYTYPE_RSA) {
        size_t nl = put_uint(NULL, pk->key.rsa.n, pk->key.rsa.nlen);
        size_t el = put_uint(NULL, pk->key.rsa.e, pk->key.rsa.elen);
        inner = put_head(NULL, 0x30, nl + el) + nl + el;
        keylen = put_head(NULL, 0x03, inner + 1) + 1 + inner;
        alglen = 2 + sizeof oid_rsa + 2;
        n = put_head(p, 0x30, put_head(NULL, 0x30, alglen) + alglen + keylen);
        n += put_head(AT(n), 0x30, alglen);
        n += put_head(AT(n), 0x06, sizeof oid_rsa);
        n += put_bytes(AT(n), oid_rsa, sizeof oid_rsa);
        n += put_head(AT(n), 0x05, 0);
        n += put_head(AT(n), 0x03, inner + 1);
        if (out) out[n] = 0;
        ++n;
        n += put_head(AT(n), 0x30, nl + el);
        n += put_uint(AT(n), pk->key.rsa.n, pk->key.rsa.nlen);
        n += put_uint(AT(n), pk->key.rsa.e, pk->key.rsa.elen);
        return n;
    }
    if (pk->key_type == BR_KEYTYPE_EC) {
        const unsigned char *c = pk->key.ec.curve == BR_EC_secp256r1 ? oid_p256
                               : pk->key.ec.curve == BR_EC_secp384r1 ? oid_p384 : oid_p521;
        size_t cl = pk->key.ec.curve == BR_EC_secp256r1 ? sizeof oid_p256 : sizeof oid_p384;
        if (pk->key.ec.curve != BR_EC_secp256r1 && pk->key.ec.curve != BR_EC_secp384r1
            && pk->key.ec.curve != BR_EC_secp521r1) return 0;
        alglen = 2 + sizeof oid_ec + 2 + cl;
        keylen = put_head(NULL, 0x03, pk->key.ec.qlen + 1) + 1 + pk->key.ec.qlen;
        n = put_head(p, 0x30, put_head(NULL, 0x30, alglen) + alglen + keylen);
        n += put_head(AT(n), 0x30, alglen);
        n += put_head(AT(n), 0x06, sizeof oid_ec);
        n += put_bytes(AT(n), oid_ec, sizeof oid_ec);
        n += put_head(AT(n), 0x06, cl);
        n += put_bytes(AT(n), c, cl);
        n += put_head(AT(n), 0x03, pk->key.ec.qlen + 1);
        if (out) out[n] = 0;
        ++n;
        n += put_bytes(AT(n), pk->key.ec.q, pk->key.ec.qlen);
        return n;
    }
#undef AT
    return 0;
}

static int same_key(const struct ot_key *k, const br_x509_pkey *pk)
{
    if (k->type != pk->key_type) return 0;
    if (k->type == BR_KEYTYPE_RSA)
        return k->pk.key.rsa.nlen == pk->key.rsa.nlen && !memcmp(k->pk.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen)
            && k->pk.key.rsa.elen == pk->key.rsa.elen && !memcmp(k->pk.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
    if (k->type == BR_KEYTYPE_EC)
        return k->pk.key.ec.curve == pk->key.ec.curve && k->pk.key.ec.qlen == pk->key.ec.qlen
            && !memcmp(k->pk.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
    return 0;
}

static const br_hash_class *hash_by_oid(const struct der *oid, const unsigned char **hoid)
{
    static const unsigned char sha2[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02 };
    static const unsigned char sha1[] = { 0x2B, 0x0E, 0x03, 0x02, 0x1A };
    if (same(oid, sha1, sizeof sha1)) { *hoid = BR_HASH_OID_SHA1; return &br_sha1_vtable; }
    if (oid->len != sizeof sha2 + 1 || memcmp(oid->p, sha2, sizeof sha2)) return NULL;
    switch (oid->p[sizeof sha2]) {
    case 1: *hoid = BR_HASH_OID_SHA256; return &br_sha256_vtable;
    case 2: *hoid = BR_HASH_OID_SHA384; return &br_sha384_vtable;
    case 3: *hoid = BR_HASH_OID_SHA512; return &br_sha512_vtable;
    }
    return NULL;
}

/* RSASSA-PSS-params: the hash (MGF1 must use the same) and the salt length */
static const br_hash_class *pss_params(struct der params, size_t *salt)
{
    static const unsigned char mgf1[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };
    struct der seq, f, alg, oid, mgfhash;
    const br_hash_class *h = &br_sha1_vtable, *mh = &br_sha1_vtable;
    const unsigned char *hoid;
    unsigned tag;
    *salt = 20;
    if (!der_next(&params, &tag, &seq) || tag != 0x30) return NULL;
    while (der_next(&seq, &tag, &f)) {
        if (tag == 0xA0) {
            if (!der_next(&f, &tag, &alg) || tag != 0x30 || !der_next(&alg, &tag, &oid) || tag != 0x06
                || !(h = hash_by_oid(&oid, &hoid))) return NULL;
        } else if (tag == 0xA1) {
            if (!der_next(&f, &tag, &alg) || tag != 0x30 || !der_next(&alg, &tag, &oid) || tag != 0x06
                || !same(&oid, mgf1, sizeof mgf1) || !der_next(&alg, &tag, &mgfhash) || tag != 0x30
                || !der_next(&mgfhash, &tag, &oid) || tag != 0x06 || !(mh = hash_by_oid(&oid, &hoid)))
                return NULL;
        } else if (tag == 0xA2) {
            struct der v;
            size_t i;
            if (!der_next(&f, &tag, &v) || tag != 0x02 || !v.len || v.len > 2 || (v.p[0] & 0x80)) return NULL;
            for (*salt = 0, i = 0; i < v.len; ++i) *salt = (*salt << 8) | v.p[i];
        } else if (tag == 0xA3) {
            struct der v;
            if (!der_next(&f, &tag, &v) || tag != 0x02 || v.len != 1 || v.p[0] != 1) return NULL;
        } else {
            return NULL;
        }
    }
    return h == mh ? h : NULL;
}

/* the services card may check this chain's signatures */
static int x509_svc_on(const struct ot_x509 *x)
{
    return x->conn && !(x->conn->ctx->flags & OTCF_NO_OFFLOAD);
}

/* the certificate's signature under key k: 0, or why not */
static unsigned cert_signature(struct ot_x509 *x, const struct leaf_parts *cp, const struct ot_key *k)
{
    static const unsigned char rsa_pre[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01 };
    static const unsigned char ecdsa_sha1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01 };
    static const unsigned char ecdsa_sha2[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03 };
    const struct ot_impls *m = x->impls;
    const br_hash_class *h = NULL;
    const unsigned char *hoid = NULL;
    unsigned char hv[64], got[64];
    br_hash_compat_context hc;
    struct der a = cp->sigalg, oid;
    unsigned tag;
    ULONG alg = 0, digest;
    size_t hl, salt = 0;
    int sv;
    if (!der_next(&a, &tag, &oid) || tag != 0x06) return BR_ERR_X509_INVALID_VALUE;
    if (same(&oid, oid_ed25519, sizeof oid_ed25519)) {
        if (k->type != OT_KEY_ED25519) return BR_ERR_X509_WRONG_KEY_TYPE;
        if (cp->sig.len != 64) return BR_ERR_X509_BAD_SIGNATURE;
        if (x509_svc_on(x)
            && (sv = ot_svc_verify(OTK_ED25519, 0, 0, k->spki, k->spki_len, cp->tbs.p, cp->tbs.len,
                                   cp->sig.p, cp->sig.len)) >= 0)
            return sv ? 0 : BR_ERR_X509_BAD_SIGNATURE;
        return ot_glue_ed25519(cp->sig.p, k->ed, cp->tbs.p, cp->tbs.len) ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    }
    if (oid.len == sizeof rsa_pre + 1 && !memcmp(oid.p, rsa_pre, sizeof rsa_pre)) {
        switch (oid.p[sizeof rsa_pre]) {
        case 5: h = &br_sha1_vtable; hoid = BR_HASH_OID_SHA1; break;
        case 11: h = &br_sha256_vtable; hoid = BR_HASH_OID_SHA256; break;
        case 12: h = &br_sha384_vtable; hoid = BR_HASH_OID_SHA384; break;
        case 13: h = &br_sha512_vtable; hoid = BR_HASH_OID_SHA512; break;
        case 10: h = pss_params(a, &salt); break;
        }
        if (!h) return BR_ERR_X509_UNSUPPORTED;
        alg = oid.p[sizeof rsa_pre] == 10 ? OTK_RSA_PSS : OTK_RSA_PKCS1;
        if (k->type != BR_KEYTYPE_RSA) return BR_ERR_X509_WRONG_KEY_TYPE;
    } else if (same(&oid, ecdsa_sha1, sizeof ecdsa_sha1)) {
        h = &br_sha1_vtable;
        alg = OTK_ECDSA;
    } else if (oid.len == sizeof ecdsa_sha2 + 1 && !memcmp(oid.p, ecdsa_sha2, sizeof ecdsa_sha2)) {
        unsigned last = oid.p[sizeof ecdsa_sha2];
        h = last == 2 ? &br_sha256_vtable : last == 3 ? &br_sha384_vtable : last == 4 ? &br_sha512_vtable : NULL;
        if (!h) return BR_ERR_X509_UNSUPPORTED;
        alg = OTK_ECDSA;
    } else {
        return BR_ERR_X509_UNSUPPORTED;
    }
    if (alg == OTK_ECDSA && k->type != BR_KEYTYPE_EC) return BR_ERR_X509_WRONG_KEY_TYPE;
    hl = (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    h->init(&hc.vtable);
    h->update(&hc.vtable, cp->tbs.p, cp->tbs.len);
    h->out(&hc.vtable, hv);
    digest = hl == 20 ? OTK_SHA1 : hl == 32 ? OTK_SHA256 : hl == 48 ? OTK_SHA384 : OTK_SHA512;
    if (x509_svc_on(x)
        && (sv = ot_svc_verify(alg, digest, (ULONG)salt, k->spki, k->spki_len, hv, hl, cp->sig.p, cp->sig.len)) >= 0)
        return sv ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    if (alg == OTK_ECDSA)
        return m->ecdsa_vrfy(m->ec, hv, hl, &k->pk.key.ec, cp->sig.p, cp->sig.len) ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    if (alg == OTK_RSA_PSS)
        return ot_rsa_pss(m, &k->pk.key.rsa, h, hv, salt, cp->sig.p, cp->sig.len) ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    if (!m->rsa_vrfy(cp->sig.p, cp->sig.len, hoid, hl, &k->pk.key.rsa, got) || memcmp(got, hv, hl))
        return BR_ERR_X509_BAD_SIGNATURE;
    return 0;
}

/* what the extensions say */
struct ext_info {
    int ca;                          /* basicConstraints cA */
    long pathlen;                    /* its pathLenConstraint; -1 none */
    int has_ku;
    unsigned ku;                     /* keyUsage's first byte (digitalSignature 0x80 ... keyCertSign 0x04) */
    int has_eku, eku_server;         /* extendedKeyUsage, and serverAuth or any in it */
    int has_san_dns;                 /* a dNSName in subjectAltName */
};

/* a critical certificatePolicies is fine when its only qualifiers are CPS pointers */
static int policies_ok(struct der v)
{
    static const unsigned char cps[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01 };
    struct der seq, info, oid, quals, q, qid;
    unsigned tag;
    if (!der_next(&v, &tag, &seq) || tag != 0x30) return 0;
    while (der_next(&seq, &tag, &info)) {
        if (tag != 0x30 || !der_next(&info, &tag, &oid) || tag != 0x06) return 0;
        if (!der_next(&info, &tag, &quals)) continue;
        if (tag != 0x30) return 0;
        while (der_next(&quals, &tag, &q))
            if (tag != 0x30 || !der_next(&q, &tag, &qid) || tag != 0x06 || !same(&qid, cps, sizeof cps)) return 0;
    }
    return 1;
}

static unsigned read_exts(struct der exts, struct ext_info *e)
{
    static const unsigned char server_auth[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    static const unsigned char any_eku[] = { 0x55, 0x1D, 0x25, 0x00 };
    static const unsigned char pkix_pe[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01 };
    struct der ext, oid, v, x;
    unsigned tag;
    memset(e, 0, sizeof *e);
    e->pathlen = -1;
    while (der_next(&exts, &tag, &ext)) {
        int critical = 0;
        if (tag != 0x30 || !der_next(&ext, &tag, &oid) || tag != 0x06 || !der_next(&ext, &tag, &v))
            return BR_ERR_X509_INVALID_VALUE;
        if (tag == 0x01) {
            if (v.len != 1) return BR_ERR_X509_INVALID_VALUE;
            critical = v.p[0] != 0;
            if (!der_next(&ext, &tag, &v)) return BR_ERR_X509_INVALID_VALUE;
        }
        if (tag != 0x04 || ext.len) return BR_ERR_X509_INVALID_VALUE;
        if (oid.len == 3 && oid.p[0] == 0x55 && oid.p[1] == 0x1D) {
            switch (oid.p[2]) {
            case 19: {                                   /* basicConstraints */
                struct der seq;
                int have;
                if (!der_next(&v, &tag, &seq) || tag != 0x30) return BR_ERR_X509_INVALID_VALUE;
                have = der_next(&seq, &tag, &x);
                if (have && tag == 0x01) {
                    if (x.len != 1) return BR_ERR_X509_INVALID_VALUE;
                    e->ca = x.p[0] != 0;
                    have = der_next(&seq, &tag, &x);
                }
                if (have && tag == 0x02) {
                    if (!x.len || x.len > 2 || (x.p[0] & 0x80)) return BR_ERR_X509_INVALID_VALUE;
                    e->pathlen = x.len == 1 ? x.p[0] : (x.p[0] << 8) | x.p[1];
                }
                break;
            }
            case 15:                                     /* keyUsage */
                if (!der_next(&v, &tag, &x) || tag != 0x03 || !x.len || x.p[0] > 7) return BR_ERR_X509_INVALID_VALUE;
                e->has_ku = 1;
                e->ku = x.len > 1 ? x.p[1] : 0;
                break;
            case 37: {                                   /* extendedKeyUsage */
                struct der seq;
                if (!der_next(&v, &tag, &seq) || tag != 0x30) return BR_ERR_X509_INVALID_VALUE;
                e->has_eku = 1;
                while (der_next(&seq, &tag, &x))
                    if (tag == 0x06 && (same(&x, server_auth, sizeof server_auth) || same(&x, any_eku, sizeof any_eku)))
                        e->eku_server = 1;
                break;
            }
            case 17: {                                   /* subjectAltName */
                struct der seq;
                if (!der_next(&v, &tag, &seq) || tag != 0x30) return BR_ERR_X509_INVALID_VALUE;
                while (der_next(&seq, &tag, &x))
                    if (tag == 0x82) e->has_san_dns = 1;
                break;
            }
            case 32:                                     /* certificatePolicies */
                if (critical && !policies_ok(v)) return BR_ERR_X509_CRITICAL_EXTENSION;
                break;
            case 35: case 14: case 18: case 9: case 31: case 46:   /* informative, or revocation */
                break;
            default:
                if (critical) return BR_ERR_X509_CRITICAL_EXTENSION;
            }
        } else if (oid.len == sizeof pkix_pe + 1 && !memcmp(oid.p, pkix_pe, sizeof pkix_pe)
                   && (oid.p[sizeof pkix_pe] == 1 || oid.p[sizeof pkix_pe] == 11)) {
            /* authorityInfoAccess, subjectInfoAccess */
        } else if (critical) {
            return BR_ERR_X509_CRITICAL_EXTENSION;
        }
    }
    return 0;
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

static unsigned check_dates(const struct leaf_parts *cp, uint32_t days, uint32_t secs)
{
    struct der v = cp->validity;
    uint32_t nb_d, nb_s, na_d, na_s;
    if (!read_time(&v, &nb_d, &nb_s) || !read_time(&v, &na_d, &na_s)) return BR_ERR_X509_BAD_TIME;
    if (days < nb_d || (days == nb_d && secs < nb_s) || days > na_d || (days == na_d && secs > na_s))
        return BR_ERR_X509_EXPIRED;
    return 0;
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

/* the host against the dNSNames, or the subject's CNs when there are none */
static int leaf_names(const unsigned char *der, size_t len, const struct leaf_parts *lp, int has_san_dns,
                      const char *host)
{
    static const unsigned char oid_cn[] = { 0x55, 0x04, 0x03 };
    struct der names, n, subj, rdns, set, atv, x;
    unsigned tag;
    if (has_san_dns) {
        if (!der_san(der, len, &names)) return 0;
        while (der_next(&names, &tag, &n))
            if (tag == 0x82 && name_matches(n.p, n.len, host)) return 1;
        return 0;
    }
    subj = lp->subject;
    if (!der_next(&subj, &tag, &rdns) || tag != 0x30) return 0;
    while (der_next(&rdns, &tag, &set))
        while (der_next(&set, &tag, &atv))
            if (der_next(&atv, &tag, &x) && tag == 0x06 && same(&x, oid_cn, sizeof oid_cn)
                && der_next(&atv, &tag, &x) && (tag == 0x0C || tag == 0x13 || tag == 0x16)
                && name_matches(x.p, x.len, host))
                return 1;
    return 0;
}

static void cert_at(const struct ot_x509 *x, int i, const unsigned char **der, size_t *len)
{
    *der = x->chain + x->chain_off[i];
    *len = x->chain_end[i] - x->chain_off[i];
}

/* the issuer named by cur among the anchors, its key checking cur's
 * signature: 0 found and good, else why not (BR_ERR_X509_NOT_TRUSTED: no
 * anchor of that name) */
static unsigned by_anchor(struct ot_x509 *x, const struct leaf_parts *cur)
{
    unsigned err = BR_ERR_X509_NOT_TRUSTED;
    size_t i;
    for (i = 0; i < x->ta_count; ++i) {
        const br_x509_trust_anchor *ta = &x->ta[i];
        struct ot_key k;
        unsigned char *spki = NULL;
        size_t n;
        unsigned e;
        if (!(ta->flags & BR_X509_TA_CA) || ta->dn.len != cur->issuer.len
            || memcmp(ta->dn.data, cur->issuer.p, cur->issuer.len))
            continue;
        memset(&k, 0, sizeof k);
        k.type = ta->pkey.key_type;
        k.pk = ta->pkey;
        if (x509_svc_on(x) && (n = anchor_spki(&ta->pkey, NULL)) && (spki = ot_alloc(n))) {
            anchor_spki(&ta->pkey, spki);
            k.spki = spki;
            k.spki_len = n;
        }
        e = cert_signature(x, cur, &k);
        ot_free(spki);
        if (!e) return 0;
        err = e;
    }
    return err;
}

int ot_cert_anchor(const unsigned char *der, size_t len, const unsigned char **dn, size_t *dn_len,
                   br_x509_pkey *pk, int *ca)
{
    struct leaf_parts lp;
    struct ext_info ei;
    struct ot_key k;
    if (!leaf_parse(der, len, &lp) || key_read(&lp.spki, &k)) return 0;
    if (k.type != BR_KEYTYPE_RSA && k.type != BR_KEYTYPE_EC) return 0;
    *dn = lp.subject.p;
    *dn_len = lp.subject.len;
    *pk = k.pk;
    *ca = !read_exts(lp.exts, &ei) && ei.ca;
    return 1;
}

#define CHECKS_NAME(c) ((c)->verify == OTV_FULL || (c)->verify == OTV_REPORT)

/* the whole check of the chain the server sent: 0 when it passes */
static unsigned chain_check(struct ot_x509 *x)
{
    struct OTConnection *c = x->conn;
    struct leaf_parts cur, cand;
    struct ext_info ei;
    struct ot_key k;
    const unsigned char *der;
    size_t len, i;
    uint32_t days, secs, used = 1;
    unsigned err;
    int depth = 0;

    if (!x->chain_count) return BR_ERR_X509_EMPTY_CHAIN;
    if (!x->chain_ok) return BR_ERR_X509_LIMIT_EXCEEDED;
    if (!ot_now(&days, &secs)) return BR_ERR_X509_TIME_UNKNOWN;
    cert_at(x, 0, &der, &len);
    if (!leaf_parse(der, len, &cur)) return BR_ERR_X509_INVALID_VALUE;
    if ((err = read_exts(cur.exts, &ei)) != 0) return err;
    if (ei.has_eku && !ei.eku_server) return BR_ERR_X509_FORBIDDEN_KEY_USAGE;
    if ((err = check_dates(&cur, days, secs)) != 0) return err;
    if (CHECKS_NAME(c)) {
        if (c->ip_len) {
            if (!ot_cert_has_ip(der, len, c->ip, (size_t)c->ip_len)) return OT_X509_IP;
        } else if (!leaf_names(der, len, &cur, ei.has_san_dns, c->host)) {
            return BR_ERR_X509_BAD_SERVER_NAME;
        }
    }
    /* trusted as it is: an anchor that is this certificate's own name and key */
    if (!key_read(&cur.spki, &k))
        for (i = 0; i < x->ta_count; ++i)
            if (!(x->ta[i].flags & BR_X509_TA_CA) && x->ta[i].dn.len == cur.subject.len
                && !memcmp(x->ta[i].dn.data, cur.subject.p, cur.subject.len) && same_key(&k, &x->ta[i].pkey))
                return 0;
    for (;;) {
        unsigned found_err = BR_ERR_X509_NOT_TRUSTED;
        int found = 0;
        if ((err = by_anchor(x, &cur)) == 0) return 0;
        if (err != BR_ERR_X509_NOT_TRUSTED) found_err = err;
        for (i = 1; i < (size_t)x->chain_count && !found; ++i) {
            const unsigned char *cd;
            size_t cl;
            if (used & (1UL << i)) continue;
            cert_at(x, (int)i, &cd, &cl);
            if (!leaf_parse(cd, cl, &cand) || cand.subject.len != cur.issuer.len
                || memcmp(cand.subject.p, cur.issuer.p, cur.issuer.len))
                continue;
            if ((err = read_exts(cand.exts, &ei)) != 0
                || (!ei.ca && (err = BR_ERR_X509_NOT_CA) != 0)
                || (ei.pathlen >= 0 && depth > ei.pathlen && (err = BR_ERR_X509_NOT_CA) != 0)
                || (ei.has_ku && !(ei.ku & 0x04) && (err = BR_ERR_X509_FORBIDDEN_KEY_USAGE) != 0)
                || (err = check_dates(&cand, days, secs)) != 0
                || (err = key_read(&cand.spki, &k)) != 0
                || (err = cert_signature(x, &cur, &k)) != 0) {
                found_err = err;
                continue;
            }
            used |= 1UL << i;
            cur = cand;
            ++depth;
            found = 1;
        }
        if (!found) return found_err;
    }
}

/* the server certificate's own key, for the handshake */
static unsigned leaf_key(struct ot_x509 *x)
{
    struct leaf_parts lp;
    struct ext_info ei;
    unsigned err;
    const unsigned char *der = x->leaf;
    size_t len = x->leaf_len;
    x->leaf_key_ok = 0;
    x->leaf_ed25519 = 0;
    if (!x->leaf_ok) {
        if (!x->chain_ok || !x->chain_count) return BR_ERR_X509_INVALID_VALUE;
        cert_at(x, 0, &der, &len);
    }
    if (!leaf_parse(der, len, &lp)) return BR_ERR_X509_INVALID_VALUE;
    if ((err = key_read(&lp.spki, &x->leaf_key)) != 0) return err;
    if (x->leaf_key.type == OT_KEY_ED25519) {
        memcpy(x->ed25519, x->leaf_key.ed, 32);
        x->leaf_ed25519 = 1;
    }
    x->leaf_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    if (!read_exts(lp.exts, &ei) && ei.has_ku)
        x->leaf_usages = ((ei.ku & 0x38) ? BR_KEYTYPE_KEYX : 0) | ((ei.ku & 0xC0) ? BR_KEYTYPE_SIGN : 0);
    x->leaf_key_ok = 1;
    return 0;
}

/* ---- the engine BearSSL's and our TLS client feed ---- */

static void xw_start_chain(const br_x509_class **ctx, const char *server_name)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    (void)server_name;
    x->cert_index = -1;
    x->accepted = 0;
    x->leaf_ok = 0;
    x->leaf_len = 0;
    x->leaf_key_ok = 0;
    x->have_fingerprint = 0;
    x->leaf_ed25519 = 0;
    x->chain_count = 0;
    x->chain_len = 0;
    x->chain_ok = 1;
    x->verdict = -1;
    c->peer_name_done = 0;
}

/* every certificate the server sent, kept for the checks and for OT_GetPeerCertificateN() */
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

static void xw_start_cert(const br_x509_class **ctx, uint32_t length)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    chain_start(x, length);
    if (++x->cert_index == 0) {
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
    }
}

static void xw_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    chain_append(x, buf, len);
    if (x->cert_index == 0) {
        br_sha256_update(&x->leaf_hash, buf, len);
        if (x->leaf_ok && x->leaf_len + len <= x->leaf_cap) {
            memcpy(x->leaf + x->leaf_len, buf, len);
            x->leaf_len += len;
        } else {
            x->leaf_ok = 0;
        }
    }
}

static void xw_end_cert(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->cert_index == 0) {
        br_sha256_out(&x->leaf_hash, x->fingerprint);
        x->have_fingerprint = 1;
        if (x->leaf_ok && x->chain_count && x->leaf_len != x->chain_want[0]) x->leaf_ok = 0;
    }
}

static unsigned xw_end_chain(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    unsigned err;
    int pin_ok;
    leaf_key(x);
    pin_ok = c->pinned && x->have_fingerprint && x->leaf_key_ok && !memcmp(x->fingerprint, c->pin, 32);

    /* OTV_REPORT: the checks OTV_FULL makes, kept for OT_GetVerifyResult();
     * the handshake goes on with the server's key whatever they say */
    if (c->verify == OTV_REPORT) {
        err = pin_ok ? 0 : chain_check(x);
        x->verdict = (int)err;
        if (!x->leaf_key_ok) return err ? err : BR_ERR_X509_INVALID_VALUE;
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
        if (!x->leaf_key_ok) {
            x->verdict = !x->chain_count ? BR_ERR_X509_EMPTY_CHAIN : BR_ERR_X509_INVALID_VALUE;
            return (unsigned)x->verdict;
        }
        x->accepted = 1;
        x->verdict = 0;
        return 0;
    }
    err = chain_check(x);
    if (!err && !x->leaf_key_ok) err = BR_ERR_X509_INVALID_VALUE;
    x->verdict = (int)err;
    if (!err) x->accepted = 1;
    return err;
}

static const br_x509_pkey *xw_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->leaf_ed25519) {
        if (usages) *usages = BR_KEYTYPE_SIGN;
        return NULL;            /* the key is x->ed25519 */
    }
    if (!x->accepted || !x->leaf_key_ok) return NULL;
    if (usages) *usages = x->leaf_usages;
    return &x->leaf_key.pk;
}

int ot_x509_spki(const struct ot_x509 *x, const unsigned char **spki, size_t *len)
{
    if (!x->leaf_key_ok || !x->leaf_key.spki) return 0;
    *spki = x->leaf_key.spki;
    *len = x->leaf_key.spki_len;
    return 1;
}

static const br_x509_class ot_x509_vtable = {
    sizeof(struct ot_x509),
    xw_start_chain, xw_start_cert, xw_append, xw_end_cert, xw_end_chain, xw_get_pkey
};

void ot_x509_init(struct ot_x509 *x, struct OTConnection *conn,
                  const struct ot_impls *m,
                  const br_x509_trust_anchor *ta, size_t ta_count)
{
    x->vtable = &ot_x509_vtable;
    x->conn = conn;
    x->impls = m;
    x->ta = ta;
    x->ta_count = ta_count;
    x->tls13 = 0;
}

void ot_x509_free(struct ot_x509 *x)
{
    ot_free(x->leaf);
    x->leaf = NULL;
    x->leaf_cap = x->leaf_len = 0;
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
    {
        struct der w = lp.spki, spki, alg = lp.sigalg, oid;
        if (der_next(&w, &tag, &spki)) key_info(&spki, info);
        if (der_next(&alg, &tag, &oid) && tag == 0x06)
            sig_name(&oid, info->SignatureAlgorithm, sizeof info->SignatureAlgorithm);
    }
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
