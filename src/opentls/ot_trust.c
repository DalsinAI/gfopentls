/* GFOpenTLS: trust anchors from PEM certificates, and the system trust store
 * (S:GFOpenTLS/ca-bundle.pem and ENVARC:GFOpenTLS/certs/, docs/AutoDocs-GFOpenTLS.md),
 * loaded once and shared by every context.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"

/* One certificate (DER) to a trust anchor. Answers 1 added, 0 skipped
 * (not a certificate, or a key GFOpenTLS does not take), or OTERR_NOMEM. */
static LONG add_der(struct ot_anchors *a, const unsigned char *der, size_t len)
{
    const unsigned char *dn;
    size_t dn_len, need;
    ot_x509_pkey pk;
    ot_x509_trust_anchor *ta;
    unsigned char *block, *p;
    int ca;

    if (!ot_cert_anchor(der, len, &dn, &dn_len, &pk, &ca)) return 0;
    if (a->count == a->cap) {
        size_t cap = a->cap ? a->cap * 2 : 64;
        ot_x509_trust_anchor *n = ot_alloc(cap * sizeof *n);
        if (!n) return OTERR_NOMEM;
        if (a->count) memcpy(n, a->ta, a->count * sizeof *n);
        ot_free(a->ta);
        a->ta = n;
        a->cap = cap;
    }
    need = dn_len + (pk.key_type == OT_KEYTYPE_RSA ? pk.key.rsa.nlen + pk.key.rsa.elen : pk.key.ec.qlen);
    block = ot_alloc(need);
    if (!block) return OTERR_NOMEM;
    ta = &a->ta[a->count];
    memset(ta, 0, sizeof *ta);
    memcpy(block, dn, dn_len);
    ta->dn.data = block;
    ta->dn.len = dn_len;
    ta->flags = ca ? OT_X509_TA_CA : 0;
    ta->pkey.key_type = pk.key_type;
    p = block + dn_len;
    if (pk.key_type == OT_KEYTYPE_RSA) {
        memcpy(p, pk.key.rsa.n, pk.key.rsa.nlen);
        ta->pkey.key.rsa.n = p;
        ta->pkey.key.rsa.nlen = pk.key.rsa.nlen;
        p += pk.key.rsa.nlen;
        memcpy(p, pk.key.rsa.e, pk.key.rsa.elen);
        ta->pkey.key.rsa.e = p;
        ta->pkey.key.rsa.elen = pk.key.rsa.elen;
    } else {
        memcpy(p, pk.key.ec.q, pk.key.ec.qlen);
        ta->pkey.key.ec.curve = pk.key.ec.curve;
        ta->pkey.key.ec.q = p;
        ta->pkey.key.ec.qlen = pk.key.ec.qlen;
    }
    ++a->count;
    return 1;
}

static int is_cert_name(const char *name, size_t len)
{
    static const char *const names[] = { "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE" };
    size_t i;
    for (i = 0; i < 3; ++i)
        if (strlen(names[i]) == len && !memcmp(names[i], name, len)) return 1;
    return 0;
}

/* where the text needle starts in p..end, or NULL */
static const char *find(const char *p, const char *end, const char *needle)
{
    size_t n = strlen(needle);
    for (; p + n <= end; ++p)
        if (*p == needle[0] && !memcmp(p, needle, n)) return p;
    return NULL;
}

static int b64_value(int ch)
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

/* base64 between p and end into out (room enough: 3/4 of the length);
 * the bytes, or -1 when it is not base64 */
static long b64_decode(const char *p, const char *end, unsigned char *out)
{
    unsigned long acc = 0;
    int bits = 0, pad = 0;
    long n = 0;
    for (; p < end; ++p) {
        int v;
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') continue;
        if (*p == '=') { ++pad; continue; }
        if (pad || (v = b64_value((unsigned char)*p)) < 0) return -1;
        acc = (acc << 6) | (unsigned long)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (unsigned char)(acc >> bits);
        }
    }
    return pad > 2 ? -1 : n;
}

/* PEM (RFC 7468): each "-----BEGIN name-----" to its "-----END name-----";
 * certificates become anchors, other objects are passed over */
LONG ot_anchors_add_pem(struct ot_anchors *a, const unsigned char *pem, size_t len)
{
    const char *p = (const char *)pem, *end = p + len;
    LONG added = 0, rc;

    if (!a || (!pem && len)) return OTERR_ARGS;
    while ((p = find(p, end, "-----BEGIN ")) != NULL) {
        const char *name = p + 11, *name_end = find(name, end, "-----"), *body, *stop, *nl;
        char tail[80];
        size_t nlen;
        if (!name_end || ((nl = find(name, end, "\n")) != NULL && nl < name_end))
            return added ? added : OTERR_ARGS;
        nlen = (size_t)(name_end - name);
        body = name_end + 5;
        if (nlen + 14 > sizeof tail) return added ? added : OTERR_ARGS;
        memcpy(tail, "-----END ", 9);
        memcpy(tail + 9, name, nlen);
        memcpy(tail + 9 + nlen, "-----", 6);
        if (!(stop = find(body, end, tail))) return added ? added : OTERR_ARGS;
        if (is_cert_name(name, nlen)) {
            unsigned char *der = ot_alloc((size_t)(stop - body) * 3 / 4 + 3);
            long n;
            if (!der) return OTERR_NOMEM;
            n = b64_decode(body, stop, der);
            if (n < 0) { ot_free(der); return added ? added : OTERR_ARGS; }
            rc = add_der(a, der, (size_t)n);
            ot_free(der);
            if (rc < 0) return rc;
            added += rc;
        }
        p = stop + 14 + nlen;
    }
    return added;
}

LONG ot_anchors_add_file(struct ot_anchors *a, const char *path)
{
    unsigned char *data;
    size_t len;
    LONG rc;
    if (!a || !path) return OTERR_ARGS;
    if (!ot_read_file(path, &data, &len)) return OTERR_TRUSTSTORE;
    rc = ot_anchors_add_pem(a, data, len);
    ot_free(data);
    return rc;
}

void ot_anchors_free(struct ot_anchors *a)
{
    size_t i;
    if (!a) return;
    for (i = 0; i < a->count; ++i) ot_free(a->ta[i].dn.data);
    ot_free(a->ta);
    memset(a, 0, sizeof *a);
}

/* ---- the system store ---- */

static struct ot_anchors ot_sys;
static int ot_sys_loaded;
static void *ot_sys_lock;

static void add_dir_file(const char *path, void *ctx)
{
    ot_anchors_add_file(ctx, path);
}

int ot_trust_init(void)
{
    if (!ot_sys_lock) ot_sys_lock = ot_lock_new();
    return ot_sys_lock != NULL;
}

const struct ot_anchors *ot_system_anchors(void)
{
    char path[256];
    int i, have_bundle = 0;
    if (!ot_sys_lock) {
        /* first use; the library makes it at init, the host tests here */
        ot_sys_lock = ot_lock_new();
        if (!ot_sys_lock) return NULL;
    }
    ot_lock(ot_sys_lock);
    if (!ot_sys_loaded) {
        ot_sys_loaded = 1;
        for (i = 0; ot_trust_location(OT_TRUST_BUNDLE, i, path, sizeof path); ++i)
            if (ot_anchors_add_file(&ot_sys, path) > 0) { have_bundle = 1; break; }
        if (!have_bundle)
            for (i = 0; ot_trust_location(OT_TRUST_FALLBACK, i, path, sizeof path); ++i)
                if (ot_anchors_add_file(&ot_sys, path) > 0) break;
        /* the first directory of local additions with certificates in it */
        for (i = 0; ot_trust_location(OT_TRUST_DIR, i, path, sizeof path); ++i)
            if (ot_each_file(path, ".pem", add_dir_file, &ot_sys) > 0) break;
    }
    ot_unlock(ot_sys_lock);
    return ot_sys.count ? &ot_sys : NULL;
}

void ot_system_anchors_free(void)
{
    ot_anchors_free(&ot_sys);
    ot_sys_loaded = 0;
    ot_lock_free(ot_sys_lock);
    ot_sys_lock = NULL;
}
