/* GFOpenTLS: the calls of gfopentls.library (docs/AutoDocs-GFOpenTLS.md), over
 * BearSSL's client engine. The library (library/opentls_lib.c) calls these
 * from its register entry points; the host tests call them directly.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"
#include "ot_tls13.h"
#include "inner.h"      /* BearSSL's br_ssl_engine_fail() */
#include <clib/gfopentls_protos.h>

/* ---- small helpers (no stdio in the library) ---- */

size_t ot_strlcpy(char *dst, const char *src, size_t size)
{
    size_t n = strlen(src);
    if (size) {
        size_t k = n < size - 1 ? n : size - 1;
        memcpy(dst, src, k);
        dst[k] = 0;
    }
    return n;
}

static void cat(char *dst, size_t size, const char *s)
{
    size_t l = strlen(dst);
    if (s && l < size) ot_strlcpy(dst + l, s, size - l);
}

static void fmt_long(char *buf, LONG v)
{
    char tmp[12];
    int i = 0, neg = v < 0;
    unsigned long u = neg ? (unsigned long)(-(v + 1)) + 1UL : (unsigned long)v;
    do { tmp[i++] = (char)('0' + (int)(u % 10UL)); u /= 10UL; } while (u);
    if (neg) *buf++ = '-';
    while (i) *buf++ = tmp[--i];
    *buf = 0;
}

static int lower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

static int same_host(const char *a, const char *b)
{
    while (*a && lower(*a) == lower(*b)) { ++a; ++b; }
    return *a == *b;
}

void ot_set_error(struct OTConnection *c, LONG code, LONG detail, const char *a,
                  const char *b, const char *d)
{
    if (!c) return;
    c->error = code;
    c->detail = detail;
    c->text[0] = 0;
    cat(c->text, sizeof c->text, a);
    cat(c->text, sizeof c->text, b);
    cat(c->text, sizeof c->text, d);
}

LONG ot_fail(struct OTConnection *c, LONG code, LONG detail, const char *a,
             const char *b, const char *d)
{
    ot_set_error(c, code, detail, a, b, d);
    if (code != OTERR_WOULDBLOCK) c->state = OTS_FAILED;
    return code;
}

/* ---- addresses ---- */

static int parse_ipv4(const char *s, unsigned char out[4])
{
    int part = 0, digits = 0;
    unsigned v = 0;
    for (;; ++s) {
        if (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s - '0');
            if (v > 255 || ++digits > 3) return 0;
        } else if (*s == '.' || *s == 0) {
            if (!digits || part > 3) return 0;
            out[part++] = (unsigned char)v;
            v = 0;
            digits = 0;
            if (*s == 0) break;
        } else {
            return 0;
        }
    }
    return part == 4;
}

static int hexval(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    ch = lower(ch);
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static int parse_ipv6(const char *s, unsigned char out[16])
{
    unsigned short w[8];
    int n = 0, gap = -1, i;
    if (s[0] == ':' && s[1] == ':') { gap = 0; s += 2; }
    while (*s) {
        unsigned v = 0;
        int digits = 0, h;
        if (n == 8) return 0;
        if (strchr(s, '.') && !strchr(s, ':')) {      /* ::ffff:1.2.3.4 */
            unsigned char v4[4];
            if (n > 6 || !parse_ipv4(s, v4)) return 0;
            w[n++] = (unsigned short)((v4[0] << 8) | v4[1]);
            w[n++] = (unsigned short)((v4[2] << 8) | v4[3]);
            break;
        }
        while ((h = hexval(*s)) >= 0) {
            v = (v << 4) | (unsigned)h;
            if (++digits > 4) return 0;
            ++s;
        }
        if (!digits) return 0;
        w[n++] = (unsigned short)v;
        if (*s == ':') {
            ++s;
            if (*s == ':') {
                if (gap >= 0) return 0;
                gap = n;
                ++s;
            } else if (*s == 0) {
                return 0;
            }
        } else if (*s) {
            return 0;
        }
    }
    if (gap < 0 && n != 8) return 0;
    if (gap >= 0 && n == 8) return 0;
    memset(out, 0, 16);
    if (gap < 0) gap = n;
    for (i = 0; i < gap; ++i) { out[2 * i] = (unsigned char)(w[i] >> 8); out[2 * i + 1] = (unsigned char)w[i]; }
    for (i = gap; i < n; ++i) {
        int j = 8 - (n - i);
        out[2 * j] = (unsigned char)(w[i] >> 8);
        out[2 * j + 1] = (unsigned char)w[i];
    }
    return 1;
}

/* ---- names ---- */

static const char *alert_name(int alert)
{
    switch (alert) {
    case 10: return "unexpected message";
    case 20: return "bad record MAC";
    case 40: return "handshake failure";
    case 42: return "bad certificate";
    case 43: return "unsupported certificate";
    case 44: return "certificate revoked";
    case 45: return "certificate expired";
    case 46: return "certificate unknown";
    case 47: return "illegal parameter";
    case 48: return "unknown CA";
    case 50: return "decode error";
    case 51: return "decrypt error";
    case 70: return "protocol version";
    case 71: return "insufficient security";
    case 80: return "internal error";
    case 86: return "inappropriate fallback";
    case 90: return "user canceled";
    case 109: return "missing extension";
    case 110: return "unsupported extension";
    case 112: return "unrecognized name";
    case 116: return "certificate required";
    case 120: return "no application protocol";
    default: return "an alert";
    }
}


/* ---- error mapping ---- */

static void cert_error(struct OTConnection *c, LONG code, int err)
{
    char name[96], num[12];
    switch (code) {
    case OTERR_HOSTNAME:
        ot_cert_name(c->x509.leaf_ok ? c->x509.leaf : NULL, c->x509.leaf_len, name, sizeof name);
        if (name[0]) {
            ot_set_error(c, code, err, "The server's certificate is for ", name, ", not ");
            cat(c->text, sizeof c->text, c->host);
            cat(c->text, sizeof c->text, ".");
        } else {
            ot_set_error(c, code, err, "The server's certificate is not for ", c->host, ".");
        }
        break;
    case OTERR_EXPIRED:
        ot_set_error(c, code, err, err == BR_ERR_X509_TIME_UNKNOWN
            ? "The Amiga's clock is not set, so certificate dates cannot be checked."
            : "A certificate in the server's chain is expired or not yet valid (check the Amiga's clock).",
            NULL, NULL);
        break;
    case OTERR_UNTRUSTED:
        ot_set_error(c, code, err, "The server's certificate is not signed by a trusted authority.", NULL, NULL);
        break;
    case OTERR_PINNED:
        ot_set_error(c, code, err, "The server's certificate is not the one remembered for ", c->host, ".");
        break;
    default:
        fmt_long(num, err);
        ot_set_error(c, OTERR_BADCERT, err, "The server's certificate could not be used (X.509 error ", num, ").");
        break;
    }
}

/* the engine's error code to ours, with its text */
LONG ot_engine_error(struct OTConnection *c, int err)
{
    char num[12];
    c->state = OTS_FAILED;
    if (err >= BR_ERR_SEND_FATAL_ALERT) {
        fmt_long(num, err - BR_ERR_SEND_FATAL_ALERT);
        ot_set_error(c, OTERR_PROTOCOL, err, "GFOpenTLS ended the connection (alert ", num, ").");
    } else if (err >= BR_ERR_RECV_FATAL_ALERT) {
        int alert = err - BR_ERR_RECV_FATAL_ALERT;
        fmt_long(num, alert);
        if (alert == 70) {
            ot_set_error(c, OTERR_VERSION, alert, c->max_version < OT_TLS13
                ? "The server refused the protocol version (it may want TLS 1.3 only)."
                : "The server refused the protocol version.", NULL, NULL);
        } else {
            ot_set_error(c, OTERR_ALERT, alert, "The server ended the connection: ", alert_name(alert), " (alert ");
            cat(c->text, sizeof c->text, num);
            cat(c->text, sizeof c->text, ").");
        }
    } else if (err == BR_ERR_X509_BAD_SERVER_NAME || err == OT_X509_IP) {
        cert_error(c, OTERR_HOSTNAME, err);
    } else if (err == BR_ERR_X509_EXPIRED || err == BR_ERR_X509_TIME_UNKNOWN) {
        cert_error(c, OTERR_EXPIRED, err);
    } else if (err == BR_ERR_X509_NOT_TRUSTED) {
        if (!c->ctx->merged_count)
            ot_set_error(c, OTERR_TRUSTSTORE, err,
                "No trusted certificates: install the CA bundle as S:GFOpenTLS/ca-bundle.pem.", NULL, NULL);
        else
            cert_error(c, OTERR_UNTRUSTED, err);
    } else if (err == OT_X509_PINNED) {
        cert_error(c, OTERR_PINNED, err);
    } else if (err >= BR_ERR_X509_OK && err < 64) {
        cert_error(c, OTERR_BADCERT, err);
    } else if (err == BR_ERR_UNSUPPORTED_VERSION || err == BR_ERR_BAD_VERSION) {
        ot_set_error(c, OTERR_VERSION, err, "The server and GFOpenTLS have no protocol version in common.", NULL, NULL);
    } else if (err == BR_ERR_BAD_CIPHER_SUITE || err == BR_ERR_INVALID_ALGORITHM) {
        ot_set_error(c, OTERR_CIPHER, err, "The server chose a cipher suite, curve or signature GFOpenTLS does not offer.", NULL, NULL);
    } else if (err == BR_ERR_NO_RANDOM) {
        ot_set_error(c, OTERR_RANDOM, err, "No random numbers for the handshake.", NULL, NULL);
    } else if (err == BR_ERR_BAD_SIGNATURE) {
        ot_set_error(c, OTERR_PROTOCOL, err, "The server's handshake signature does not verify.", NULL, NULL);
    } else if (err == BR_ERR_IO) {
        ot_set_error(c, OTERR_IO, err, "The connection failed.", NULL, NULL);
    } else {
        fmt_long(num, err);
        ot_set_error(c, OTERR_PROTOCOL, err, "The server broke the TLS protocol (engine error ", num, ").");
    }
    return c->error;
}

/* ---- I/O ---- */

LONG ot_io(struct OTConnection *c, int write, unsigned char *buf, size_t len)
{
    LONG n;
    if (len > 0x7FFFFFFFUL) len = 0x7FFFFFFFUL;
    if (c->hook) {
        struct OTIOMessage m;
        m.MethodID = write ? OTIO_WRITE : OTIO_READ;
        m.Buffer = buf;
        m.Length = (LONG)len;
        n = ot_hook_call(c->hook, c, &m);
        if (n > (LONG)len) n = OTERR_IO;
        if (n < 0 && n != OTERR_WOULDBLOCK) n = OTERR_IO;
        return n;
    }
    return write ? ot_sock_write(c->fd, c->socketbase, buf, (LONG)len)
                 : ot_sock_read(c->fd, c->socketbase, buf, (LONG)len);
}

/* ---- contexts ---- */

#define CFG_HAS(cfg, field) \
    ((cfg)->Size >= offsetof(struct OTContextConfig, field) + sizeof((cfg)->field))

struct merged_block { struct merged_block *next; };

ULONG OT_Version(VOID)
{
    return ((ULONG)OT_LIB_VERSION << 16) | OT_LIB_REVISION;
}

struct OTContext *OT_NewContext(CONST struct OTContextConfig *config, LONG *error)
{
    struct OTContext *x;
    LONG minv = OT_TLS12, maxv = OT_TLS13, rc;
    if (error) *error = OTERR_OK;
    if (config && config->Size < 2 * sizeof(ULONG)) { if (error) *error = OTERR_ARGS; return NULL; }
    if (config && CFG_HAS(config, MinVersion) && config->MinVersion) minv = config->MinVersion;
    if (config && CFG_HAS(config, MaxVersion) && config->MaxVersion) maxv = config->MaxVersion;
    if (minv < OT_TLS10 || maxv < OT_TLS10 || maxv > OT_TLS13 || minv > OT_TLS13 || maxv < minv) {
        if (error) *error = OTERR_ARGS;
        return NULL;
    }
    if (maxv < OT_TLS12) {             /* TLS 1.0 and 1.1 are gone since 2.0 */
        if (error) *error = OTERR_UNSUPPORTED;
        return NULL;
    }
    if (minv < OT_TLS12) minv = OT_TLS12;
    x = ot_alloc(sizeof *x);
    if (!x || !(x->lock = ot_lock_new())) {
        ot_free(x);
        if (error) *error = OTERR_NOMEM;
        return NULL;
    }
    x->flags = config ? config->Flags : 0;
    x->min_version = minv;
    x->max_version = maxv;
    if (config && CFG_HAS(config, ALPN) && config->ALPN && config->ALPN[0]) {
        size_t l = strlen((const char *)config->ALPN);
        x->alpn = ot_alloc(l + 1);
        if (!x->alpn) { OT_FreeContext(x); if (error) *error = OTERR_NOMEM; return NULL; }
        memcpy(x->alpn, config->ALPN, l);
    }
    if (config && CFG_HAS(config, CAFile) && config->CAFile) {
        rc = ot_anchors_add_file(&x->extra, (const char *)config->CAFile);
        if (rc <= 0) {
            OT_FreeContext(x);
            if (error) *error = rc < 0 ? rc : OTERR_TRUSTSTORE;
            return NULL;
        }
    }
    return x;
}

VOID OT_FreeContext(struct OTContext *x)
{
    struct merged_block *b, *n;
    if (!x) return;
    /* every array made, newest first: a handshake may have used an older one */
    if (x->merged) {
        for (b = ((struct merged_block *)(void *)x->merged) - 1; b; b = n) {
            n = b->next;
            ot_free(b);
        }
    }
    ot_anchors_free(&x->extra);
    ot_free(x->alpn);
    ot_lock_free(x->lock);
    ot_free(x);
}

/* the trust anchors for a handshake: the system's and the context's own */
static void merged_anchors(struct OTContext *x, const br_x509_trust_anchor **ta, size_t *n)
{
    ot_lock(x->lock);
    if (!x->merged_ok) {
        const struct ot_anchors *sys = (x->flags & OTCF_NO_SYSTEM_TRUST) ? NULL : ot_system_anchors();
        size_t count = (sys ? sys->count : 0) + x->extra.count;
        struct merged_block *b = ot_alloc(sizeof(br_x509_trust_anchor) * (count ? count : 1)
                                          + sizeof(br_x509_trust_anchor));
        if (b) {
            br_x509_trust_anchor *arr = (br_x509_trust_anchor *)(void *)(b + 1);
            /* the block header sits just before the array; keep the old ones */
            b->next = x->merged ? ((struct merged_block *)(void *)x->merged) - 1 : NULL;
            if (sys && sys->count) memcpy(arr, sys->ta, sys->count * sizeof *arr);
            if (x->extra.count)
                memcpy(arr + (sys ? sys->count : 0), x->extra.ta, x->extra.count * sizeof *arr);
            x->merged = arr;
            x->merged_count = count;
            x->merged_ok = 1;
            x->system_missing = !(x->flags & OTCF_NO_SYSTEM_TRUST) && !sys;
        }
    }
    *ta = x->merged;
    *n = x->merged ? x->merged_count : 0;
    ot_unlock(x->lock);
}

LONG OT_AddTrustPEM(struct OTContext *x, CONST_APTR pem, LONG length)
{
    LONG rc;
    if (!x || !pem || length <= 0) return OTERR_ARGS;
    ot_lock(x->lock);
    rc = ot_anchors_add_pem(&x->extra, pem, (size_t)length);
    x->merged_ok = 0;
    ot_unlock(x->lock);
    return rc;
}

LONG OT_AddTrustFile(struct OTContext *x, CONST_STRPTR path)
{
    LONG rc;
    if (!x || !path) return OTERR_ARGS;
    ot_lock(x->lock);
    rc = ot_anchors_add_file(&x->extra, (const char *)path);
    x->merged_ok = 0;
    ot_unlock(x->lock);
    return rc;
}

/* ---- connections ---- */

static LONG set_alpn(struct OTConnection *c, const char *list)
{
    size_t l;
    char *p;
    ot_free(c->alpn);
    c->alpn = NULL;
    c->alpn_count = 0;
    if (!list || !list[0]) return OTERR_OK;
    l = strlen(list);
    c->alpn = ot_alloc(l + 1);
    if (!c->alpn) return OTERR_NOMEM;
    memcpy(c->alpn, list, l);
    for (p = c->alpn; *p && c->alpn_count < OT_ALPN_MAX; ) {
        char *start = p;
        while (*p && *p != ',') ++p;
        if (*p) *p++ = 0;
        if (*start && strlen(start) < 256) c->alpn_names[c->alpn_count++] = start;
    }
    return OTERR_OK;
}

struct OTConnection *OT_NewConnection(struct OTContext *x, CONST_STRPTR hostname, LONG *error)
{
    struct OTConnection *c;
    const char *h = (const char *)hostname;
    size_t l;
    if (error) *error = OTERR_OK;
    if (!x || !h || !h[0] || (l = strlen(h)) > OT_HOST_MAX) { if (error) *error = OTERR_ARGS; return NULL; }
    c = ot_alloc(sizeof *c);
    if (!c) { if (error) *error = OTERR_NOMEM; return NULL; }
    c->ctx = x;
    c->fd = -1;
    c->min_version = x->min_version;
    c->max_version = x->max_version;
    c->iobuf_len = (x->flags & OTCF_SMALL_BUFFERS) ? OT_IOBUF_SMALL : OT_IOBUF_LARGE;
    c->iobuf = ot_alloc(c->iobuf_len + OT_OUT_MAX);
    if (!c->iobuf) { ot_free(c); if (error) *error = OTERR_NOMEM; return NULL; }
    c->out = c->iobuf + c->iobuf_len;
    if (h[0] == '[' && h[l - 1] == ']' && l - 2 < sizeof c->host) {   /* [v6] */
        memcpy(c->host, h + 1, l - 2);
        c->host[l - 2] = 0;
    } else {
        ot_strlcpy(c->host, h, sizeof c->host);
    }
    if (parse_ipv4(c->host, c->ip)) c->ip_len = 4;
    else if (strchr(c->host, ':') && parse_ipv6(c->host, c->ip)) c->ip_len = 16;
    else if (strchr(c->host, ':')) { OT_FreeConnection(c); if (error) *error = OTERR_ARGS; return NULL; }
    if (set_alpn(c, x->alpn) != OTERR_OK) { OT_FreeConnection(c); if (error) *error = OTERR_NOMEM; return NULL; }
    c->state = OTS_NEW;
    return c;
}

VOID OT_FreeConnection(struct OTConnection *c)
{
    if (!c) return;
    ot13_free(c);
    if (c->offer13) ot_free(c->offer13);
    ot_x509_free(&c->x509);
    if (c->iobuf) {
        memset(c->iobuf, 0, c->iobuf_len + OT_OUT_MAX);
        ot_free(c->iobuf);
    }
    ot_free(c->alpn);
    memset(c, 0, sizeof *c);       /* the session's keys go too */
    ot_free(c);
}

#define BEFORE_HANDSHAKE(c) do { if (!(c)) return OTERR_ARGS; \
    if ((c)->state != OTS_NEW) return OTERR_STATE; } while (0)

LONG OT_SetSocket(struct OTConnection *c, LONG socket, struct Library *socketBase)
{
    BEFORE_HANDSHAKE(c);
#ifdef __amigaos__
    if (!socketBase) return OTERR_ARGS;
#endif
    if (socket < 0) return OTERR_ARGS;
    c->fd = socket;
    c->socketbase = socketBase;
    c->hook = NULL;
    c->have_io = 1;
    return OTERR_OK;
}

LONG OT_SetIOHook(struct OTConnection *c, struct Hook *hook)
{
    BEFORE_HANDSHAKE(c);
    if (!hook) return OTERR_ARGS;
    c->hook = hook;
    c->have_io = 1;
    return OTERR_OK;
}

LONG OT_SetALPN(struct OTConnection *c, CONST_STRPTR protocols)
{
    BEFORE_HANDSHAKE(c);
    return set_alpn(c, (const char *)protocols);
}

LONG OT_SetVerify(struct OTConnection *c, LONG mode)
{
    BEFORE_HANDSHAKE(c);
    if (mode < OTV_FULL || mode > OTV_REPORT) return OTERR_ARGS;
    c->verify = mode;
    return OTERR_OK;
}

LONG OT_PinCertificate(struct OTConnection *c, CONST UBYTE *sha256)
{
    BEFORE_HANDSHAKE(c);
    if (!sha256) { c->pinned = 0; return OTERR_OK; }
    memcpy(c->pin, sha256, 32);
    c->pinned = 1;
    return OTERR_OK;
}

LONG OT_SetSession(struct OTConnection *c, struct OTSession *s)
{
    BEFORE_HANDSHAKE(c);
    if (c->offer13) { ot_free(c->offer13); c->offer13 = NULL; }
    if (!s) { c->offer_session = 0; return OTERR_OK; }
    if (!same_host(s->host, c->host)) return OTERR_ARGS;
    c->offered = s->params;
    c->offer_session = 1;
    ot_session_lock();
    c->offer13 = ot13_ticket_copy(s->t13);       /* NULL while it waits for one */
    ot_session_unlock();
    return OTERR_OK;
}

LONG OT_SetVersion(struct OTConnection *c, LONG minVersion, LONG maxVersion)
{
    BEFORE_HANDSHAKE(c);
    if (!minVersion) minVersion = c->ctx->min_version;
    if (!maxVersion) maxVersion = c->ctx->max_version;
    if (minVersion < OT_TLS10 || maxVersion > OT_TLS13 || minVersion > maxVersion) return OTERR_ARGS;
    if (maxVersion < OT_TLS12) return OTERR_UNSUPPORTED;      /* TLS 1.0 and 1.1 are gone since 2.0 */
    if (minVersion < OT_TLS12) minVersion = OT_TLS12;
    c->min_version = minVersion;
    c->max_version = maxVersion;
    return OTERR_OK;
}

static LONG start_handshake(struct OTConnection *c)
{
    struct OTContext *x = c->ctx;
    const br_x509_trust_anchor *ta = NULL;
    size_t ta_count = 0;
    int need_trust = c->verify == OTV_FULL || c->verify == OTV_NO_HOSTNAME || c->verify == OTV_REPORT;

    if (!c->have_io)
        return ot_fail(c, OTERR_STATE, 0, "No socket or I/O hook was given.", NULL, NULL);
    /* With no trust store the handshake still runs as far as the server's
     * certificate, so that the caller can show it and offer to trust it
     * (OT_GetPeerFingerprint, OT_GetPeerName); it then fails with
     * OTERR_TRUSTSTORE unless the certificate is pinned. */
    if (!ot_glue_ready())
        return ot_fail(c, OTERR_UNSUPPORTED, 0, "gfopencrypto.library 2.3 or newer is needed.", NULL, NULL);
    if (need_trust) merged_anchors(x, &ta, &ta_count);
    ot_glue_select(&c->impls, !(x->flags & OTCF_NO_OFFLOAD));
    ot_x509_init(&c->x509, c, &c->impls, ta, ta_count);
    c->state = OTS_HANDSHAKE;
    return ot13_start(c);
}

LONG OT_Handshake(struct OTConnection *c)
{
    LONG rc;
    if (!c) return OTERR_ARGS;
    if (c->state == OTS_OPEN) return OTERR_OK;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state == OTS_CLOSED) return OTERR_STATE;
    if (c->state == OTS_NEW && (rc = start_handshake(c)) != OTERR_OK) return rc;
    if ((rc = ot13_handshake(c)) != OTERR_OK) return rc;
    c->state = OTS_OPEN;
    c->error = OTERR_OK;
    c->text[0] = 0;
    c->resumed = c->t13->psk_used;
    return OTERR_OK;
}

LONG OT_Read(struct OTConnection *c, APTR buffer, LONG length)
{
    if (!c || length < 0 || (!buffer && length)) return OTERR_ARGS;
    if (c->state == OTS_CLOSED) return c->clean_close ? 0 : OTERR_STATE;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    if (!length) return 0;
    return ot13_read(c, buffer, length);
}

LONG OT_Write(struct OTConnection *c, CONST_APTR buffer, LONG length)
{
    const unsigned char *p = buffer;
    if (!c || length < 0 || (!buffer && length)) return OTERR_ARGS;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    return ot13_write(c, p, length);
}

LONG OT_Pending(struct OTConnection *c)
{
    if (!c || c->state != OTS_OPEN) return 0;
    return ot13_pending(c);
}

LONG OT_Close(struct OTConnection *c)
{
    LONG rc;
    if (!c) return OTERR_ARGS;
    if (c->state == OTS_CLOSED) return OTERR_OK;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    rc = ot13_close(c);
    if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
    if (rc != OTERR_OK) return rc;
    c->state = OTS_CLOSED;
    c->clean_close = 1;
    return OTERR_OK;
}

/* ---- sessions ---- */

/* A TLS 1.3 session may wait for its ticket (OT_GetSession) while the
 * connection that will bring it, and the session, are used and freed by
 * different tasks: one lock covers the waiting lists and tickets. */
static void *session_lock;

int ot_session_init(void)
{
    if (!session_lock) session_lock = ot_lock_new();
    return session_lock != NULL;
}

void ot_session_cleanup(void)
{
    ot_lock_free(session_lock);
    session_lock = NULL;
}

void ot_session_lock(void)
{
    if (!session_lock) ot_session_init();     /* the host tests; the library makes it at init */
    if (session_lock) ot_lock(session_lock);
}

void ot_session_unlock(void)
{
    if (session_lock) ot_unlock(session_lock);
}

struct OTSession *OT_GetSession(struct OTConnection *c)
{
    struct OTSession *s;
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return NULL;
    s = ot_alloc(sizeof *s);
    if (!s) return NULL;
    if (!c->t13->v12) {
        /* TLS 1.3: the newest ticket; until the first comes (OT_Read reads
         * it, after the handshake), a session that waits for it */
        ot_strlcpy(s->host, c->host, sizeof s->host);
        ot_session_lock();
        s->t13 = ot13_ticket_copy(c->t13->ticket);
        ot_session_unlock();
        if (!s->t13) {
            if (c->state != OTS_OPEN) { ot_free(s); return NULL; }
            ot13_session_wait(c, s);
        }
        return s;
    }
    s->params = c->session12;
    if (!s->params.session_id_len || !s->params.version) { ot_free(s); return NULL; }
    ot_strlcpy(s->host, c->host, sizeof s->host);
    return s;
}

VOID OT_FreeSession(struct OTSession *s)
{
    if (!s) return;
    if (s->source) ot13_session_unwait(s);
    if (s->t13) ot_free(s->t13);
    memset(s, 0, sizeof *s);       /* the master secret */
    ot_free(s);
}

/* 1 when the session can resume something: a TLS 1.2 session ID, or a
 * TLS 1.3 ticket (which a waiting session gets in OT_Read) */
LONG OT_SessionHasTicket(struct OTSession *s)
{
    LONG has;
    if (!s) return 0;
    if (s->params.session_id_len) return 1;
    ot_session_lock();
    has = s->t13 != NULL;
    ot_session_unlock();
    return has;
}

LONG OT_SessionResumed(struct OTConnection *c)
{
    return c && c->state != OTS_NEW && c->resumed ? 1 : 0;
}

/* ---- information ---- */

LONG OT_GetError(struct OTConnection *c) { return c ? c->error : OTERR_ARGS; }
LONG OT_GetErrorDetail(struct OTConnection *c) { return c ? c->detail : 0; }

CONST_STRPTR OT_GetErrorText(struct OTConnection *c)
{
    if (!c) return (CONST_STRPTR)"No connection.";
    if (!c->error) return (CONST_STRPTR)"No error.";
    if (!c->text[0]) return OT_ErrorString(c->error);
    return (CONST_STRPTR)c->text;
}

CONST_STRPTR OT_ErrorString(LONG error)
{
    static const char *const names[] = {
        "No error.",
        "Bad arguments.",
        "Out of memory.",
        "The connection failed.",
        "The peer closed the connection without close_notify.",
        "The socket would block: call again.",
        "The peer broke the TLS protocol.",
        "No protocol version in common.",
        "No cipher suite in common.",
        "The peer sent a fatal alert.",
        "The certificate is not signed by a trusted authority.",
        "The certificate is not for this host.",
        "The certificate is expired or not yet valid.",
        "The certificate is malformed or cannot be used.",
        "No trusted certificates could be read.",
        "Call out of order.",
        "No random numbers.",
        "Not supported by this version of GFOpenTLS.",
        "Internal error in GFOpenTLS.",
        "The certificate is not the pinned one.",
    };
    if (error > 0 || error < -(LONG)(sizeof names / sizeof names[0]) + 1)
        return (CONST_STRPTR)"Unknown error.";
    return (CONST_STRPTR)names[-error];
}

LONG OT_GetProtocol(struct OTConnection *c)
{
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return 0;
    return c->t13->v12 ? OT_TLS12 : OT_TLS13;
}

CONST_STRPTR OT_GetCipher(struct OTConnection *c)
{
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return (CONST_STRPTR)"";
    return (CONST_STRPTR)c->t13->suite->name;
}

CONST_STRPTR OT_GetALPN(struct OTConnection *c)
{
    return (CONST_STRPTR)(c ? c->alpn_selected : "");
}

LONG OT_GetPeerFingerprint(struct OTConnection *c, UBYTE *sha256)
{
    if (!c || !sha256) return OTERR_ARGS;
    if (!c->x509.have_fingerprint) return OTERR_STATE;
    memcpy(sha256, c->x509.fingerprint, 32);
    return OTERR_OK;
}

LONG OT_GetPeerCertificate(struct OTConnection *c, APTR buffer, LONG length)
{
    if (!c) return OTERR_ARGS;
    if (!c->x509.have_fingerprint || !c->x509.leaf_ok || !c->x509.leaf_len) return OTERR_STATE;
    if (!buffer) return (LONG)c->x509.leaf_len;
    if (length < (LONG)c->x509.leaf_len) return OTERR_ARGS;
    memcpy(buffer, c->x509.leaf, c->x509.leaf_len);
    return (LONG)c->x509.leaf_len;
}

CONST_STRPTR OT_GetPeerName(struct OTConnection *c)
{
    if (!c || !c->x509.have_fingerprint || !c->x509.leaf_ok) return (CONST_STRPTR)"";
    if (!c->peer_name_done) {
        ot_cert_name(c->x509.leaf, c->x509.leaf_len, c->peer_name, sizeof c->peer_name);
        c->peer_name_done = 1;
    }
    return (CONST_STRPTR)c->peer_name;
}

LONG OT_Random(APTR buffer, LONG length)
{
    if (length < 0 || (!buffer && length)) return OTERR_ARGS;
    return ot_random(buffer, (size_t)length);
}

ULONG OT_Accelerated(VOID)
{
    return ot_glue_accelerated() | (ot_svc_ready(0) ? OTACC_SERVICE : 0);
}

/* ---- version 1, revision 5 (6 November 2026): for FileZilla ---- */

LONG OT_GetVerifyResult(struct OTConnection *c)
{
    int err;
    if (!c) return OTERR_ARGS;
    err = c->x509.verdict;
    if (!c->x509.have_fingerprint || err < 0) return OTERR_STATE;
    if (!err) return OTERR_OK;
    if (err == BR_ERR_X509_BAD_SERVER_NAME || err == OT_X509_IP) return OTERR_HOSTNAME;
    if (err == BR_ERR_X509_EXPIRED || err == BR_ERR_X509_TIME_UNKNOWN) return OTERR_EXPIRED;
    if (err == BR_ERR_X509_NOT_TRUSTED) return c->ctx->merged_count ? OTERR_UNTRUSTED : OTERR_TRUSTSTORE;
    if (err == OT_X509_PINNED) return OTERR_PINNED;
    return OTERR_BADCERT;
}

LONG OT_GetPeerChainLength(struct OTConnection *c)
{
    struct ot_x509 *x;
    LONG n = 0;
    if (!c) return OTERR_ARGS;
    x = &c->x509;
    if (!x->have_fingerprint) return OTERR_STATE;
    /* the certificates kept whole, from the server's first */
    while (n < x->chain_count && x->chain_end[n] - x->chain_off[n] == x->chain_want[n]) ++n;
    return n;
}

LONG OT_GetPeerCertificateN(struct OTConnection *c, LONG index, APTR buffer, LONG length)
{
    struct ot_x509 *x;
    size_t len;
    if (!c || index < 0) return OTERR_ARGS;
    x = &c->x509;
    if (!x->have_fingerprint) return OTERR_STATE;
    if (index >= OT_GetPeerChainLength(c)) return OTERR_ARGS;
    len = x->chain_end[index] - x->chain_off[index];
    if (!buffer) return (LONG)len;
    if (length < (LONG)len) return OTERR_ARGS;
    memcpy(buffer, x->chain + x->chain_off[index], len);
    return (LONG)len;
}

CONST_STRPTR OT_GetKeyExchange(struct OTConnection *c)
{
    unsigned curve;
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return (CONST_STRPTR)"";
    if (c->t13->suite->rsa_kx) return (CONST_STRPTR)"RSA";
    if (c->t13->resumed12) return (CONST_STRPTR)"";
    curve = c->t13->group == 29 ? BR_EC_curve25519 : c->t13->group == 23 ? BR_EC_secp256r1
          : c->t13->group == 24 ? BR_EC_secp384r1 : c->t13->group == 25 ? BR_EC_secp521r1 : 0;
    switch (curve) {
    case BR_EC_curve25519: return (CONST_STRPTR)"x25519";
    case BR_EC_secp256r1: return (CONST_STRPTR)"secp256r1";
    case BR_EC_secp384r1: return (CONST_STRPTR)"secp384r1";
    case BR_EC_secp521r1: return (CONST_STRPTR)"secp521r1";
    }
    return (CONST_STRPTR)"";
}

static int has_word(const char *s, const char *w)
{
    for (; *s; ++s) {
        size_t i = 0;
        while (w[i] && s[i] == w[i]) ++i;
        if (!w[i]) return 1;
    }
    return 0;
}

CONST_STRPTR OT_GetMAC(struct OTConnection *c)
{
    const char *name;
    size_t n;
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return (CONST_STRPTR)"";
    if (!c->t13->v12) return (CONST_STRPTR)"AEAD";
    name = (const char *)OT_GetCipher(c);
    n = strlen(name);
    if (!n) return (CONST_STRPTR)"";
    if (has_word(name, "GCM") || has_word(name, "CHACHA20")) return (CONST_STRPTR)"AEAD";
    if (n > 7 && !strcmp(name + n - 7, "-SHA384")) return (CONST_STRPTR)"SHA384";
    if (n > 7 && !strcmp(name + n - 7, "-SHA256")) return (CONST_STRPTR)"SHA256";
    if (n > 4 && !strcmp(name + n - 4, "-SHA")) return (CONST_STRPTR)"SHA1";
    return (CONST_STRPTR)"";
}
