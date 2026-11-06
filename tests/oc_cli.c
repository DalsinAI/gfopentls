/* GFOpenCrypto: a line-at-a-time front end for tests/differential.py, which
 * checks GFOpenCrypto against Python's cryptography package (OpenSSL) on
 * random inputs. Each line: an operation and its arguments in hex ("-" is
 * empty); the answer: hex, or 0/1.
 * Copyright (c) 2026 AmiCradle Team. MIT. */
#include "gfopencrypto/gfopencrypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(uint8_t *out, const char *s)
{
    size_t i, n;
    if (!strcmp(s, "-")) return 0;
    n = strlen(s) / 2;
    for (i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void put(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) printf("%02x", b[i]);
    if (!n) printf("-");
    printf("\n");
}

int main(void)
{
    static char line[1 << 20];
    static uint8_t a[1 << 17], b[1 << 17], c[1 << 17], d[1 << 17], e[1 << 17], f[1 << 17], out[1 << 17];
    char *w[10];
    while (fgets(line, sizeof line, stdin)) {
        int n = 0;
        char *p = strtok(line, " \n");
        while (p && n < 10) { w[n++] = p; p = strtok(NULL, " \n"); }
        if (!n) continue;
        if (!strcmp(w[0], "x25519")) {
            unhex(a, w[1]); unhex(b, w[2]);
            int r = oc_x25519(out, a, b);
            if (r) printf("refused\n"); else put(out, 32);
        } else if (!strcmp(w[0], "ed25519")) {
            size_t ml = unhex(c, w[3]);
            unhex(a, w[1]); unhex(b, w[2]);
            printf("%d\n", oc_ed25519_verify(a, b, c, ml));
        } else if (!strcmp(w[0], "chacha")) {       /* key nonce counter(hex u64) data */
            size_t l = unhex(c, w[4]);
            unhex(a, w[1]); unhex(b, w[2]);
            oc_chacha20_xor(out, c, l, a, b, strtoull(w[3], NULL, 16));
            put(out, l);
        } else if (!strcmp(w[0], "poly")) {
            size_t l = unhex(b, w[2]);
            unhex(a, w[1]);
            oc_poly1305(out, b, l, a);
            put(out, 16);
        } else if (!strcmp(w[0], "aes")) {          /* mode key iv data */
            size_t kl = unhex(a, w[2]), l = unhex(out, w[4]);
            unhex(b, w[3]);
            if (oc_aes(out, l, a, kl, b, atoi(w[1]))) printf("refused\n"); else put(out, l);
        } else if (!strcmp(w[0], "rsa")) {          /* n e sig */
            size_t nl = unhex(a, w[1]), el = unhex(b, w[2]);
            unhex(c, w[3]);
            if (oc_rsa_public(out, c, a, nl, b, el)) printf("refused\n"); else put(out, nl);
        } else if (!strcmp(w[0], "ecdsa")) {        /* curve qx qy r s hash */
            size_t hl;
            unhex(a, w[2]); unhex(b, w[3]); unhex(c, w[4]); unhex(d, w[5]);
            hl = unhex(e, w[6]);
            printf("%d\n", oc_ecdsa_verify(atoi(w[1]), a, b, c, d, e, hl));
        } else if (!strcmp(w[0], "sha256")) {
            size_t l = unhex(a, w[1]);
            oc_sha256(a, l, out); put(out, 32);
        } else if (!strcmp(w[0], "sha1")) {
            size_t l = unhex(a, w[1]);
            oc_sha1(a, l, out); put(out, 20);
        } else if (!strcmp(w[0], "sha512")) {
            size_t l = unhex(a, w[1]);
            oc_sha512(a, l, out); put(out, 64);
        } else if (!strcmp(w[0], "kem")) {          /* seed seed2: pk, then ct, ss, then dec ss */
            static uint8_t pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES], ct[OC_SNTRUP761_CT_BYTES];
            uint8_t ss[32], ss2[32];
            unhex(a, w[1]); unhex(b, w[2]);
            oc_sntrup761_keypair(pk, sk, a);
            oc_sntrup761_enc(ct, ss, pk, b);
            oc_sntrup761_dec(ss2, ct, sk);
            printf("%d\n", !memcmp(ss, ss2, 32));
        } else if (!strcmp(w[0], "hmac")) {         /* hash key data */
            size_t kl = unhex(a, w[2]), l = unhex(b, w[3]);
            int h = atoi(w[1]);
            if (oc_hmac(h, a, kl, b, l, out)) printf("refused\n"); else put(out, oc_hash_length(h));
        } else if (!strcmp(w[0], "pbkdf2")) {       /* hash password salt iterations length */
            size_t pl = unhex(a, w[2]), sl = unhex(b, w[3]), ol = (size_t)atoi(w[5]);
            if (oc_pbkdf2(atoi(w[1]), a, pl, b, sl, (uint32_t)atoi(w[4]), out, ol)) printf("refused\n");
            else put(out, ol);
        } else if (!strcmp(w[0], "sha3")) {         /* variant data length */
            size_t l = unhex(a, w[2]), ol = (size_t)atoi(w[3]);
            if (oc_sha3((int)strtol(w[1], NULL, 0), a, l, out, ol)) printf("refused\n"); else put(out, ol);
        } else if (!strcmp(w[0], "argon2")) {       /* type t m lanes length password salt secret ad */
            uint32_t t = (uint32_t)atoi(w[2]), m = (uint32_t)atoi(w[3]), p2 = (uint32_t)atoi(w[4]);
            size_t ol = (size_t)atoi(w[5]), pl, sl, kl, al;
            void *mem;
            pl = unhex(a, w[6]); sl = unhex(b, w[7]);
            kl = n > 8 ? unhex(c, w[8]) : 0;
            al = n > 9 ? unhex(d, w[9]) : 0;
            mem = malloc(oc_argon2_memory(m, p2) + 1);
            if (oc_argon2(atoi(w[1]), out, (uint32_t)ol, a, pl, b, sl, c, kl, d, al, t, m, p2, mem))
                printf("refused\n");
            else put(out, ol);
            free(mem);
        } else if (!strcmp(w[0], "edsign")) {       /* seed msg: pk sig */
            size_t l = unhex(b, w[2]);
            unhex(a, w[1]);
            oc_ed25519_public_key(out, a);
            oc_ed25519_sign(out + 32, a, b, l);
            put(out, 96);
        } else if (!strcmp(w[0], "ecsign")) {       /* curve d hash: r s */
            int cv = atoi(w[1]);
            size_t bl = (size_t)(cv + 7) / 8, hl;
            unhex(a, w[2]);
            hl = unhex(b, w[3]);
            if (oc_ecdsa_sign(cv, out, out + bl, a, b, hl)) printf("refused\n"); else put(out, 2 * bl);
        } else if (!strcmp(w[0], "eckeygen")) {     /* curve seed: d point */
            int cv = atoi(w[1]);
            size_t bl = (size_t)(cv + 7) / 8, sl = unhex(a, w[2]);
            if (!oc_ec_keygen(cv, out, out + bl, a, sl)) printf("refused\n"); else put(out, 1 + 3 * bl);
        } else if (!strcmp(w[0], "modexp")) {       /* base exp mod */
            size_t bl = unhex(a, w[1]), el = unhex(b, w[2]), ml = unhex(c, w[3]);
            if (oc_modexp(out, a, bl, b, el, c, ml)) printf("refused\n"); else put(out, ml);
        } else if (!strcmp(w[0], "rsapriv")) {      /* n e d p q in [dp dq qinv] */
            static uint8_t g[1 << 12], h2[1 << 12], i2[1 << 12], j2[1 << 12];
            size_t nl = unhex(a, w[1]), el = unhex(b, w[2]), dl = unhex(c, w[3]);
            size_t pl = unhex(d, w[4]), ql = unhex(e, w[5]), dpl = 0, dql = 0, qil = 0;
            unhex(f, w[6]);
            if (n > 9) { dpl = unhex(g, w[7]); dql = unhex(h2, w[8]); qil = unhex(i2, w[9]); }
            if (oc_rsa_private(j2, f, a, nl, b, el, c, dl, d, pl, e, ql,
                               dpl ? g : NULL, dpl, dql ? h2 : NULL, dql, qil ? i2 : NULL, qil))
                printf("refused\n");
            else put(j2, nl);
        } else if (!strcmp(w[0], "prime")) {        /* number */
            size_t l = unhex(a, w[1]);
            printf("%d\n", oc_is_probable_prime(a, l, 0));
        } else {
            printf("unknown\n");
        }
        (void)f;
        fflush(stdout);
    }
    return 0;
}
