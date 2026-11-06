/* GFOpenStubTest: a program linked with -lgfopencrypto -lgfopentls and
 * nothing else of ours. The stubs open both libraries before main(); this
 * checks the bases, the versions, the streaming hashes against the one-call
 * ones and published vectors, MD5, oc_hmac and oc_x25519_base. Prints
 * "GFOPENSTUBS PASS". MIT, Copyright (c) 2026 AmiCradle Team. */
#include <stdio.h>
#include <string.h>
#include <exec/libraries.h>
#include <proto/gfopentls.h>
#include <gfopencrypto/gfopencrypto.h>

extern struct Library *OpenCryptoBase;

static int fails;
static void check(int ok, const char *what)
{
    if (!ok) { ++fails; printf("FAIL %s\n", what); }
}

static int hexeq(const unsigned char *b, const char *hex, size_t n)
{
    char s[3];
    size_t i;
    for (i = 0; i < n; ++i) {
        sprintf(s, "%02x", b[i]);
        if (s[0] != hex[2 * i] || s[1] != hex[2 * i + 1]) return 0;
    }
    return 1;
}

static unsigned char data[3000];

int main(void)
{
    unsigned char a[64], b[64];
    size_t i, at, n, step;
    ULONG v;
    check(OpenCryptoBase && OpenTLSBase, "both bases open before main()");
    v = OT_Version();
    printf("gfopentls.library %lu.%lu, gfopencrypto.library %u.%u\n", (unsigned long)(v >> 16),
           (unsigned long)(v & 0xffff), OpenCryptoBase->lib_Version, OpenCryptoBase->lib_Revision);
    check((v >> 16) > 1 || (v & 0xffff) >= 5, "gfopentls.library 1.5 or newer");
    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)(i * 131 + 7);

    oc_sha256("abc", 3, a);
    check(hexeq(a, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32), "sha256 abc");
    oc_md5("abc", 3, a);
    check(hexeq(a, "900150983cd24fb0d6963f7d28e17f72", 16), "md5 abc");
    oc_md5("", 0, a);
    check(hexeq(a, "d41d8cd98f00b204e9800998ecf8427e", 16), "md5 empty");
    for (step = 1; step <= 200; step += 33) {
        for (n = 0; n <= sizeof data; n += 111 + step) {
            OCSHA256 c2; OCSHA512 c5; OCSHA1 c1;
            oc_sha256_init(&c2); oc_sha512_init(&c5); oc_sha1_init(&c1);
            for (at = 0; at < n; at += step) {
                size_t k = n - at < step ? n - at : step;
                oc_sha256_update(&c2, data + at, k);
                oc_sha512_update(&c5, data + at, k);
                oc_sha1_update(&c1, data + at, k);
            }
            oc_sha256_final(&c2, a); oc_sha256(data, n, b); check(!memcmp(a, b, 32), "sha256 streaming");
            oc_sha512_final(&c5, a); oc_sha512(data, n, b); check(!memcmp(a, b, 64), "sha512 streaming");
            oc_sha1_final(&c1, a); oc_sha1(data, n, b); check(!memcmp(a, b, 20), "sha1 streaming");
        }
    }
    /* RFC 4231 test case 2 */
    check(oc_hmac(OC_HASH_SHA256, "Jefe", 4, "what do ya want for nothing?", 28, a) == 0 &&
          hexeq(a, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32), "hmac-sha256");
    check(oc_hmac(7, "k", 1, "d", 1, a) == -1, "hmac unknown hash");
    {
        static const unsigned char nine[32] = { 9 };
        oc_x25519_base(a, data);
        check(oc_x25519(b, data, nine) == 0 && !memcmp(a, b, 32), "x25519_base");
    }
    check(oc_ct_equal(data, data, 100) == 1 && oc_ct_equal(data, data + 1, 100) == 0, "ct_equal");
    printf("GFOPENSTUBS %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 20 : 0;
}
