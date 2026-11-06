/* GFOpenCrypto: gfopencrypto 2.4's additions against published vectors, built
 * for the PC (ctest) and the Amiga (build-amiga.sh: GFOpenCryptoKeyVectors),
 * so the same checks run on both, with times on the Amiga.
 *   HMAC-SHA1     RFC 2202 tests 1 and 6;  HMAC-SHA512  RFC 4231 tests 1 and 6
 *   PBKDF2        RFC 6070 (SHA-1, 1, 2 and 4096 rounds, the 25-byte one),
 *                 and SHA-256 / SHA-512 values from Python's hashlib
 *   SHA-3         FIPS 202 "abc" and "" (SHA3-256/384/512), SHAKE256 over
 *                 "" (64 bytes) and a squeeze past the rate
 *   Argon2        RFC 9106 section 5 (d, i and id)
 *   Ed25519       RFC 8032 section 7.1 tests 1 to 3: public keys and
 *                 signatures from the seeds, and they verify
 *   ECDSA         RFC 6979 A.2.5-A.2.7 "sample" (P-256/SHA-256,
 *                 P-384/SHA-384, P-521/SHA-512): r and s, and they verify;
 *                 key generation gives a key whose point matches
 *   modexp        2^x mod the 2048-bit group 14 prime (RFC 3526)
 *   RSA private   a 2048-bit throwaway key, with and without dp, dq, qinv;
 *                 a wrong d is refused
 *   prime test    group 14's prime, its neighbour, 561, 2047
 * Copyright (c) 2026 AmiCradle Team. MIT. */
#include "gfopencrypto/gfopencrypto.h"
#include "keys_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures, checks;

static size_t unhex(uint8_t *out, const char *s)
{
    size_t i, n = strlen(s) / 2;
    for (i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void check(int ok, const char *what)
{
    ++checks;
    if (!ok) {
        ++failures;
        printf("FAIL %s\n", what);
    }
}

static void check_hex(const uint8_t *got, size_t n, const char *want, const char *what)
{
    static uint8_t w[1024];
    size_t i;
    unhex(w, want);
    check(strlen(want) == 2 * n && !memcmp(got, w, n), what);
    if (strlen(want) == 2 * n && memcmp(got, w, n)) {
        printf("     got  ");
        for (i = 0; i < n; ++i) printf("%02x", got[i]);
        printf("\n     want %s\n", want);
    }
}

static clock_t t_start;
static void tick(void) { t_start = clock(); }
static void tock(const char *what)
{
    printf("     %-34s %ld ms\n", what, (long)((clock() - t_start) * 1000 / CLOCKS_PER_SEC));
}

static void test_hmac(void)
{
    uint8_t key[131], out[64], data[160];
    memset(key, 0x0b, 20);
    oc_hmac_sha1(key, 20, "Hi There", 8, out);
    check_hex(out, 20, "b617318655057264e28bc0b6fb378c8ef146be00", "HMAC-SHA1 RFC 2202 test 1");
    memset(key, 0xaa, 80);
    oc_hmac_sha1(key, 80, "Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
    check_hex(out, 20, "aa4ae5e15272d00e95705637ce8a3b55ed402112", "HMAC-SHA1 RFC 2202 test 6");
    memset(key, 0x0b, 20);
    oc_hmac_sha512(key, 20, "Hi There", 8, out);
    check_hex(out, 64, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", "HMAC-SHA512 RFC 4231 test 1");
    memset(key, 0xaa, 131);
    oc_hmac_sha512(key, 131, "Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
    check_hex(out, 64, "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", "HMAC-SHA512 RFC 4231 test 6");
    memset(data, 0xdd, 50);
    memset(key, 0xaa, 20);
    check(oc_hmac(OC_HASH_SHA256, key, 20, data, 50, out) == 0, "HMAC-SHA256 through oc_hmac");
    check_hex(out, 32, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "HMAC-SHA256 RFC 4231 test 3");
    check(oc_hmac(9, key, 20, data, 50, out) == -1, "oc_hmac refuses an unknown hash");
}

static void test_pbkdf2(void)
{
    uint8_t out[64];
    oc_pbkdf2(OC_HASH_SHA1, "password", 8, "salt", 4, 1, out, 20);
    check_hex(out, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6", "PBKDF2-SHA1 RFC 6070 1 round");
    oc_pbkdf2(OC_HASH_SHA1, "password", 8, "salt", 4, 2, out, 20);
    check_hex(out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "PBKDF2-SHA1 RFC 6070 2 rounds");
    tick();
    oc_pbkdf2(OC_HASH_SHA1, "password", 8, "salt", 4, 4096, out, 20);
    tock("PBKDF2-SHA1, 4096 rounds");
    check_hex(out, 20, "4b007901b765489abead49d926f721d065a429c1", "PBKDF2-SHA1 RFC 6070 4096 rounds");
    oc_pbkdf2(OC_HASH_SHA1, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
              4096, out, 25);
    check_hex(out, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", "PBKDF2-SHA1 RFC 6070 25 bytes");
    oc_pbkdf2(OC_HASH_SHA256, "password", 8, "salt", 4, 4096, out, 32);
    check_hex(out, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", "PBKDF2-SHA256 4096 rounds");
    tick();
    oc_pbkdf2(OC_HASH_SHA512, "password", 8, "salt", 4, 4096, out, 64);
    tock("PBKDF2-SHA512, 4096 rounds");
    check_hex(out, 64, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5", "PBKDF2-SHA512 4096 rounds");
    check(oc_pbkdf2(OC_HASH_SHA1, "p", 1, "s", 1, 0, out, 20) == -1, "PBKDF2 refuses 0 rounds");
}

static void test_sha3(void)
{
    static uint8_t out[300];
    OCSHA3 ctx;
    oc_sha3(OC_SHA3_256, "abc", 3, out, 32);
    check_hex(out, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "SHA3-256 abc");
    oc_sha3(OC_SHA3_384, "abc", 3, out, 48);
    check_hex(out, 48, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", "SHA3-384 abc");
    oc_sha3(OC_SHA3_512, "abc", 3, out, 64);
    check_hex(out, 64, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", "SHA3-512 abc");
    oc_sha3(OC_SHA3_256, "", 0, out, 32);
    check_hex(out, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "SHA3-256 empty");
    oc_sha3(OC_SHAKE256, "", 0, out, 64);
    check_hex(out, 64, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", "SHAKE256 empty, 64 bytes");
    /* streaming in odd pieces equals one call */
    {
        static uint8_t msg[1000], one[200];
        size_t i, at;
        for (i = 0; i < sizeof msg; ++i) msg[i] = (uint8_t)(i * 7);
        oc_sha3(OC_SHAKE256, msg, sizeof msg, one, 200);
        oc_sha3_init(&ctx, OC_SHAKE256);
        for (at = 0, i = 1; at < sizeof msg; at += i, i = i * 3 % 197 + 1)
            oc_sha3_update(&ctx, msg + at, at + i > sizeof msg ? sizeof msg - at : i);
        oc_sha3_final(&ctx, out, 200);
        check(!memcmp(out, one, 200), "SHAKE256 streaming in pieces matches one call");
    }
    check(oc_sha3(OC_SHA3_256, "abc", 3, out, 31) == -1, "SHA3-256 refuses a short output");
    check(oc_sha3(224, "abc", 3, out, 28) == -1, "SHA-3 refuses an unknown variant");
}

static void test_argon2(void)
{
    static const char *want[3] = {
        "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" };
    static const char *name[3] = { "Argon2d RFC 9106 5.1", "Argon2i RFC 9106 5.2", "Argon2id RFC 9106 5.3" };
    uint8_t pw[32], salt[16], secret[8], ad[12], out[32];
    void *mem = malloc(oc_argon2_memory(32, 4));
    int t;
    memset(pw, 1, sizeof pw);
    memset(salt, 2, sizeof salt);
    memset(secret, 3, sizeof secret);
    memset(ad, 4, sizeof ad);
    for (t = 0; t < 3; ++t) {
        check(oc_argon2(t, out, 32, pw, 32, salt, 16, secret, 8, ad, 12, 3, 32, 4, mem) == 0, name[t]);
        check_hex(out, 32, want[t], name[t]);
    }
    free(mem);
    /* PuTTY's default for a new key: Argon2id, 8192 KB, 1 lane, its pass count */
    mem = malloc(oc_argon2_memory(8192, 1));
    if (mem) {
        tick();
        oc_argon2(OC_ARGON2ID, out, 32, "password", 8, salt, 16, NULL, 0, NULL, 0, 1, 8192, 1, mem);
        tock("Argon2id, 8 MB, 1 pass");
        free(mem);
    }
}

static void test_ed25519(void)
{
    static const struct { const char *seed, *pk, *msg, *sig; } v[] = {
        { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
        { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
        { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
          "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
          "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    };
    uint8_t seed[32], pk[32], msg[2], sig[64];
    size_t i, ml;
    for (i = 0; i < sizeof v / sizeof v[0]; ++i) {
        char what[80];
        unhex(seed, v[i].seed);
        ml = unhex(msg, v[i].msg);
        oc_ed25519_public_key(pk, seed);
        sprintf(what, "Ed25519 RFC 8032 7.1 test %u public key", (unsigned)i + 1);
        check_hex(pk, 32, v[i].pk, what);
        if (i == 0) tick();
        oc_ed25519_sign(sig, seed, msg, ml);
        if (i == 0) tock("Ed25519 sign");
        sprintf(what, "Ed25519 RFC 8032 7.1 test %u signature", (unsigned)i + 1);
        check_hex(sig, 64, v[i].sig, what);
        sprintf(what, "Ed25519 test %u signature verifies", (unsigned)i + 1);
        check(oc_ed25519_verify(sig, pk, msg, ml) == 1, what);
    }
}

static void test_ecdsa(void)
{
    static const struct { int curve; const char *d, *r, *s, *pub; } v[] = {
        { 256, OC_TK_EC256_D, OC_TK_EC256_R, OC_TK_EC256_S, OC_TK_EC256_PUB },
        { 384, OC_TK_EC384_D, OC_TK_EC384_R, OC_TK_EC384_S, OC_TK_EC384_PUB },
        { 521, OC_TK_EC521_D, OC_TK_EC521_R, OC_TK_EC521_S, OC_TK_EC521_PUB },
    };
    uint8_t d[66], r[66], s[66], h[64], pub[133], pt[133], seed[80];
    size_t i, bl, hl;
    for (i = 0; i < 3; ++i) {
        char what[80];
        bl = (size_t)(v[i].curve + 7) / 8;
        unhex(d, v[i].d);
        unhex(pub, v[i].pub);
        hl = v[i].curve == 256 ? 32 : v[i].curve == 384 ? 48 : 64;
        if (hl == 32) oc_sha256("sample", 6, h);
        else if (hl == 48) oc_sha384("sample", 6, h);
        else oc_sha512("sample", 6, h);
        tick();
        check(oc_ecdsa_sign(v[i].curve, r, s, d, h, hl) == 0, "ECDSA sign answers 0");
        sprintf(what, "ECDSA P-%d sign", v[i].curve);
        tock(what);
        sprintf(what, "ECDSA P-%d RFC 6979 r", v[i].curve);
        check_hex(r, bl, v[i].r, what);
        sprintf(what, "ECDSA P-%d RFC 6979 s", v[i].curve);
        check_hex(s, bl, v[i].s, what);
        sprintf(what, "ECDSA P-%d signature verifies", v[i].curve);
        check(oc_ecdsa_verify(v[i].curve, pub + 1, pub + 1 + bl, r, s, h, hl) == 1, what);
        /* key generation: the point is d G */
        memset(seed, 0x5a, sizeof seed);
        seed[0] = (uint8_t)i;
        sprintf(what, "ECDSA P-%d key generation", v[i].curve);
        check(oc_ec_keygen(v[i].curve, d, pt, seed, bl + 8) == (int)(1 + 2 * bl), what);
        memcpy(pub, pt, 1 + 2 * bl);
        check(oc_ec_mulgen(v[i].curve, pt, d, bl) == (int)(1 + 2 * bl) && !memcmp(pt, pub, 1 + 2 * bl), what);
        check(oc_ecdsa_sign(v[i].curve, r, s, d, h, hl) == 0
              && oc_ecdsa_verify(v[i].curve, pub + 1, pub + 1 + bl, r, s, h, hl) == 1,
              "a generated key signs and verifies");
    }
    memset(d, 0, sizeof d);
    check(oc_ecdsa_sign(256, r, s, d, h, 32) == -1, "ECDSA refuses d = 0");
}

static void test_bignum(void)
{
    static uint8_t n[256], e[4], dd[256], p[128], q[128], dp[128], dq[128], qi[128];
    static uint8_t in[256], out[256], x[64], g[1];
    size_t nl, el, dl, pl, ql, dpl, dql, qil;
    nl = unhex(n, OC_TK_G14_P);
    unhex(x, OC_TK_G14_X);
    g[0] = 2;
    tick();
    check(oc_modexp(out, g, 1, x, 64, n, nl) == 0, "modexp answers 0");
    tock("modexp 2048-bit, 512-bit exponent");
    check_hex(out, 256, OC_TK_G14_GX, "modexp 2^x mod the group 14 prime");
    check(oc_is_probable_prime(n, nl, 0) == 1, "the group 14 prime is prime");
    n[nl - 1] += 2;
    check(oc_is_probable_prime(n, nl, 0) == 0, "the group 14 prime + 2 is composite");
    {
        uint8_t c[2] = { 0x02, 0x31 }, f[2] = { 0x07, 0xff };     /* 561, 2047 */
        check(oc_is_probable_prime(c, 2, 0) == 0, "561 (Carmichael) is composite");
        check(oc_is_probable_prime(f, 2, 0) == 0, "2047 (a strong pseudoprime to base 2) is composite");
    }

    nl = unhex(n, OC_TK_RSA_N); el = unhex(e, OC_TK_RSA_E); dl = unhex(dd, OC_TK_RSA_D);
    pl = unhex(p, OC_TK_RSA_P); ql = unhex(q, OC_TK_RSA_Q);
    dpl = unhex(dp, OC_TK_RSA_DP); dql = unhex(dq, OC_TK_RSA_DQ); qil = unhex(qi, OC_TK_RSA_QINV);
    unhex(in, OC_TK_RSA_IN);
    tick();
    check(oc_rsa_private(out, in, n, nl, e, el, dd, dl, p, pl, q, ql, dp, dpl, dq, dql, qi, qil) == 0,
          "RSA-2048 private answers 0");
    tock("RSA-2048 private (CRT)");
    check_hex(out, 256, OC_TK_RSA_OUT, "RSA-2048 private with dp, dq, qinv");
    memset(out, 0, sizeof out);
    check(oc_rsa_private(out, in, n, nl, e, el, dd, dl, p, pl, q, ql, NULL, 0, NULL, 0, NULL, 0) == 0,
          "RSA-2048 private from d, p, q alone answers 0");
    check_hex(out, 256, OC_TK_RSA_OUT, "RSA-2048 private from d, p, q alone");
    dd[dl - 1] ^= 2;
    check(oc_rsa_private(out, in, n, nl, e, el, dd, dl, p, pl, q, ql, NULL, 0, NULL, 0, NULL, 0) == -1,
          "RSA private refuses a wrong d");
}

int main(void)
{
    printf("GFOpenCrypto 2.4 vectors\n");
    test_hmac();
    test_pbkdf2();
    test_sha3();
    test_argon2();
    test_ed25519();
    test_ecdsa();
    test_bignum();
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 10 : 0;
}
