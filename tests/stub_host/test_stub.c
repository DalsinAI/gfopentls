/* libgfopencrypto.a's own code on the host: the streaming hashes' buffering
 * and padding (against the one-call hashes, which here are the real code),
 * MD5, oc_hmac's dispatch, the ChaCha20 counter's split, oc_x25519_base,
 * oc_expand_seed and oc_argon2_memory. The library calls are mock.c's.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <stdio.h>
#include <string.h>
#include <gfopencrypto/gfopencrypto.h>

void ref_md5(const void *d, size_t n, uint8_t *out);
size_t ref_argon2_memory(uint32_t m, uint32_t l);
void ref_chacha20_xor(uint8_t *out, const uint8_t *in, size_t n, const uint8_t *k, const uint8_t *nonce, uint64_t c);
void ref_expand_seed(uint8_t *out, size_t n, const uint8_t *seed, const char *label);

static int fails, checks;
static void check(int ok, const char *what, size_t a, size_t b)
{
    ++checks;
    if (!ok) { ++fails; printf("FAIL %s (%zu, %zu)\n", what, a, b); }
}

static uint8_t data[2000];
static const size_t lens[] = { 0, 1, 3, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129,
                               191, 192, 255, 256, 257, 1000, 2000 };
static const size_t chunks[] = { 1, 7, 63, 64, 65, 127, 128, 129, 2000 };

int main(void)
{
    size_t i, j, k, at, n;
    uint8_t a[64], b[64], ka[300], kb[300];
    for (i = 0; i < sizeof data; ++i) data[i] = (uint8_t)(i * 131 + 7);
    for (i = 0; i < sizeof lens / sizeof *lens; ++i) {
        for (j = 0; j < sizeof chunks / sizeof *chunks; ++j) {
            OCSHA256 c2; OCSHA512 c5; OCSHA1 c1;
            oc_sha256_init(&c2); oc_sha512_init(&c5); oc_sha1_init(&c1);
            for (at = 0; at < lens[i]; at += n) {
                n = lens[i] - at < chunks[j] ? lens[i] - at : chunks[j];
                oc_sha256_update(&c2, data + at, n);
                oc_sha512_update(&c5, data + at, n);
                oc_sha1_update(&c1, data + at, n);
            }
            oc_sha256_final(&c2, a); oc_sha256(data, lens[i], b);
            check(!memcmp(a, b, 32), "sha256 streaming", lens[i], chunks[j]);
            oc_sha512_final(&c5, a); oc_sha512(data, lens[i], b);
            check(!memcmp(a, b, 64), "sha512 streaming", lens[i], chunks[j]);
            oc_sha1_final(&c1, a); oc_sha1(data, lens[i], b);
            check(!memcmp(a, b, 20), "sha1 streaming", lens[i], chunks[j]);
        }
        oc_md5(data, lens[i], a); ref_md5(data, lens[i], b);
        check(!memcmp(a, b, 16), "md5", lens[i], 0);
    }
    /* RFC 1321's "abc" */
    oc_md5("abc", 3, a);
    check(!memcmp(a, "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72", 16), "md5 abc", 0, 0);
    for (k = 1; k <= 4; ++k) {
        size_t hl = oc_hash_length((int)k);
        check(oc_hmac((int)k, "key", 3, data, 100, a) == 0, "hmac rc", k, 0);
        if (k == 1) oc_hmac_sha1("key", 3, data, 100, b);
        if (k == 2) oc_hmac_sha256("key", 3, data, 100, b);
        if (k == 3) oc_hmac_sha384("key", 3, data, 100, b);
        if (k == 4) oc_hmac_sha512("key", 3, data, 100, b);
        check(hl && !memcmp(a, b, hl), "hmac dispatch", k, hl);
    }
    check(oc_hmac(9, "key", 3, data, 1, a) == -1 && oc_hash_length(9) == 0, "hmac unknown", 0, 0);
    check(oc_hmac(2, NULL, 3, data, 1, a) == -1, "hmac NULL key", 0, 0);
    {
        static const uint8_t nine[32] = { 9 };
        oc_x25519_base(a, data);
        check(oc_x25519(b, data, nine) == 0 && !memcmp(a, b, 32), "x25519_base", 0, 0);
    }
    for (k = 0; k < 3; ++k) {
        static const uint64_t ctr[3] = { 0, 0xffffffffu, 0x0000000500000003ull };
        oc_chacha20_xor(ka, data, 300, data + 40, data + 80, ctr[k]);
        ref_chacha20_xor(kb, data, 300, data + 40, data + 80, ctr[k]);
        check(!memcmp(ka, kb, 300), "chacha20 counter", k, 0);
    }
    oc_expand_seed(ka, 300, data, "labelxyz"); ref_expand_seed(kb, 300, data, "labelxyz");
    check(!memcmp(ka, kb, 300), "expand_seed", 0, 0);
    for (k = 0; k < 6; ++k) {
        static const uint32_t m[6] = { 0, 8, 19, 64, 100, 4096 }, l[6] = { 1, 1, 2, 4, 3, 0 };
        check(oc_argon2_memory(m[k], l[k]) == ref_argon2_memory(m[k], l[k]), "argon2_memory", m[k], l[k]);
    }
    {
        uint8_t out[32], out2[32];
        check(oc_argon2(OC_ARGON2ID, out, 32, "pw", 2, "saltsalt", 8, NULL, 0, NULL, 0, 1, 16, 1, NULL) == 0,
              "argon2 through the library", 0, 0);
        oc_blake2b(out2, 32, data, 10);
        check(out[0] != out2[0] || out[1] != out2[1], "blake2b member linked", 0, 0);
    }
    printf("STUB HOST %s (%d checks, %d failures)\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails != 0;
}
