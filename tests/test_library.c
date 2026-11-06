#include <exec/types.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include <proto/gfopencrypto.h>

#include <stdio.h>
#include <string.h>

struct Library *OpenCryptoBase;

static int same_hex(const UBYTE *data, ULONG length, const char *hex)
{
    ULONG i;
    for (i = 0; i < length; ++i) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1 || data[i] != (UBYTE)v)
            return 0;
    }
    return 1;
}

#define CHECK(x) do { if (!(x)) {     printf("OPENCRYPTOLIB FAIL line=%d expr=%s\n", __LINE__, #x);     rc = 20; goto done; } } while (0)

int main(void)
{
    int rc = 0;
    ULONG i;
    UBYTE out[64];
    struct OCBufferHash hash;
    struct OCHmacRequest hmac;
    struct OCCompareRequest cmp;
    struct OCCleanseRequest clean;

    OpenCryptoBase = OpenLibrary((CONST_STRPTR)OPENCRYPTOLIB_NAME,
                                 OPENCRYPTOLIB_VERSION);
    CHECK(OpenCryptoBase != NULL);
    CHECK((OC_Version() >> 16) == OPENCRYPTOLIB_VERSION);

    hash.data = "abc";
    hash.length = 3;
    hash.out = out;
    OC_SHA256(&hash);
    CHECK(same_hex(out, 32,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"));

    OC_SHA384(&hash);
    CHECK(same_hex(out, 48,
        "cb00753f45a35e8bb5a03d699ac65007"
        "272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7"));

    /* revision 2: SHA-1, one shot and as blocks ("abc", padded by hand) */
    if ((OC_Version() & 0xffff) >= 2) {
        static const UBYTE iv[20] = OC_SHA1_IV;
        UBYTE block[64];
        struct OCBlocksRequest blocks;

        OC_SHA1(&hash);
        CHECK(same_hex(out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));

        memset(block, 0, sizeof block);
        memcpy(block, "abc", 3);
        block[3] = 0x80;
        block[63] = 24;
        memcpy(out, iv, 20);
        blocks.state = out;
        blocks.data = block;
        blocks.blocks = 1;
        CHECK(OC_SHA1Blocks(&blocks) == 0);
        CHECK(same_hex(out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));
        blocks.state = NULL;
        CHECK(OC_SHA1Blocks(&blocks) == OCERR_ARGS);
    }

    /* revision 3: MD5 blocks (RFC 1321's "abc"), GHASH (the GCM paper's
     * test case 2) and P-256 point multiplication */
    if ((OC_Version() & 0xffff) >= 3) {
        static const UBYTE md5iv[16] = OC_MD5_IV;
        UBYTE block[64], y[16], pt[65], pt2[65], k[32];
        struct OCBlocksRequest blocks;
        struct OCGHASHRequest gh;
        struct OCECMulRequest em;
        memset(block, 0, sizeof block);
        memcpy(block, "abc", 3);
        block[3] = 0x80;
        block[56] = 24;
        memcpy(out, md5iv, 16);
        blocks.state = out;
        blocks.data = block;
        blocks.blocks = 1;
        CHECK(OC_MD5Blocks(&blocks) == 0);
        CHECK(same_hex(out, 16, "900150983cd24fb0d6963f7d28e17f72"));

        memset(y, 0, sizeof y);
        memset(block, 0, sizeof block);
        for (i = 0; i < 16; ++i) {
            unsigned v;
            sscanf("66e94bd4ef8a2c3b884cfa59ca342b2e" + 2 * i, "%2x", &v); out[i] = (UBYTE)v;
            sscanf("0388dace60b6a392f328c2b971b2fe78" + 2 * i, "%2x", &v); block[i] = (UBYTE)v;
        }
        block[31] = 0x80;
        gh.y = y; gh.h = out; gh.data = block; gh.length = 32;
        CHECK(OC_GHASH(&gh) == 0);
        CHECK(same_hex(y, 16, "f38cbb1ad69223dcc3457ae5b6b0f885"));

        memset(k, 0, sizeof k);
        k[31] = 2;
        em.curve = 256; em.point = pt; em.point_length = 65; em.scalar = k; em.scalar_length = 32;
        CHECK(OC_ECMulGen(&em) == 65);              /* 2G */
        k[31] = 1;
        em.point = pt2;
        CHECK(OC_ECMulGen(&em) == 65);              /* G */
        CHECK(same_hex(pt2, 33, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        k[31] = 2;
        CHECK(OC_ECMul(&em) == 1);                  /* 2 * G */
        CHECK(memcmp(pt, pt2, 65) == 0);
        pt2[40] ^= 1;
        CHECK(OC_ECMul(&em) == 0);                  /* off the curve */
    }

    hmac.key = "key";
    hmac.key_length = 3;
    hmac.data = "The quick brown fox jumps over the lazy dog";
    hmac.data_length = (ULONG)strlen((const char *)hmac.data);
    hmac.out = out;
    OC_HMAC_SHA256(&hmac);
    CHECK(same_hex(out, 32,
        "f7bc83f430538424b13298e6aa6fb143"
        "ef4d59a14946175997479dbc2d1a3cd8"));

    cmp.a = out;
    cmp.b = out;
    cmp.length = 32;
    CHECK(OC_CtEqual(&cmp) == 1);

    clean.data = out;
    clean.length = sizeof out;
    OC_Cleanse(&clean);
    for (i = 0; i < sizeof out; ++i)
        CHECK(out[i] == 0);

    puts("OPENCRYPTOLIB PASS sha256 sha384 sha1 md5 ghash ec-mul hmac ct-cleanse");

done:
    if (OpenCryptoBase)
        CloseLibrary(OpenCryptoBase);
    return rc;
}
