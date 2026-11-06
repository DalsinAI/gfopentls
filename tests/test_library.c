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

    /* revision 4: the FileZilla calls, each once (the full vectors are
     * GFOpenCryptoKeyVectors) */
    if ((OC_Version() & 0xffff) >= 4) {
        static UBYTE n[256], seed[40], big[64], pt[65], r[32], s[32];
        struct OCPBKDF2Request pb;
        struct OCSHA3Request sr;
        struct OCArgon2Request ar;
        struct OCEd25519SignRequest es;
        struct OCECDSASignRequest ds;
        struct OCECKeyGenRequest kg;
        struct OCECDSARequest dv;
        struct OCModExpRequest me;
        struct OCPrimeRequest pr;
        OCSHA3 ctx;
        UBYTE two = 2, three = 3;

        hmac.key = "key"; hmac.key_length = 3;
        hmac.data = "The quick brown fox jumps over the lazy dog";
        hmac.data_length = (ULONG)strlen((const char *)hmac.data);
        hmac.out = out;
        OC_HMAC_SHA1(&hmac);
        CHECK(same_hex(out, 20, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"));
        OC_HMAC_SHA512(&hmac);
        CHECK(same_hex(out, 16, "b42af09057bac1e2d41708e48a902e09"));

        pb.hash = OC_HASH_SHA1; pb.password = "password"; pb.password_length = 8;
        pb.salt = "salt"; pb.salt_length = 4; pb.iterations = 2; pb.out = out; pb.out_length = 20;
        CHECK(OC_PBKDF2(&pb) == 0);
        CHECK(same_hex(out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
        pb.iterations = 0;
        CHECK(OC_PBKDF2(&pb) == OCERR_ARGS);

        sr.ctx = NULL; sr.variant = OC_SHA3_256; sr.data = "abc"; sr.length = 3;
        sr.out = out; sr.out_length = 32;
        CHECK(OC_SHA3(&sr) == 0);
        CHECK(same_hex(out, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        sr.ctx = &ctx; sr.variant = OC_SHAKE256;
        CHECK(OC_SHA3Init(&sr) == 0);
        sr.data = ""; sr.length = 0;
        CHECK(OC_SHA3Update(&sr) == 0);
        CHECK(OC_SHA3Final(&sr) == 0);
        CHECK(same_hex(out, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));

        memset(big, 1, 32); memset(seed, 2, 16); memset(r, 3, 8); memset(s, 4, 12);
        ar.type = OC_ARGON2ID; ar.out = out; ar.out_length = 32;
        ar.password = big; ar.password_length = 32; ar.salt = seed; ar.salt_length = 16;
        ar.secret = r; ar.secret_length = 8; ar.ad = s; ar.ad_length = 12;
        ar.passes = 3; ar.m_kib = 32; ar.lanes = 4;
        CHECK(OC_Argon2(&ar) == 0);
        CHECK(same_hex(out, 32, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));

        for (i = 0; i < 32; ++i) {
            unsigned v;
            sscanf("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" + 2 * i, "%2x", &v);
            seed[i] = (UBYTE)v;
        }
        es.out = big; es.seed = seed; es.msg = ""; es.length = 0;
        CHECK(OC_Ed25519PublicKey(&es) == 0);
        CHECK(same_hex(big, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
        CHECK(OC_Ed25519Sign(&es) == 0);
        CHECK(same_hex(big, 64, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));

        memset(seed, 0x5a, sizeof seed);
        kg.curve = 256; kg.d = big; kg.point = pt; kg.seed = seed; kg.seed_length = 40;
        CHECK(OC_ECKeyGen(&kg) == 65);
        hash.data = "sample"; hash.length = 6; hash.out = out;
        OC_SHA256(&hash);
        ds.curve = 256; ds.r = r; ds.s = s; ds.d = big; ds.hash = out; ds.hash_length = 32;
        CHECK(OC_ECDSASign(&ds) == 0);
        dv.curve = 256; dv.qx = pt + 1; dv.qy = pt + 33; dv.r = r; dv.s = s;
        dv.hash = out; dv.hash_length = 32;
        CHECK(OC_ECDSAVerify(&dv) == 1);

        /* 2^3 mod 2^2048 - 1 ... any odd modulus: 0xff..ff */
        memset(n, 0xff, sizeof n);
        me.out = big; me.base = &two; me.base_length = 1; me.exponent = &three;
        me.exponent_length = 1; me.modulus = n; me.modulus_length = 32;
        CHECK(OC_ModExp(&me) == 0);
        CHECK(big[31] == 8 && big[0] == 0);

        pr.number = n; pr.length = 32; pr.rounds = 0;
        CHECK(OC_IsProbablePrime(&pr) == 0);        /* 2^256 - 1 */
        n[0] = 0x7f;
        CHECK(OC_IsProbablePrime(&pr) == 0);
        two = 0xfb;                                 /* 251 */
        pr.number = &two; pr.length = 1;
        CHECK(OC_IsProbablePrime(&pr) == 1);
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

    puts("OPENCRYPTOLIB PASS sha256 sha384 sha1 md5 ghash ec-mul hmac ct-cleanse"
         " hmac-sha1/512 pbkdf2 sha3 argon2 ed25519-sign ecdsa-sign modexp prime");

done:
    if (OpenCryptoBase)
        CloseLibrary(OpenCryptoBase);
    return rc;
}
