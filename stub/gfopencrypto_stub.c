/* libgfopencrypto.a: the <gfopencrypto/gfopencrypto.h> calls (oc_*), served
 * by gfopencrypto.library 2.4. Link with -lgfopencrypto; the library opens
 * into OpenCryptoBase before main() and closes when the program ends. A
 * program that can't open gfopencrypto.library 2.4 or newer says so and
 * ends with RETURN_FAIL before main().
 *
 * Each oc_* call fills the library's request struct and makes the call.
 * The streaming hashes (oc_sha256_init/update/final, the SHA-512 and SHA-1
 * ones) and oc_md5 keep their partial block and do the padding here, over
 * OC_SHA256Blocks, OC_SHA512Blocks, OC_SHA1Blocks and OC_MD5Blocks: their
 * contexts' h[] holds the chaining value as the big-endian bytes the Blocks
 * calls take (on a 68k that is also the words' own layout).
 * A verification the library refuses for want of stack (OCERR_STACK) is
 * answered 0, never a pass.
 *
 * oc_emsa_pss_verify, oc_keccak_f1600 and oc_blake2b have no library call
 * (the first takes a C function, the others are building blocks): they come
 * from separate members of this library (stub_pss.c, stub_keccak.c,
 * stub_blake2b.c) and are linked only when used. oc_argon2() ignores its
 * memory argument (the library allocates its own and wipes it).
 *
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <proto/exec.h>
#include <stabs.h>
#include <libraries/gfopencrypto.h>
#include <proto/gfopencrypto.h>
#include "stub_open.h"

struct Library *OpenCryptoBase;

static void __attribute__((used)) oc_stub_open(void)
{
	if (!OpenCryptoBase)
		OpenCryptoBase = gfopen_stub_open(OPENCRYPTOLIB_NAME, OPENCRYPTOLIB_VERSION, 4);
}
ADD2INIT(oc_stub_open, -50);

static void __attribute__((used)) oc_stub_close(void)
{
	if (OpenCryptoBase) {
		CloseLibrary(OpenCryptoBase);
		OpenCryptoBase = 0;
	}
}
ADD2EXIT(oc_stub_close, -50);

static void wipe(void *p, ULONG n)
{
	volatile UBYTE *q = (volatile UBYTE *)p;
	while (n--) *q++ = 0;
}

static void copy(void *to, const void *from, ULONG n)
{
	UBYTE *d = (UBYTE *)to;
	const UBYTE *s = (const UBYTE *)from;
	while (n--) *d++ = *s++;
}

/* ---- the streaming hashes: whole blocks to the library, the rest here ---- */

typedef LONG (*blocks_fn)(UBYTE *state, const void *data, ULONG blocks);

static LONG sha256_blocks(UBYTE *st, const void *d, ULONG n)
{ struct OCBlocksRequest r = { st, d, n }; return OC_SHA256Blocks(&r); }
static LONG sha512_blocks(UBYTE *st, const void *d, ULONG n)
{ struct OCBlocksRequest r = { st, d, n }; return OC_SHA512Blocks(&r); }
static LONG sha1_blocks(UBYTE *st, const void *d, ULONG n)
{ struct OCBlocksRequest r = { st, d, n }; return OC_SHA1Blocks(&r); }
static LONG md5_blocks(UBYTE *st, const void *d, ULONG n)
{ struct OCBlocksRequest r = { st, d, n }; return OC_MD5Blocks(&r); }

/* adds data to a hash with a bs-byte block (64 or 128) */
static void stream_update(blocks_fn fn, UBYTE *state, UBYTE *block, size_t *used,
                          uint64_t *total, ULONG bs, const void *data, size_t length)
{
	const UBYTE *p = (const UBYTE *)data;
	ULONG n;
	if (!length) return;
	*total += length;
	if (*used) {
		n = bs - *used;
		if (n > length) n = length;
		copy(block + *used, p, n);
		*used += n; p += n; length -= n;
		if (*used < bs) return;
		fn(state, block, 1);
		*used = 0;
	}
	if (length >= bs) {
		n = length / bs;
		fn(state, p, n);
		p += n * bs; length -= n * bs;
	}
	if (length) {
		copy(block, p, length);
		*used = length;
	}
}

/* the last block(s): 0x80, zeros, the length in bits (big-endian for SHA,
 * little-endian for MD5) in the last lenbytes bytes */
static void stream_final(blocks_fn fn, UBYTE *state, UBYTE *block, size_t used,
                         uint64_t total, ULONG bs, ULONG lenbytes, int little)
{
	uint64_t bits = total << 3;
	ULONG i;
	block[used++] = 0x80;
	if (used > bs - lenbytes) {
		while (used < bs) block[used++] = 0;
		fn(state, block, 1);
		used = 0;
	}
	while (used < bs - 8) block[used++] = 0;
	for (i = 0; i < 8; ++i)
		block[bs - 8 + i] = little ? (UBYTE)(bits >> (8 * i)) : (UBYTE)(bits >> (56 - 8 * i));
	fn(state, block, 1);
}

void oc_sha256_init(OCSHA256 *ctx)
{
	static const UBYTE iv[OC_SHA256_BYTES] = {
		0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85, 0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
		0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c, 0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19 };
	copy(ctx->h, iv, sizeof iv);
	ctx->total_bytes = 0;
	ctx->block_used = 0;
}

void oc_sha256_update(OCSHA256 *ctx, const void *data, size_t length)
{
	stream_update(sha256_blocks, (UBYTE *)ctx->h, ctx->block, &ctx->block_used,
	              &ctx->total_bytes, OC_SHA256_BLOCK_BYTES, data, length);
}

void oc_sha256_final(OCSHA256 *ctx, uint8_t out[OC_SHA256_BYTES])
{
	stream_final(sha256_blocks, (UBYTE *)ctx->h, ctx->block, ctx->block_used,
	             ctx->total_bytes, OC_SHA256_BLOCK_BYTES, 8, 0);
	copy(out, ctx->h, OC_SHA256_BYTES);
	wipe(ctx, sizeof *ctx);
}

void oc_sha512_init(OCSHA512 *ctx)
{
	static const UBYTE iv[OC_SHA512_BYTES] = {
		0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08, 0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
		0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b, 0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
		0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1, 0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
		0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b, 0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79 };
	copy(ctx->h, iv, sizeof iv);
	ctx->total_bytes = 0;
	ctx->block_used = 0;
}

void oc_sha512_update(OCSHA512 *ctx, const void *data, size_t length)
{
	stream_update(sha512_blocks, (UBYTE *)ctx->h, ctx->block, &ctx->block_used,
	              &ctx->total_bytes, OC_SHA512_BLOCK_BYTES, data, length);
}

void oc_sha512_final(OCSHA512 *ctx, uint8_t out[OC_SHA512_BYTES])
{
	/* SHA-512's length field is 128 bits; the top 64 are zero here */
	stream_final(sha512_blocks, (UBYTE *)ctx->h, ctx->block, ctx->block_used,
	             ctx->total_bytes, OC_SHA512_BLOCK_BYTES, 16, 0);
	copy(out, ctx->h, OC_SHA512_BYTES);
	wipe(ctx, sizeof *ctx);
}

void oc_sha1_init(OCSHA1 *ctx)
{
	static const UBYTE iv[OC_SHA1_BYTES] = OC_SHA1_IV;
	copy(ctx->h, iv, sizeof iv);
	ctx->total_bytes = 0;
	ctx->block_used = 0;
}

void oc_sha1_update(OCSHA1 *ctx, const void *data, size_t length)
{
	stream_update(sha1_blocks, (UBYTE *)ctx->h, ctx->block, &ctx->block_used,
	              &ctx->total_bytes, OC_SHA1_BLOCK_BYTES, data, length);
}

void oc_sha1_final(OCSHA1 *ctx, uint8_t out[OC_SHA1_BYTES])
{
	stream_final(sha1_blocks, (UBYTE *)ctx->h, ctx->block, ctx->block_used,
	             ctx->total_bytes, OC_SHA1_BLOCK_BYTES, 8, 0);
	copy(out, ctx->h, OC_SHA1_BYTES);
	wipe(ctx, sizeof *ctx);
}

void oc_md5(const void *data, size_t length, uint8_t out[OC_MD5_BYTES])
{
	static const UBYTE iv[OC_MD5_BYTES] = OC_MD5_IV;
	UBYTE state[OC_MD5_BYTES], block[64];
	size_t used = 0;
	uint64_t total = 0;
	copy(state, iv, sizeof state);
	stream_update(md5_blocks, state, block, &used, &total, 64, data, length);
	stream_final(md5_blocks, state, block, used, total, 64, 8, 1);
	copy(out, state, OC_MD5_BYTES);
	wipe(block, sizeof block);
	wipe(state, sizeof state);
}

/* ---- one-call hashes, HMAC, HKDF, PBKDF2 ---- */

void oc_sha256(const void *data, size_t length, uint8_t out[OC_SHA256_BYTES])
{ struct OCBufferHash r = { data, length, out }; OC_SHA256(&r); }
void oc_sha384(const void *data, size_t length, uint8_t out[OC_SHA384_BYTES])
{ struct OCBufferHash r = { data, length, out }; OC_SHA384(&r); }
void oc_sha512(const void *data, size_t length, uint8_t out[OC_SHA512_BYTES])
{ struct OCBufferHash r = { data, length, out }; OC_SHA512(&r); }
void oc_sha1(const void *data, size_t length, uint8_t out[OC_SHA1_BYTES])
{ struct OCBufferHash r = { data, length, out }; OC_SHA1(&r); }

void oc_sha256_blocks(uint8_t state[OC_SHA256_BYTES], const void *data, size_t nblocks)
{ sha256_blocks(state, data, nblocks); }
void oc_sha512_blocks(uint8_t state[OC_SHA512_BYTES], const void *data, size_t nblocks)
{ sha512_blocks(state, data, nblocks); }
void oc_sha1_blocks(uint8_t state[OC_SHA1_BYTES], const void *data, size_t nblocks)
{ sha1_blocks(state, data, nblocks); }
void oc_md5_blocks(uint8_t state[OC_MD5_BYTES], const void *data, size_t nblocks)
{ md5_blocks(state, data, nblocks); }

void oc_hmac_sha256(const void *key, size_t key_length, const void *data, size_t data_length,
                    uint8_t out[OC_SHA256_BYTES])
{ struct OCHmacRequest r = { key, key_length, data, data_length, out }; OC_HMAC_SHA256(&r); }
void oc_hmac_sha384(const void *key, size_t key_length, const void *data, size_t data_length,
                    uint8_t out[OC_SHA384_BYTES])
{ struct OCHmacRequest r = { key, key_length, data, data_length, out }; OC_HMAC_SHA384(&r); }
void oc_hmac_sha1(const void *key, size_t key_length, const void *data, size_t data_length,
                  uint8_t out[OC_SHA1_BYTES])
{ struct OCHmacRequest r = { key, key_length, data, data_length, out }; OC_HMAC_SHA1(&r); }
void oc_hmac_sha512(const void *key, size_t key_length, const void *data, size_t data_length,
                    uint8_t out[OC_SHA512_BYTES])
{ struct OCHmacRequest r = { key, key_length, data, data_length, out }; OC_HMAC_SHA512(&r); }

size_t oc_hash_length(int hash)
{
	switch (hash) {
	case OC_HASH_SHA1: return OC_SHA1_BYTES;
	case OC_HASH_SHA256: return OC_SHA256_BYTES;
	case OC_HASH_SHA384: return OC_SHA384_BYTES;
	case OC_HASH_SHA512: return OC_SHA512_BYTES;
	}
	return 0;
}

int oc_hmac(int hash, const void *key, size_t key_length,
            const void *data, size_t data_length, uint8_t *out)
{
	if (!out || (!key && key_length) || (!data && data_length)) return -1;
	switch (hash) {
	case OC_HASH_SHA1: oc_hmac_sha1(key, key_length, data, data_length, out); return 0;
	case OC_HASH_SHA256: oc_hmac_sha256(key, key_length, data, data_length, out); return 0;
	case OC_HASH_SHA384: oc_hmac_sha384(key, key_length, data, data_length, out); return 0;
	case OC_HASH_SHA512: oc_hmac_sha512(key, key_length, data, data_length, out); return 0;
	}
	return -1;
}

int oc_hkdf_sha256(const void *salt, size_t salt_length, const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length, void *out, size_t out_length)
{
	struct OCHKDFRequest r = { salt, salt_length, ikm, ikm_length, info, info_length, out, out_length };
	return OC_HKDF_SHA256(&r) ? -1 : 0;
}

int oc_hkdf_sha384(const void *salt, size_t salt_length, const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length, void *out, size_t out_length)
{
	struct OCHKDFRequest r = { salt, salt_length, ikm, ikm_length, info, info_length, out, out_length };
	return OC_HKDF_SHA384(&r) ? -1 : 0;
}

int oc_pbkdf2(int hash, const void *password, size_t password_length,
              const void *salt, size_t salt_length, uint32_t iterations,
              void *out, size_t out_length)
{
	struct OCPBKDF2Request r = { hash, password, password_length, salt, salt_length,
	                             iterations, (UBYTE *)out, out_length };
	return OC_PBKDF2(&r) ? -1 : 0;
}

int oc_sha3_init(OCSHA3 *ctx, int variant)
{
	struct OCSHA3Request r = { ctx, variant, 0, 0, 0, 0 };
	return OC_SHA3Init(&r) ? -1 : 0;
}

void oc_sha3_update(OCSHA3 *ctx, const void *data, size_t length)
{
	struct OCSHA3Request r = { ctx, 0, data, length, 0, 0 };
	OC_SHA3Update(&r);
}

int oc_sha3_final(OCSHA3 *ctx, uint8_t *out, size_t out_length)
{
	struct OCSHA3Request r = { ctx, 0, 0, 0, out, out_length };
	return OC_SHA3Final(&r) ? -1 : 0;
}

int oc_sha3(int variant, const void *data, size_t length, uint8_t *out, size_t out_length)
{
	struct OCSHA3Request r = { 0, variant, data, length, out, out_length };
	return OC_SHA3(&r) ? -1 : 0;
}

/* ---- SSH's primitives ---- */

int oc_x25519(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES],
              const uint8_t point[OC_X25519_BYTES])
{
	struct OCX25519Request r = { out, scalar, point };
	if (!point) return -1;
	return OC_X25519(&r) ? -1 : 0;
}

void oc_x25519_base(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES])
{
	struct OCX25519Request r = { out, scalar, 0 };
	OC_X25519(&r);
}

int oc_ed25519_verify(const uint8_t sig[OC_ED25519_SIGNATURE_BYTES],
                      const uint8_t pk[OC_ED25519_PUBLIC_BYTES], const void *msg, size_t length)
{
	struct OCEd25519Request r = { sig, pk, msg, length };
	return OC_Ed25519Verify(&r) == 1;
}

void oc_sntrup761_keypair(uint8_t pk[OC_SNTRUP761_PK_BYTES], uint8_t sk[OC_SNTRUP761_SK_BYTES],
                          const uint8_t seed[OC_SEED_BYTES])
{
	struct OCKemRequest r = { pk, sk, 0, 0, seed };
	OC_SNTRUP761KeyPair(&r);
}

void oc_sntrup761_enc(uint8_t ct[OC_SNTRUP761_CT_BYTES], uint8_t ss[OC_SNTRUP761_SS_BYTES],
                      const uint8_t pk[OC_SNTRUP761_PK_BYTES], const uint8_t seed[OC_SEED_BYTES])
{
	struct OCKemRequest r = { (UBYTE *)pk, 0, ct, ss, seed };
	OC_SNTRUP761Enc(&r);
}

void oc_sntrup761_dec(uint8_t ss[OC_SNTRUP761_SS_BYTES], const uint8_t ct[OC_SNTRUP761_CT_BYTES],
                      const uint8_t sk[OC_SNTRUP761_SK_BYTES])
{
	struct OCKemRequest r = { 0, (UBYTE *)sk, (UBYTE *)ct, ss, 0 };
	OC_SNTRUP761Dec(&r);
}

void oc_chacha20_xor(uint8_t *out, const uint8_t *in, size_t length,
                     const uint8_t key[32], const uint8_t nonce[8], uint64_t counter)
{
	struct OCChaChaRequest r = { out, in, length, key, nonce,
	                             (ULONG)(counter >> 32), (ULONG)counter };
	OC_ChaCha20(&r);
}

void oc_expand_seed(uint8_t *out, size_t length, const uint8_t seed[OC_SEED_BYTES],
                    const char label[8])
{
	oc_chacha20_xor(out, 0, length, seed, (const uint8_t *)label, 0);
}

void oc_poly1305(uint8_t tag[16], const void *data, size_t length, const uint8_t key[32])
{
	struct OCPolyRequest r = { tag, data, length, key };
	OC_Poly1305(&r);
}

void oc_ghash(uint8_t y[16], const uint8_t h[16], const void *data, size_t length)
{
	struct OCGHASHRequest r = { y, h, data, length };
	OC_GHASH(&r);
}

int oc_aes(uint8_t *buf, size_t length, const uint8_t *key, size_t keylen,
           const uint8_t iv[16], int mode)
{
	struct OCAESRequest r = { buf, length, key, keylen, iv, (ULONG)mode };
	return OC_AES(&r) ? -1 : 0;
}

/* ---- public keys ---- */

int oc_rsa_public(uint8_t *out, const uint8_t *sig, const uint8_t *n, size_t n_length,
                  const uint8_t *e, size_t e_length)
{
	struct OCRSARequest r = { out, sig, n, n_length, e, e_length };
	return OC_RSAPublic(&r) ? -1 : 0;
}

int oc_ecdsa_verify(int curve, const uint8_t *qx, const uint8_t *qy,
                    const uint8_t *r_, const uint8_t *s, const uint8_t *hash, size_t hash_length)
{
	struct OCECDSARequest r = { curve, qx, qy, r_, s, hash, hash_length };
	return OC_ECDSAVerify(&r) == 1;
}

int oc_ec_mul(int curve, uint8_t *point, size_t point_length,
              const uint8_t *scalar, size_t scalar_length)
{
	struct OCECMulRequest r = { curve, point, point_length, scalar, scalar_length };
	return OC_ECMul(&r) == 1;
}

int oc_ec_mulgen(int curve, uint8_t *point, const uint8_t *scalar, size_t scalar_length)
{
	struct OCECMulRequest r = { curve, point, 0, scalar, scalar_length };
	LONG n = OC_ECMulGen(&r);
	return n > 0 ? (int)n : 0;
}

int oc_rsa_pss_verify(const uint8_t *sig, const uint8_t *n, size_t n_length,
                      const uint8_t *e, size_t e_length,
                      const uint8_t *mhash, size_t hash_length, long salt_length)
{
	struct OCRSAPSSRequest r = { sig, n, n_length, e, e_length, mhash, hash_length, salt_length };
	return OC_RSAPSSVerify(&r) == 1;
}

/* ---- FileZilla's: key files, signing, Diffie-Hellman ---- */

size_t oc_argon2_memory(uint32_t m_kib, uint32_t lanes)
{
	uint32_t m = m_kib;
	if (!lanes || lanes > 0xffffff) return 0;
	if (m < 8 * lanes) m = 8 * lanes;
	return (size_t)(m - m % (4 * lanes)) * 1024;
}

int oc_argon2(int type, uint8_t *out, uint32_t out_length,
              const void *password, size_t password_length,
              const void *salt, size_t salt_length,
              const void *secret, size_t secret_length,
              const void *ad, size_t ad_length,
              uint32_t t_cost, uint32_t m_kib, uint32_t lanes, void *memory)
{
	struct OCArgon2Request r = { type, out, out_length, password, password_length,
	                             salt, salt_length, secret, secret_length, ad, ad_length,
	                             t_cost, m_kib, lanes };
	(void)memory;
	return OC_Argon2(&r) ? -1 : 0;
}

void oc_ed25519_public_key(uint8_t pk[OC_ED25519_PUBLIC_BYTES], const uint8_t seed[32])
{
	struct OCEd25519SignRequest r = { pk, seed, 0, 0 };
	OC_Ed25519PublicKey(&r);
}

void oc_ed25519_sign(uint8_t sig[OC_ED25519_SIGNATURE_BYTES], const uint8_t seed[32],
                     const void *msg, size_t length)
{
	struct OCEd25519SignRequest r = { sig, seed, msg, length };
	OC_Ed25519Sign(&r);
}

int oc_ecdsa_sign(int curve, uint8_t *r_, uint8_t *s, const uint8_t *d,
                  const uint8_t *hash, size_t hash_length)
{
	struct OCECDSASignRequest r = { curve, r_, s, d, hash, hash_length };
	return OC_ECDSASign(&r) ? -1 : 0;
}

int oc_ec_keygen(int curve, uint8_t *d, uint8_t *point, const uint8_t *seed, size_t seed_length)
{
	struct OCECKeyGenRequest r = { curve, d, point, seed, seed_length };
	LONG n = OC_ECKeyGen(&r);
	return n > 0 ? (int)n : 0;
}

int oc_modexp(uint8_t *out, const uint8_t *base, size_t base_length,
              const uint8_t *exponent, size_t exponent_length,
              const uint8_t *modulus, size_t modulus_length)
{
	struct OCModExpRequest r = { out, base, base_length, exponent, exponent_length,
	                             modulus, modulus_length };
	return OC_ModExp(&r) ? -1 : 0;
}

int oc_rsa_private(uint8_t *out, const uint8_t *in,
                   const uint8_t *n, size_t n_length, const uint8_t *e, size_t e_length,
                   const uint8_t *d, size_t d_length, const uint8_t *p, size_t p_length,
                   const uint8_t *q, size_t q_length, const uint8_t *dp, size_t dp_length,
                   const uint8_t *dq, size_t dq_length, const uint8_t *qinv, size_t qinv_length)
{
	struct OCRSAPrivateRequest r = { out, in, n, n_length, e, e_length, d, d_length,
	                                 p, p_length, q, q_length, dp, dp_length,
	                                 dq, dq_length, qinv, qinv_length };
	return OC_RSAPrivate(&r) ? -1 : 0;
}

int oc_is_probable_prime(const uint8_t *number, size_t length, int rounds)
{
	struct OCPrimeRequest r = { number, length, rounds };
	LONG v = OC_IsProbablePrime(&r);
	return v < 0 ? -1 : (int)v;
}

int oc_ct_equal(const void *a, const void *b, size_t length)
{
	struct OCCompareRequest r = { a, b, length };
	return (int)OC_CtEqual(&r);
}

void oc_cleanse(void *p, size_t length)
{
	struct OCCleanseRequest r = { p, length };
	OC_Cleanse(&r);
}
