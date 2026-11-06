#ifndef OPENCRYPTO_OPENCRYPTO_H
#define OPENCRYPTO_OPENCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SHA256_BYTES 32
#define OC_SHA256_BLOCK_BYTES 64
#define OC_SHA384_BYTES 48
#define OC_SHA512_BYTES 64
#define OC_SHA512_BLOCK_BYTES 128
#define OC_SHA1_BYTES 20
#define OC_SHA1_BLOCK_BYTES 64

typedef struct OCSHA256 {
    uint32_t h[8];
    uint64_t total_bytes;
    uint8_t block[OC_SHA256_BLOCK_BYTES];
    size_t block_used;
} OCSHA256;

typedef struct OCSHA512 {
    uint64_t h[8];
    uint64_t total_bytes;
    uint8_t block[OC_SHA512_BLOCK_BYTES];
    size_t block_used;
} OCSHA512;

typedef struct OCSHA1 {
    uint32_t h[5];
    uint64_t total_bytes;
    uint8_t block[OC_SHA1_BLOCK_BYTES];
    size_t block_used;
} OCSHA1;

void oc_sha256_init(OCSHA256 *ctx);
void oc_sha256_update(OCSHA256 *ctx, const void *data, size_t length);
void oc_sha256_final(OCSHA256 *ctx, uint8_t out[OC_SHA256_BYTES]);
void oc_sha256(const void *data, size_t length, uint8_t out[OC_SHA256_BYTES]);

void oc_hmac_sha256(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[OC_SHA256_BYTES]);

int oc_hkdf_sha256(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length);

void oc_sha384(const void *data, size_t length, uint8_t out[OC_SHA384_BYTES]);
void oc_sha512(const void *data, size_t length, uint8_t out[OC_SHA512_BYTES]);

void oc_hmac_sha384(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[OC_SHA384_BYTES]);

int oc_hkdf_sha384(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length);

void oc_sha512_init(OCSHA512 *ctx);
void oc_sha512_update(OCSHA512 *ctx, const void *data, size_t length);
void oc_sha512_final(OCSHA512 *ctx, uint8_t out[OC_SHA512_BYTES]);

/* The compression functions over whole blocks; the chaining value is kept
 * as big-endian bytes (32 for SHA-256, 64 for SHA-512), the same on every
 * machine. For callers that do their own buffering and padding. */
void oc_sha256_blocks(uint8_t state[OC_SHA256_BYTES], const void *data, size_t nblocks);
void oc_sha512_blocks(uint8_t state[OC_SHA512_BYTES], const void *data, size_t nblocks);

/* SHA-1 (FIPS 180-4, 6 Nov 2026), for formats that name it (file identity
 * checks, older protocols). Not collision resistant: new designs use
 * SHA-256. oc_sha1_blocks keeps the chaining value as 20 big-endian bytes. */
void oc_sha1_init(OCSHA1 *ctx);
void oc_sha1_update(OCSHA1 *ctx, const void *data, size_t length);
void oc_sha1_final(OCSHA1 *ctx, uint8_t out[OC_SHA1_BYTES]);
void oc_sha1(const void *data, size_t length, uint8_t out[OC_SHA1_BYTES]);
void oc_sha1_blocks(uint8_t state[OC_SHA1_BYTES], const void *data, size_t nblocks);

/* MD5 (RFC 1321), only for what still names it (TLS 1.0 and 1.1); the
 * block function keeps the 16-byte chaining value little-endian */
#define OC_MD5_BYTES 16
void oc_md5(const void *data, size_t length, uint8_t out[OC_MD5_BYTES]);
void oc_md5_blocks(uint8_t state[OC_MD5_BYTES], const void *data, size_t nblocks);

/* ---- for SSH's key exchanges, host keys and default cipher (8 Oct 2026) ---- */

#define OC_SEED_BYTES 32
#define OC_X25519_BYTES 32
#define OC_ED25519_PUBLIC_BYTES 32
#define OC_ED25519_SIGNATURE_BYTES 64
#define OC_SNTRUP761_PK_BYTES 1158
#define OC_SNTRUP761_SK_BYTES 1763
#define OC_SNTRUP761_CT_BYTES 1039
#define OC_SNTRUP761_SS_BYTES 32

/* X25519 (RFC 7748), constant time: out = scalar * point. 0, or -1 when
 * the result is all zeros (a small-order point; the caller refuses it). */
int oc_x25519(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES],
              const uint8_t point[OC_X25519_BYTES]);
void oc_x25519_base(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES]);

/* Ed25519 verification (RFC 8032): 1 when sig is pk's signature of msg. */
int oc_ed25519_verify(const uint8_t sig[OC_ED25519_SIGNATURE_BYTES],
                      const uint8_t pk[OC_ED25519_PUBLIC_BYTES],
                      const void *msg, size_t length);

/* sntrup761 as SSH's sntrup761x25519-sha512 uses it, constant time. The
 * randomness comes from a 32-byte seed (expanded with ChaCha20), so the
 * caller supplies fresh secret random bytes for every call. */
void oc_sntrup761_keypair(uint8_t pk[OC_SNTRUP761_PK_BYTES], uint8_t sk[OC_SNTRUP761_SK_BYTES],
                          const uint8_t seed[OC_SEED_BYTES]);
void oc_sntrup761_enc(uint8_t ct[OC_SNTRUP761_CT_BYTES], uint8_t ss[OC_SNTRUP761_SS_BYTES],
                      const uint8_t pk[OC_SNTRUP761_PK_BYTES], const uint8_t seed[OC_SEED_BYTES]);
void oc_sntrup761_dec(uint8_t ss[OC_SNTRUP761_SS_BYTES], const uint8_t ct[OC_SNTRUP761_CT_BYTES],
                      const uint8_t sk[OC_SNTRUP761_SK_BYTES]);

/* ChaCha20 with a 64-bit nonce and 64-bit block counter (Bernstein's
 * original, as chacha20-poly1305@openssh.com uses); in may be NULL for the
 * key stream itself, or equal to out. Poly1305 (RFC 8439 section 2.5). */
void oc_chacha20_xor(uint8_t *out, const uint8_t *in, size_t length,
                     const uint8_t key[32], const uint8_t nonce[8], uint64_t counter);
void oc_poly1305(uint8_t tag[16], const void *data, size_t length, const uint8_t key[32]);
/* GHASH (NIST SP 800-38D 6.4), AES-GCM's hash: y = (y + X_i) . h for each
 * 16-byte part of the data (the last padded with zeros), constant time */
void oc_ghash(uint8_t y[16], const uint8_t h[16], const void *data, size_t length);
/* length bytes from a seed: ChaCha20's key stream, the label as nonce */
void oc_expand_seed(uint8_t *out, size_t length, const uint8_t seed[OC_SEED_BYTES],
                    const char label[8]);

/* AES-128/192/256 (FIPS 197), constant time. buf is changed in place;
 * iv is the IV (CBC) or the first counter block (CTR: a 128-bit big-endian
 * counter, SSH's SDCTR); the caller moves its IV or counter on itself.
 * CBC and ECB take whole blocks. 0, or -1 for a bad key length or mode. */
#define OC_AES_CTR 0
#define OC_AES_CBC_ENCRYPT 1
#define OC_AES_CBC_DECRYPT 2
#define OC_AES_ECB_ENCRYPT 3
int oc_aes(uint8_t *buf, size_t length, const uint8_t *key, size_t keylen,
           const uint8_t iv[16], int mode);

/* RSA (PKCS #1 v1.5 or anything else built on it): out = sig^e mod n, all
 * big-endian, out as long as n. Public values only: not constant time.
 * 0, or -1 when sig >= n, n is even or longer than OC_RSA_MAX_BYTES. */
#define OC_RSA_MAX_BYTES 1024
int oc_rsa_public(uint8_t *out, const uint8_t *sig, const uint8_t *n, size_t n_length,
                  const uint8_t *e, size_t e_length);

/* ECDSA verification on NIST P-256, P-384 and P-521 (curve = 256, 384,
 * 521): the public point and the signature's r and s as big-endian
 * integers of the curve's size ((bits + 7) / 8 bytes), the hash as it came
 * (truncated to the curve's size as FIPS 186 says). 1 when valid. */
int oc_ecdsa_verify(int curve, const uint8_t *qx, const uint8_t *qy,
                    const uint8_t *r, const uint8_t *s,
                    const uint8_t *hash, size_t hash_length);

/* ECDH on P-256, P-384 and P-521 (curve = 256, 384, 521), constant time:
 * oc_ec_mul() sets point (X9.62 uncompressed, 04 || x || y, 1 + 2 bytes
 * of the curve's size) to scalar . point, after checking the point is on
 * the curve; 1, or 0 for a bad point, curve or result. oc_ec_mulgen()
 * writes scalar . G there and returns its length (0 on failure). The
 * scalar is big-endian, any length. */
int oc_ec_mul(int curve, uint8_t *point, size_t point_length,
              const uint8_t *scalar, size_t scalar_length);
int oc_ec_mulgen(int curve, uint8_t *point, const uint8_t *scalar, size_t scalar_length);

/* RSASSA-PSS verification (RFC 8017 section 8.1.2), as TLS 1.3 uses it
 * (rsa_pss_rsae_*): MGF1 with the message's own hash, which hash_length
 * names (32 SHA-256, 48 SHA-384, 64 SHA-512). salt_length is the salt's
 * length, or -1 for any (TLS 1.3 wants the hash's length). 1 when sig is
 * a signature of the hash mhash under (n, e), 0 when not.
 * oc_emsa_pss_verify() is the encoding check alone, on em = sig^e mod n
 * (em_length bytes, the modulus mod_bits long), with the hash as a
 * function, for callers that do the RSA operation and hashing their own
 * way. Public values only: not constant time. (20 October 2026) */
typedef void (*oc_hash_fn)(const void *data, size_t length, uint8_t *out);
int oc_rsa_pss_verify(const uint8_t *sig, const uint8_t *n, size_t n_length,
                      const uint8_t *e, size_t e_length,
                      const uint8_t *mhash, size_t hash_length, long salt_length);
int oc_emsa_pss_verify(const uint8_t *em, size_t em_length, size_t mod_bits,
                       const uint8_t *mhash, size_t hash_length, long salt_length,
                       oc_hash_fn hash);

/* What gfopencrypto.library's OC_Accelerated() answers: the operations this
 * machine runs as host code (AmiCradle's AC090); 0 on a real Amiga. */
#define OCF_X25519    (1u << 0)
#define OCF_ED25519   (1u << 1)
#define OCF_SNTRUP761 (1u << 2)
#define OCF_SHA256    (1u << 3)
#define OCF_SHA512    (1u << 4)
#define OCF_CHACHA20  (1u << 5)
#define OCF_POLY1305  (1u << 6)
#define OCF_AES       (1u << 7)
#define OCF_RSA       (1u << 8)
#define OCF_ECDSA     (1u << 9)

/* ---- for FileZilla's SFTP and FTPS, and its key files (6 November 2026) ---- */

/* The hashes HMAC, PBKDF2 and the rest take by name */
#define OC_HASH_SHA1   1
#define OC_HASH_SHA256 2
#define OC_HASH_SHA384 3
#define OC_HASH_SHA512 4
size_t oc_hash_length(int hash);        /* 20, 32, 48, 64; 0 for an unknown hash */

/* HMAC (RFC 2104) with any of the four: out gets oc_hash_length(hash)
 * bytes. 0, or -1 for an unknown hash or a NULL pointer with a length. */
int oc_hmac(int hash, const void *key, size_t key_length,
            const void *data, size_t data_length, uint8_t *out);
void oc_hmac_sha1(const void *key, size_t key_length,
                  const void *data, size_t data_length, uint8_t out[OC_SHA1_BYTES]);
void oc_hmac_sha512(const void *key, size_t key_length,
                    const void *data, size_t data_length, uint8_t out[OC_SHA512_BYTES]);

/* PBKDF2 (RFC 8018 section 5.2) with HMAC over the hash: out_length bytes
 * from the password, the salt and iterations (1 or more) rounds. Each round
 * after the first is two compressions. 0, or -1 for bad arguments. */
int oc_pbkdf2(int hash, const void *password, size_t password_length,
              const void *salt, size_t salt_length, uint32_t iterations,
              void *out, size_t out_length);

/* SHA-3 (FIPS 202): SHA3-256, SHA3-384, SHA3-512 and SHAKE256. Streaming:
 * init, update as often as wanted, final (which wipes the context). final's
 * out_length is the digest's size for SHA-3 (32, 48, 64), any number of
 * bytes for SHAKE256. 0, or -1 for an unknown variant or a wrong length.
 * oc_keccak_f1600 is the permutation alone, lanes in the host's order. */
#define OC_SHA3_256 256
#define OC_SHA3_384 384
#define OC_SHA3_512 512
#define OC_SHAKE256 0x10100
typedef struct OCSHA3 {
    uint64_t a[25];
    uint32_t rate, used, out_length;
    uint8_t domain, pad[3];
} OCSHA3;
int oc_sha3_init(OCSHA3 *ctx, int variant);
void oc_sha3_update(OCSHA3 *ctx, const void *data, size_t length);
int oc_sha3_final(OCSHA3 *ctx, uint8_t *out, size_t out_length);
int oc_sha3(int variant, const void *data, size_t length, uint8_t *out, size_t out_length);
void oc_keccak_f1600(uint64_t state[25]);

/* BLAKE2b (RFC 7693), unkeyed, 1 to 64 bytes out; Argon2's hash */
int oc_blake2b(uint8_t *out, size_t out_length, const void *data, size_t length);

/* Argon2 (RFC 9106, version 0x13). type: OC_ARGON2D, OC_ARGON2I or
 * OC_ARGON2ID (PuTTY's key files may name any of them). memory is
 * oc_argon2_memory(m_kib, lanes) bytes, 8-byte aligned, from the caller
 * (wiped before the call returns). The salt is 8 bytes or more, m_kib at
 * least 8 * lanes, out_length 4 or more. 0, or -1 for bad arguments. */
#define OC_ARGON2D  0
#define OC_ARGON2I  1
#define OC_ARGON2ID 2
size_t oc_argon2_memory(uint32_t m_kib, uint32_t lanes);
int oc_argon2(int type, uint8_t *out, uint32_t out_length,
              const void *password, size_t password_length,
              const void *salt, size_t salt_length,
              const void *secret, size_t secret_length,
              const void *ad, size_t ad_length,
              uint32_t t_cost, uint32_t m_kib, uint32_t lanes, void *memory);

/* Ed25519 (RFC 8032) from the 32-byte private seed: the public key, and a
 * signature of msg. Constant time. */
void oc_ed25519_public_key(uint8_t pk[OC_ED25519_PUBLIC_BYTES], const uint8_t seed[32]);
void oc_ed25519_sign(uint8_t sig[OC_ED25519_SIGNATURE_BYTES], const uint8_t seed[32],
                     const void *msg, size_t length);

/* ECDSA on P-256, P-384, P-521 (curve = 256, 384, 521). oc_ecdsa_sign: r
 * and s ((curve + 7) / 8 bytes each, big-endian) for the hash under the
 * private key d (the same size), the nonce RFC 6979's with the hash that
 * hash_length names (20 SHA-1, 32 SHA-256, 48 SHA-384, 64 SHA-512); 0, or
 * -1 for bad arguments or d not in 1 .. n - 1. oc_ec_keygen: d = 1 + seed
 * mod (n - 1), seed fresh secret random bytes, at least 8 more than d's
 * size; point = d G (04 || x || y); the point's length, or 0 on failure.
 * Constant time. */
int oc_ecdsa_sign(int curve, uint8_t *r, uint8_t *s, const uint8_t *d,
                  const uint8_t *hash, size_t hash_length);
int oc_ec_keygen(int curve, uint8_t *d, uint8_t *point, const uint8_t *seed, size_t seed_length);

/* out = base^exponent mod modulus, constant time in the base and the
 * exponent (every bit of its exponent_length bytes is used), for
 * Diffie-Hellman groups 14 to 18 and group exchange. The modulus is odd, up
 * to OC_RSA_MAX_BYTES; out is modulus_length bytes. 0, or -1. */
int oc_modexp(uint8_t *out, const uint8_t *base, size_t base_length,
              const uint8_t *exponent, size_t exponent_length,
              const uint8_t *modulus, size_t modulus_length);

/* RSA's private operation, out = in^d mod n, with the CRT and in constant
 * time; all big-endian, out and in n_length bytes. dp, dq (d mod p - 1,
 * q - 1) and qinv (1/q mod p) may be NULL: they are made from d, p and q.
 * The answer is checked with e before it is given (a fault or a wrong key
 * gives -1 and zeros, never a bad signature). Padding is the caller's.
 * 0, or -1. */
int oc_rsa_private(uint8_t *out, const uint8_t *in,
                   const uint8_t *n, size_t n_length,
                   const uint8_t *e, size_t e_length,
                   const uint8_t *d, size_t d_length,
                   const uint8_t *p, size_t p_length,
                   const uint8_t *q, size_t q_length,
                   const uint8_t *dp, size_t dp_length,
                   const uint8_t *dq, size_t dq_length,
                   const uint8_t *qinv, size_t qinv_length);

/* Miller-Rabin after trial division, for public numbers (a group
 * exchange's prime): base 2, then rounds - 1 bases made from the number's
 * SHA-512 (rounds 0: 40). 1 probably prime, 0 composite, -1 bad arguments. */
int oc_is_probable_prime(const uint8_t *number, size_t length, int rounds);

int oc_ct_equal(const void *a, const void *b, size_t length);
void oc_cleanse(void *p, size_t length);

#ifdef __cplusplus
}
#endif

#endif
