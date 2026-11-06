/* the host stub test: gfopencrypto.library's calls, made with the real
 * code (renamed real_oc_* by rename.h), as library/opencrypto_lib.c makes
 * them. MIT, Copyright (c) 2026 AmiCradle Team. */
#include "rename.h"
#include <stdlib.h>
#include <exec/types.h>
#include <proto/gfopencrypto.h>

struct Library *gfopen_stub_open(const char *name, ULONG version, UWORD revision)
{ (void)name; (void)version; (void)revision; return (struct Library *)1; }

LONG OC_SHA256(struct OCBufferHash *r) { oc_sha256(r->data, r->length, r->out); return 0; }
LONG OC_SHA384(struct OCBufferHash *r) { oc_sha384(r->data, r->length, r->out); return 0; }
LONG OC_SHA512(struct OCBufferHash *r) { oc_sha512(r->data, r->length, r->out); return 0; }
LONG OC_SHA1(struct OCBufferHash *r) { oc_sha1(r->data, r->length, r->out); return 0; }
LONG OC_HMAC_SHA256(struct OCHmacRequest *r) { oc_hmac_sha256(r->key, r->key_length, r->data, r->data_length, r->out); return 0; }
LONG OC_HMAC_SHA384(struct OCHmacRequest *r) { oc_hmac_sha384(r->key, r->key_length, r->data, r->data_length, r->out); return 0; }
LONG OC_HMAC_SHA1(struct OCHmacRequest *r) { oc_hmac_sha1(r->key, r->key_length, r->data, r->data_length, r->out); return 0; }
LONG OC_HMAC_SHA512(struct OCHmacRequest *r) { oc_hmac_sha512(r->key, r->key_length, r->data, r->data_length, r->out); return 0; }
LONG OC_HKDF_SHA256(struct OCHKDFRequest *r) { return oc_hkdf_sha256(r->salt, r->salt_length, r->ikm, r->ikm_length, r->info, r->info_length, r->out, r->out_length); }
LONG OC_HKDF_SHA384(struct OCHKDFRequest *r) { return oc_hkdf_sha384(r->salt, r->salt_length, r->ikm, r->ikm_length, r->info, r->info_length, r->out, r->out_length); }
LONG OC_CtEqual(struct OCCompareRequest *r) { return oc_ct_equal(r->a, r->b, r->length) ? 1 : 0; }
LONG OC_Cleanse(struct OCCleanseRequest *r) { oc_cleanse(r->data, r->length); return 0; }
LONG OC_X25519(struct OCX25519Request *r)
{
    static const UBYTE nine[32] = { 9 };
    return oc_x25519(r->out, r->scalar, r->point ? r->point : nine);
}
LONG OC_Ed25519Verify(struct OCEd25519Request *r) { return oc_ed25519_verify(r->sig, r->pk, r->msg, r->length); }
LONG OC_SNTRUP761KeyPair(struct OCKemRequest *r) { oc_sntrup761_keypair(r->pk, r->sk, r->seed); return 0; }
LONG OC_SNTRUP761Enc(struct OCKemRequest *r) { oc_sntrup761_enc(r->ct, r->ss, r->pk, r->seed); return 0; }
LONG OC_SNTRUP761Dec(struct OCKemRequest *r) { oc_sntrup761_dec(r->ss, r->ct, r->sk); return 0; }
LONG OC_SHA256Blocks(struct OCBlocksRequest *r) { if (r->blocks) oc_sha256_blocks(r->state, r->data, r->blocks); return 0; }
LONG OC_SHA512Blocks(struct OCBlocksRequest *r) { if (r->blocks) oc_sha512_blocks(r->state, r->data, r->blocks); return 0; }
LONG OC_SHA1Blocks(struct OCBlocksRequest *r) { if (r->blocks) oc_sha1_blocks(r->state, r->data, r->blocks); return 0; }
LONG OC_MD5Blocks(struct OCBlocksRequest *r) { if (r->blocks) oc_md5_blocks(r->state, r->data, r->blocks); return 0; }
LONG OC_ChaCha20(struct OCChaChaRequest *r)
{
    if (r->length)
        oc_chacha20_xor(r->out, r->in, r->length, r->key, r->nonce,
                        ((uint64_t)r->counter_hi << 32) | r->counter_lo);
    return 0;
}
LONG OC_Poly1305(struct OCPolyRequest *r) { oc_poly1305(r->tag, r->data, r->length, r->key); return 0; }
LONG OC_AES(struct OCAESRequest *r) { return r->length ? (oc_aes(r->buf, r->length, r->key, r->key_length, r->iv, r->mode) ? -1 : 0) : 0; }
LONG OC_GHASH(struct OCGHASHRequest *r) { if (r->length) oc_ghash(r->y, r->h, r->data, r->length); return 0; }
LONG OC_RSAPublic(struct OCRSARequest *r) { return oc_rsa_public(r->out, r->sig, r->n, r->n_length, r->e, r->e_length) ? -1 : 0; }
LONG OC_ECDSAVerify(struct OCECDSARequest *r) { return oc_ecdsa_verify(r->curve, r->qx, r->qy, r->r, r->s, r->hash, r->hash_length); }
LONG OC_RSAPSSVerify(struct OCRSAPSSRequest *r) { return oc_rsa_pss_verify(r->sig, r->n, r->n_length, r->e, r->e_length, r->hash, r->hash_length, r->salt_length); }
LONG OC_ECMul(struct OCECMulRequest *r) { return oc_ec_mul(r->curve, r->point, r->point_length, r->scalar, r->scalar_length); }
LONG OC_ECMulGen(struct OCECMulRequest *r) { return oc_ec_mulgen(r->curve, r->point, r->scalar, r->scalar_length); }
LONG OC_PBKDF2(struct OCPBKDF2Request *r) { return oc_pbkdf2(r->hash, r->password, r->password_length, r->salt, r->salt_length, r->iterations, r->out, r->out_length) ? -1 : 0; }
LONG OC_SHA3(struct OCSHA3Request *r) { return oc_sha3(r->variant, r->data, r->length, r->out, r->out_length) ? -1 : 0; }
LONG OC_SHA3Init(struct OCSHA3Request *r) { return oc_sha3_init(r->ctx, r->variant) ? -1 : 0; }
LONG OC_SHA3Update(struct OCSHA3Request *r) { oc_sha3_update(r->ctx, r->data, r->length); return 0; }
LONG OC_SHA3Final(struct OCSHA3Request *r) { return oc_sha3_final(r->ctx, r->out, r->out_length) ? -1 : 0; }
LONG OC_Argon2(struct OCArgon2Request *r)
{
    size_t n = oc_argon2_memory(r->m_kib, r->lanes);
    void *m = n ? malloc(n) : NULL;   /* malloc is 8-byte aligned or better */
    LONG rc = m ? oc_argon2(r->type, r->out, r->out_length, r->password, r->password_length, r->salt,
                            r->salt_length, r->secret, r->secret_length, r->ad, r->ad_length,
                            r->passes, r->m_kib, r->lanes, m) : -3;
    free(m);
    return rc ? -1 : 0;
}
LONG OC_Ed25519Sign(struct OCEd25519SignRequest *r) { oc_ed25519_sign(r->out, r->seed, r->msg, r->length); return 0; }
LONG OC_Ed25519PublicKey(struct OCEd25519SignRequest *r) { oc_ed25519_public_key(r->out, r->seed); return 0; }
LONG OC_ECDSASign(struct OCECDSASignRequest *r) { return oc_ecdsa_sign(r->curve, r->r, r->s, r->d, r->hash, r->hash_length) ? -1 : 0; }
LONG OC_ECKeyGen(struct OCECKeyGenRequest *r) { return oc_ec_keygen(r->curve, r->d, r->point, r->seed, r->seed_length); }
LONG OC_ModExp(struct OCModExpRequest *r) { return oc_modexp(r->out, r->base, r->base_length, r->exponent, r->exponent_length, r->modulus, r->modulus_length) ? -1 : 0; }
LONG OC_RSAPrivate(struct OCRSAPrivateRequest *r)
{
    return oc_rsa_private(r->out, r->in, r->n, r->n_length, r->e, r->e_length, r->d, r->d_length,
                          r->p, r->p_length, r->q, r->q_length, r->dp, r->dp_length,
                          r->dq, r->dq_length, r->qinv, r->qinv_length) ? -1 : 0;
}
LONG OC_IsProbablePrime(struct OCPrimeRequest *r) { return oc_is_probable_prime(r->number, r->length, r->rounds); }

/* the real code, for test_stub.c to compare with */
void ref_md5(const void *d, size_t n, uint8_t *out) { oc_md5(d, n, out); }
size_t ref_argon2_memory(uint32_t m, uint32_t l) { return oc_argon2_memory(m, l); }
void ref_chacha20_xor(uint8_t *out, const uint8_t *in, size_t n, const uint8_t *k, const uint8_t *nonce, uint64_t c)
{ oc_chacha20_xor(out, in, n, k, nonce, c); }
void ref_expand_seed(uint8_t *out, size_t n, const uint8_t *seed, const char *label) { oc_expand_seed(out, n, seed, label); }
