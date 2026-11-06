/* BearSSL's own MD5, SHA-1 and SHA-2 code under other names: the host
 * tests' reference for ot_glue.c, which defines BearSSL's names over
 * GFOpenCrypto (CMakeLists.txt, bearssl_hash_ref). Test only. */
#ifndef BEARSSL_HASH_REF_H
#define BEARSSL_HASH_REF_H
#define br_md5_IV ref_md5_IV
#define br_md5_init ref_md5_init
#define br_md5_out ref_md5_out
#define br_md5_round ref_md5_round
#define br_md5_set_state ref_md5_set_state
#define br_md5_state ref_md5_state
#define br_md5_update ref_md5_update
#define br_md5_vtable ref_md5_vtable
#define br_sha1_IV ref_sha1_IV
#define br_sha1_init ref_sha1_init
#define br_sha1_out ref_sha1_out
#define br_sha1_round ref_sha1_round
#define br_sha1_set_state ref_sha1_set_state
#define br_sha1_state ref_sha1_state
#define br_sha1_update ref_sha1_update
#define br_sha1_vtable ref_sha1_vtable
#define br_sha224_IV ref_sha224_IV
#define br_sha224_init ref_sha224_init
#define br_sha224_out ref_sha224_out
#define br_sha224_set_state ref_sha224_set_state
#define br_sha224_state ref_sha224_state
#define br_sha224_update ref_sha224_update
#define br_sha224_vtable ref_sha224_vtable
#define br_sha256_IV ref_sha256_IV
#define br_sha256_init ref_sha256_init
#define br_sha256_out ref_sha256_out
#define br_sha256_vtable ref_sha256_vtable
#define br_sha2small_round ref_sha2small_round
#define br_sha384_init ref_sha384_init
#define br_sha384_out ref_sha384_out
#define br_sha384_set_state ref_sha384_set_state
#define br_sha384_state ref_sha384_state
#define br_sha384_update ref_sha384_update
#define br_sha384_vtable ref_sha384_vtable
#define br_sha512_init ref_sha512_init
#define br_sha512_out ref_sha512_out
#define br_sha512_vtable ref_sha512_vtable
#endif
