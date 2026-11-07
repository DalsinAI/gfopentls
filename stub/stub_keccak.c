/* libgfopencrypto.a's oc_keccak_f1600(): the permutation alone has no
 * library call, so it is linked here. SHA-3 itself goes to the library
 * (gfopencrypto_stub.c); this member's own copies are renamed out of the
 * way and never called. MIT, Copyright (c) 2026 AmiCradle Team. */
#define oc_sha3_init ocstub_unused_sha3_init
#define oc_sha3_update ocstub_unused_sha3_update
#define oc_sha3_final ocstub_unused_sha3_final
#define oc_sha3 ocstub_unused_sha3
#include "../src/opencrypto_sha3.c"
