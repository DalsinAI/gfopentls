/* libgfopencrypto.a's oc_blake2b(): BLAKE2b alone has no library call, so
 * it is linked here. Argon2 itself goes to the library (gfopencrypto_stub.c);
 * this member's own copies are renamed out of the way and never called.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#define oc_argon2 ocstub_unused_argon2
#define oc_argon2_memory ocstub_unused_argon2_memory
#include "../src/opencrypto_argon2.c"
