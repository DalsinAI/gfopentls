/* libgfopencrypto.a's oc_emsa_pss_verify(): no library call takes a C hash
 * function, so the encoding check itself is linked (it is public-value
 * arithmetic only). MIT, Copyright (c) 2026 AmiCradle Team. */
#include "../src/opencrypto_pss.c"
