/* The services card for the host tests: gfopenservice's opentls.key/1 host
 * code (opentls_key.c, a copy) called in-process, as the card would.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"
#include "opentls_key.h"
#include "svc_host.h"

static LONG host_call(UWORD op, ULONG arg, const ULONG extra[4], struct ot_sbuf buf[4], ULONG *result, ULONG *aux)
{
    struct otk_buffer b[4];
    uint32_t x[4], r = 0, a = 0;
    int i, status;
    for (i = 0; i < 4; ++i) {
        b[i].in = buf[i].in;
        b[i].out = buf[i].out;
        b[i].length = buf[i].length;
        b[i].written = 0;
        x[i] = extra[i];
    }
    status = otk_call(op, arg, x, b, &r, &a);
    for (i = 0; i < 4; ++i) buf[i].written = b[i].written;
    *result = r;
    *aux = a;
    return status;
}

void svc_host_install(void)
{
    ot_svc_install(host_call, OTSVC_WHERE_CARD);
}

unsigned long svc_host_calls(void)
{
    return ot_svc_calls();
}
