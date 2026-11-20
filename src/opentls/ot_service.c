/* GFOpenTLS: the TLS key work on the services card, through
 * gfopenservice.device's opentls.key/1 (gfopenservice docs/OPENTLS_KEY.md).
 * On an Amiga with no card, or no device, nothing goes there and
 * GFOpenCrypto does it all; the host tests install a card of their own.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include "ot_internal.h"

static ot_svc_transport transport;
static ULONG where;
static ULONG calls;
static void *svc_lock;

#ifdef __amigaos__

#include <exec/io.h>
#include <proto/exec.h>
#include <devices/gfopenservice.h>

extern struct ExecBase *SysBase;

static struct MsgPort *open_port;
static struct OSRequest *opened;
static UWORD handle;
static int tried;

/* one DoIO from the calling task, on its own port: connections on
 * several tasks each wait for their own answer */
static LONG device_call(UWORD op, ULONG arg, const ULONG extra[4], struct ot_sbuf buf[4],
                        ULONG *result, ULONG *aux)
{
    struct MsgPort *port = CreateMsgPort();
    struct OSRequest *io = port ? (struct OSRequest *)CreateIORequest(port, sizeof *io) : NULL;
    LONG status = OSERR_LOST;
    int i;
    if (io) {
        io->os_Req.io_Device = opened->os_Req.io_Device;
        io->os_Req.io_Unit = opened->os_Req.io_Unit;
        io->os_Req.io_Command = OSCMD_CALL;
        io->os_Service = handle;
        io->os_Op = op;
        io->os_Arg = arg;
        io->os_Flags = 0;
        for (i = 0; i < 4; ++i) {
            io->os_Extra[i] = extra[i];
            if (buf[i].out) {
                io->os_Buf[i].ob_Data = buf[i].out;
                io->os_Flags |= 1UL << i;
            } else
                io->os_Buf[i].ob_Data = (APTR)buf[i].in;
            io->os_Buf[i].ob_Length = buf[i].in || buf[i].out ? buf[i].length : 0;
        }
        DoIO((struct IORequest *)io);
        status = io->os_Req.io_Error ? OSERR_LOST : io->os_Status;
        *result = io->os_Result;
        *aux = io->os_Aux;
        if (status == OSERR_OK && op == OTK_KEYGEN) {
            buf[0].written = io->os_Aux;
            buf[1].written = io->os_Result;
        } else if (status == OSERR_OK && op == OTK_DERIVE)
            buf[2].written = io->os_Result;
        DeleteIORequest((struct IORequest *)io);
    }
    if (port) DeleteMsgPort(port);
    return status;
}

static void device_close(void)
{
    if (!opened) return;
    if (handle) {
        opened->os_Req.io_Command = OSCMD_CLOSE;
        opened->os_Service = handle;
        DoIO((struct IORequest *)opened);
    }
    CloseDevice((struct IORequest *)opened);
    DeleteIORequest((struct IORequest *)opened);
    DeleteMsgPort(open_port);
    opened = NULL;
    open_port = NULL;
    handle = 0;
}

/* the device and the service, once: a machine with no card does not
 * ask again for every handshake */
static void device_open(void)
{
    static const char name[] = "opentls.key/1";
    tried = 1;
    open_port = CreateMsgPort();
    opened = open_port ? (struct OSRequest *)CreateIORequest(open_port, sizeof *opened) : NULL;
    if (!opened || OpenDevice((CONST_STRPTR)OPENSERVICE_NAME, 0, (struct IORequest *)opened, 0)) {
        if (opened) DeleteIORequest((struct IORequest *)opened);
        if (open_port) DeleteMsgPort(open_port);
        opened = NULL;
        open_port = NULL;
        return;
    }
    memset(opened->os_Buf, 0, sizeof opened->os_Buf);
    opened->os_Req.io_Command = OSCMD_OPEN;
    opened->os_Buf[0].ob_Data = (APTR)name;
    opened->os_Buf[0].ob_Length = sizeof name - 1;
    if (DoIO((struct IORequest *)opened) || opened->os_Status) {
        device_close();
        return;
    }
    handle = (UWORD)opened->os_Result;
    opened->os_Req.io_Command = OSCMD_WHERE;
    opened->os_Service = handle;
    DoIO((struct IORequest *)opened);
    where = opened->os_Result;
    transport = device_call;
}

static void ensure_open(void)
{
    if (tried) return;
    ot_lock(svc_lock);
    if (!tried) device_open();
    ot_unlock(svc_lock);
}

void ot_svc_cleanup(void)
{
    transport = NULL;
    device_close();
    tried = 0;
    where = 0;
    ot_lock_free(svc_lock);
    svc_lock = NULL;
}

#else

static void ensure_open(void) {}

void ot_svc_cleanup(void)
{
    transport = NULL;
    where = 0;
}

#endif

int ot_svc_init(void)
{
    if (!svc_lock) svc_lock = ot_lock_new();
    return svc_lock != NULL;
}

void ot_svc_install(ot_svc_transport fn, ULONG w)
{
    transport = fn;
    where = fn ? w : 0;
}

ULONG ot_svc_calls(void)
{
    return calls;
}

int ot_svc_ready(int keys)
{
    ensure_open();
    return transport && (!keys || where == OTSVC_WHERE_CARD);
}

static LONG call(UWORD op, ULONG arg, const ULONG extra[4], struct ot_sbuf buf[4], ULONG *result, ULONG *aux)
{
    LONG status;
    *result = *aux = 0;
    status = transport(op, arg, extra, buf, result, aux);
    if (!status) ++calls;                   /* a count for the tests: a lost update costs nothing */
    return status;
}

int ot_svc_verify(ULONG alg, ULONG digest, const unsigned char *spki, size_t spki_len,
                  const unsigned char *data, size_t data_len, const unsigned char *sig, size_t sig_len)
{
    struct ot_sbuf buf[4];
    ULONG extra[4] = { 0, 0, 0, 0 }, result, aux;
    if (!spki || !ot_svc_ready(0)) return -1;
    memset(buf, 0, sizeof buf);
    extra[0] = digest;
    buf[0].in = spki;
    buf[0].length = (ULONG)spki_len;
    buf[1].in = data;
    buf[1].length = (ULONG)data_len;
    buf[2].in = sig;
    buf[2].length = (ULONG)sig_len;
    if (call(OTK_VERIFY, alg, extra, buf, &result, &aux)) return -1;
    return result == 1;
}

size_t ot_svc_keygen(ULONG curve, unsigned char *priv, size_t priv_len, unsigned char *pub, size_t pub_room)
{
    struct ot_sbuf buf[4];
    ULONG extra[4] = { 0, 0, 0, 0 }, result, aux;
    if (!ot_svc_ready(1)) return 0;
    memset(buf, 0, sizeof buf);
    buf[0].out = priv;
    buf[0].length = (ULONG)priv_len;
    buf[1].out = pub;
    buf[1].length = (ULONG)pub_room;
    if (call(OTK_KEYGEN, curve, extra, buf, &result, &aux)) return 0;
    if (aux != priv_len || buf[0].written != aux || !result || result > pub_room || buf[1].written != result) {
        memset(priv, 0, priv_len);
        return 0;
    }
    return result;
}

size_t ot_svc_derive(ULONG curve, const unsigned char *priv, size_t priv_len,
                     const unsigned char *peer, size_t peer_len, unsigned char *out, size_t room)
{
    struct ot_sbuf buf[4];
    ULONG extra[4] = { 0, 0, 0, 0 }, result, aux;
    if (!ot_svc_ready(1)) return 0;
    memset(buf, 0, sizeof buf);
    buf[0].in = priv;
    buf[0].length = (ULONG)priv_len;
    buf[1].in = peer;
    buf[1].length = (ULONG)peer_len;
    buf[2].out = out;
    buf[2].length = (ULONG)room;
    if (call(OTK_DERIVE, curve, extra, buf, &result, &aux)) return 0;
    if (!result || result > room || buf[2].written != result) return 0;
    return result;
}
