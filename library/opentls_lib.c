/* gfopentls.library 1.4: a TLS client for AmigaOS 3.x, on BearSSL's
 * protocol code (third_party/bearssl, MIT) with GFOpenCrypto doing all the
 * maths through gfopencrypto.library 2.3 or newer (src/opentls/ot_glue.c).
 * docs/AutoDocs-GFOpenTLS.md is the contract.
 * MIT licensed and free. Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/resident.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>

#include "../src/opentls/ot_internal.h"
#include <clib/gfopentls_protos.h>

#define REG(r, decl) register decl __asm(#r)

struct OpenTLSLibBase {
    struct Library lib;
    BPTR seglist;
};

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

int start(void) { return -1; }

static const char lib_name[] = OPENTLSLIB_NAME;
static const char lib_id[] =
    "gfopentls.library 1.4 (6.11.2026) GFOpenTLS, AmiCradle Team\r\n";
/* For Version FILE and the Installer: without it, Version only finds the
 * library's version once it is in memory. */
static const char lib_ver[] __attribute__((used)) =
    "$VER: gfopentls.library 1.4 (6.11.2026) GFOpenTLS, AmiCradle Team";

static struct Library *lib_init(REG(d0, struct OpenTLSLibBase *base),
                                REG(a0, BPTR seglist),
                                REG(a6, struct ExecBase *sys));
static struct Library *lib_open(REG(a6, struct OpenTLSLibBase *base));
static BPTR lib_close(REG(a6, struct OpenTLSLibBase *base));
static BPTR lib_expunge(REG(a6, struct OpenTLSLibBase *base));
static ULONG lib_null(void);

#include "ot_entries.h"

static const APTR lib_vectors[] = {
    (APTR)lib_open, (APTR)lib_close, (APTR)lib_expunge, (APTR)lib_null,
#include "ot_vectors.h"
    (APTR)-1
};

static const struct {
    ULONG size;
    const APTR *vectors;
    APTR data;
    APTR init;
} lib_inittable = {
    sizeof(struct OpenTLSLibBase), lib_vectors, NULL, (APTR)lib_init
};

const struct Resident lib_romtag = {
    RTC_MATCHWORD, (struct Resident *)&lib_romtag, (APTR)(&lib_romtag + 1),
    RTF_AUTOINIT, OT_LIB_VERSION, NT_LIBRARY, 0,
    (char *)lib_name, (char *)lib_id, (APTR)&lib_inittable
};

static struct Library *lib_init(REG(d0, struct OpenTLSLibBase *base),
                                REG(a0, BPTR seglist),
                                REG(a6, struct ExecBase *sys))
{
    SysBase = sys;
    base->seglist = seglist;
    base->lib.lib_Revision = OT_LIB_REVISION;
    DOSBase = (struct DosLibrary *)OpenLibrary((CONST_STRPTR)"dos.library", 37);
    if (!DOSBase || !ot_random_init() || !ot_trust_init() || !ot_session_init()) {
        if (DOSBase) CloseLibrary((struct Library *)DOSBase);
        FreeMem((UBYTE *)base - base->lib.lib_NegSize,
                base->lib.lib_NegSize + base->lib.lib_PosSize);
        return NULL;
    }
    return &base->lib;
}

static struct Library *lib_open(REG(a6, struct OpenTLSLibBase *base))
{
    base->lib.lib_OpenCnt++;
    base->lib.lib_Flags &= ~LIBF_DELEXP;
    return &base->lib;
}

static BPTR lib_close(REG(a6, struct OpenTLSLibBase *base))
{
    base->lib.lib_OpenCnt--;
    if (base->lib.lib_OpenCnt == 0 && (base->lib.lib_Flags & LIBF_DELEXP))
        return lib_expunge(base);
    return 0;
}

static BPTR lib_expunge(REG(a6, struct OpenTLSLibBase *base))
{
    BPTR seglist;
    if (base->lib.lib_OpenCnt) {
        base->lib.lib_Flags |= LIBF_DELEXP;
        return 0;
    }
    seglist = base->seglist;
    Remove(&base->lib.lib_Node);
    ot_glue_cleanup();
    ot_system_anchors_free();
    ot_session_cleanup();
    ot_random_cleanup();
    CloseLibrary((struct Library *)DOSBase);
    FreeMem((UBYTE *)base - base->lib.lib_NegSize,
            base->lib.lib_NegSize + base->lib.lib_PosSize);
    return seglist;
}

static ULONG lib_null(void) { return 0; }
