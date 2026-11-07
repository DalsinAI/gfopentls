/* What the link stubs do when a library they need is missing or too old:
 * say so (in the Shell, or in a requester when started from Workbench) and
 * end the program with RETURN_FAIL before main() runs.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef GFOPENTLS_STUB_OPEN_H
#define GFOPENTLS_STUB_OPEN_H
#include <exec/types.h>
#include <exec/libraries.h>

/* name, version and revision; the opened base, or the program ends */
struct Library *gfopen_stub_open(const char *name, ULONG version, UWORD revision);

#endif
