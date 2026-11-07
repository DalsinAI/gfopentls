/* libgfopentls.a: opens gfopentls.library 1.5 or newer into OpenTLSBase
 * (the base <proto/gfopentls.h> names) before main() and closes it when the
 * program ends; the calls themselves are the inline macros of
 * <proto/gfopentls.h>. A program that can't open it says so and ends with
 * RETURN_FAIL before main(). gfopentls.library opens gfopencrypto.library
 * itself. MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <proto/exec.h>
#include <stabs.h>
#include <libraries/gfopentls.h>
#include "stub_open.h"

struct Library *OpenTLSBase;

static void __attribute__((used)) ot_stub_open(void)
{
	if (!OpenTLSBase)
		OpenTLSBase = gfopen_stub_open(OPENTLSLIB_NAME, OPENTLSLIB_VERSION, 5);
}
ADD2INIT(ot_stub_open, -50);

static void __attribute__((used)) ot_stub_close(void)
{
	if (OpenTLSBase) {
		CloseLibrary(OpenTLSBase);
		OpenTLSBase = 0;
	}
}
ADD2EXIT(ot_stub_close, -50);
