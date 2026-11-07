/* The link stubs' library opener (stub_open.h).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/libraries.h>
#include <dos/dos.h>
#include <intuition/intuition.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/intuition.h>
#include <stdlib.h>
#include "stub_open.h"

extern struct DosLibrary *DOSBase;

static ULONG put(char *buf, ULONG at, const char *s)
{
	while (*s && at < 159) buf[at++] = *s++;
	buf[at] = 0;
	return at;
}

static ULONG put_num(char *buf, ULONG at, ULONG n)
{
	char d[12];
	int i = 0;
	do { d[i++] = (char)('0' + n % 10); n /= 10; } while (n && i < 11);
	while (i && at < 159) buf[at++] = d[--i];
	buf[at] = 0;
	return at;
}

static void say(const char *text)
{
	struct Process *me = (struct Process *)FindTask(NULL);
	BPTR out = DOSBase ? Output() : 0;
	ULONG n = 0;
	while (text[n]) ++n;
	if (out && me->pr_CLI) {
		Write(out, (APTR)text, n);
		Write(out, (APTR)"\n", 1);
	} else {
		struct Library *IntuitionBase = OpenLibrary((CONST_STRPTR)"intuition.library", 36);
		if (IntuitionBase) {
			struct EasyStruct es = { sizeof(struct EasyStruct), 0,
			                         (UBYTE *)"Library missing", (UBYTE *)"%s", (UBYTE *)"OK" };
			EasyRequest(NULL, &es, NULL, (ULONG)text);
			CloseLibrary(IntuitionBase);
		}
	}
}

struct Library *gfopen_stub_open(const char *name, ULONG version, UWORD revision)
{
	struct Library *base = OpenLibrary((CONST_STRPTR)name, version);
	char msg[160];
	ULONG at;
	if (base && (base->lib_Version > version || base->lib_Revision >= revision))
		return base;
	if (base)
		CloseLibrary(base);
	at = put(msg, 0, "This program needs ");
	at = put(msg, at, name);
	at = put(msg, at, " ");
	at = put_num(msg, at, version);
	at = put(msg, at, ".");
	at = put_num(msg, at, revision);
	put(msg, at, " or newer in LIBS: (install GFOpenTLS).");
	say(msg);
	exit(RETURN_FAIL);
	return NULL;
}
