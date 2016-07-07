#ifndef GREYLIST_H
#define GREYLIST_H

#include "sessions.h"

BOOL glInit();
VOID glDone();
LONG glAdd(PSESS pSess);
VOID glClean();
VOID glGetCounters(PULONG pulIPSender, PULONG pulIPCf);
BOOL glSave();

#endif // GREYLIST_H
