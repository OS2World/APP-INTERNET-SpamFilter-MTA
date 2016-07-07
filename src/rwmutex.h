#ifndef RWMUTEX_H
#define RWMUTEX_H

#include "xpl.h"

typedef struct _RWMTX {
  ULONG                ulReadLock;
  ULONG                ulWriteWait;
  HMTX                 hmtxRWLock;
  HEV                  hevWriteAllow;
} RWMTX, *PRWMTX;

BOOL rwmtxInit(PRWMTX pRWMtx);
VOID rwmtxDone(PRWMTX pRWMtx);
BOOL rwmtxLockRead(PRWMTX pRWMtx);
VOID rwmtxUnlockRead(PRWMTX pRWMtx);
BOOL rwmtxLockWrite(PRWMTX pRWMtx);
VOID rwmtxUnlockWrite(PRWMTX pRWMtx);

#endif // RWMUTEX_H
