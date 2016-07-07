#ifndef IFPIPE_H
#define IFPIPE_H

BOOL ifpipeInit();
VOID ifpipeDone();
VOID ifpipeRequest(ULONG cReq, PSZ *apszReq);

#endif // IFPIPE_H
