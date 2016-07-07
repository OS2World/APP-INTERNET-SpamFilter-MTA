#ifndef IFSOCK_H
#define IFSOCK_H

BOOL ifsockInit();
VOID ifsockDone();
VOID ifsockRequest(ULONG cReq, PSZ *apszReq);

#endif // IFSOCK_H
