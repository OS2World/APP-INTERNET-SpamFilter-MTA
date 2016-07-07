#ifndef SOCKETS_H
#define SOCKETS_H

BOOL socketInit();
VOID socketDone();
int socketNew();
VOID socketDestroy(int iSock);
VOID socketCancel(ULONG ulTID);

#endif // SOCKETS_H
