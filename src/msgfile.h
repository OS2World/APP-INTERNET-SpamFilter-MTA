#ifndef MSGFILE_H
#define MSGFILE_H

#include <stdio.h>
#include "addrlist.h"
#include "linkseq.h"

typedef struct _MSGFILE {
  LINKSEQ    lsFields;
  FILE       *fd;
  ULONG      ulBodyStart;
} MSGFILE, *PMSGFILE;

PMSGFILE mfOpen(PSZ pszFile);
VOID mfClose(PMSGFILE pFile);
VOID mfSetHeader(PMSGFILE pFile, PSZ pszField, PSZ pszValue);
VOID mfScanBody(PMSGFILE pFile, PADDRLIST pList);
BOOL mfStore(PMSGFILE pFile, PSZ pszFile);
BOOL mfGetOutsideHost(PMSGFILE pFile, struct in_addr *pInAddr,
                      ULONG cbHostName, PCHAR pcHostName);
BOOL mfGetMessageId(PMSGFILE pFile, PULONG pcbMsgId, PSZ *ppszMsgId);
BOOL mfGetFirstReceivedByHost(PMSGFILE pFile, PULONG pcbHost, PCHAR *ppcHost);

#endif // MSGFILE_H
