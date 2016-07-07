#ifndef ADDRLIST_H
#define ADDRLIST_H

#include <time.h>

typedef struct _ADDRITEM {
  time_t     timeExpire;
  CHAR       szAddr[1];
} ADDRITEM, *PADDRITEM;

typedef struct _ADDRLIST {
  ULONG      ulMaxItems;
  ULONG      cItems;
  PADDRITEM  *ppItems;
  HMTX       hmtxList;
  BOOL       fChanged;
} ADDRLIST, *PADDRLIST;

BOOL addrlstInit(PADDRLIST pAddrList, ULONG ulInitRecords);
VOID addrlstDone(PADDRLIST pAddrList);
BOOL addrlstAdd(PADDRLIST pAddrList, PSZ pszAddr, ULONG ulTTL);
BOOL addrlstCheck(PADDRLIST pAddrList, PSZ pszAddr);
VOID addrlstClean(PADDRLIST pAddrList);
BOOL addrlstSave(PADDRLIST pAddrList, PSZ pszFile);
BOOL addrlstLoad(PADDRLIST pAddrList, PSZ pszFile);
ULONG addrlstGetCount(PADDRLIST pAddrList);

#endif // ADDRLIST_H
