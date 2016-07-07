#ifndef REQUESTS_H
#define REQUESTS_H

#include "xpl.h"
#include "sf.h"
#include "addrlist.h"

#define REQ_ANSWER_OK            0
#define REQ_ANSWER_ERROR         1
#define REQ_ANSWER_SPAM          2
#define REQ_ANSWER_DELAYED       3

#ifndef REQUESTS_C
extern PSZ             apszReqAnswerResuts[];
extern ADDRLIST        stWhiteAddrList;
#endif

typedef VOID (*PFNREQCB)(PVOID pUser, ULONG cbAnswer, PCHAR pcAnswer);

BOOL reqInit();
VOID reqDone();
BOOL reqNew(ULONG cbText, PCHAR pcText, PFNREQCB pfnCallback, PVOID pUser);
VOID reqClean();
VOID reqStoreLists();
ULONG reqGetCount();
ULONG reqDynIPGetCount();
VOID reqCloseSession(PSZ pszSessId);
VOID reqReconfigured();

#endif // REQUESTS_H
