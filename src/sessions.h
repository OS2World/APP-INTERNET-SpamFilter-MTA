#ifndef SESSIONS_H
#define SESSIONS_H

#include "linkseq.h"
#include "requests.h"
#include "msgfile.h"

#define SESS_LOG_SPAM            0
#define SESS_LOG_NOT_SPAM        1
#define SESS_LOG_INFO            2
#define SESS_LOG_SCORE           3
#define SESS_LOG_WARNING         4
#define SESS_LOG_DELAYED         5
#define SESS_LOG_ERROR           6

typedef struct _SESS {
  SEQOBJ               seqObj;

  ULONG                ulFlags;  // bit 0 - session locked (not released).
  CHAR                 acId[SF_MAX_SESS_ID_LENGTH + 1];
  ULONG                ulCommandNo;
  ULONG                ulExpire;
  ULONG                ulTID;       // Open session thread. When fl. bit 0 set.
  ULONG                ulOpenTime;  // When flag bit 0 set.

  struct in_addr       stInAddr;
  PSZ                  pszHostName;
  PSZ                  pszEHLO;
  PSZ                  pszSender;
  ULONG                cRcpt;
  PSZ                  *ppszRcpt;

  BOOL                 fLocalClient;
  LONG                 lScoreClient;

  LONG                 lScore;
  BOOL                 fRelay;
  LONG                 lScoreRelay;
  BOOL                 fLocalSender;
  ULONG                ulRWLLevel;
  PSZ                  pszSpamTrap;
  ULONG                ulSPFLevel;
} SESS, *PSESS;

#define sessIsCommandTimeout(sess) ( testFlag1( &(sess)->ulFlags ) != 0 )

BOOL sessInit(ULONG ulCommandTimeout);
VOID sessDone();
VOID sessClean();
PSESS sessOpen(PSZ pszId, ULONG ulCommandNo);
BOOL sessDestroy(PSESS pSess);
BOOL sessClose(PSESS pSess);
VOID sessLog(PSESS pSess, ULONG ulLevel, ULONG ulType, PSZ pszFormat, ...);
VOID sessAddRecepient(PSESS pSess, ULONG cbAddr, PCHAR pcAddr);
VOID sessClearRecepient(PSESS pSess);
BOOL sessAddScore(PSESS pSess, LONG lScore, PSZ pszFormat, ...);
BOOL sessClientListed(PSESS pSess, PLINKSEQ plsHostList);
ULONG sessCount();
ULONG sessIPCount(struct in_addr stInAddr);
VOID sessSetCommandTimeout(ULONG ulCommandTimeout);

#endif // SESSIONS_H
