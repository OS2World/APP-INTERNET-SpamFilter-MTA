#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <arpa\inet.h>
#include <time.h>
#include "util.h"
#include "linkseq.h"
#include "dns.h"
#include "log.h"
#include "spf.h"
#include "greylist.h"
#include "sigqueue.h"
#include "mboxchk.h"
#include "stat.h"
#include "msgfile.h"
#include "idfreq.h"
#include "debug.h"
#define REQUESTS_C
#include "requests.h"

#define _WHITELIST_FILE          "whitelst.txt"
#define _SPAM_URL_HOSTLIST_FILE  "spamlink.txt"
#define THREAD_STACK_SIZE        65535
#define COMMAND_LIST             "@ACCEPT EHLO RSET MAIL RCPT DATA " \
                                 "@CONTENT QUIT"

#define FL_LOCAL_CLIENT          1
#define FL_LOCAL_SENDER          2
#define FL_RELAY                 4

typedef struct _SESSCMD *PSESSCMD;

typedef BOOL (*PFNCMD)(PSESS pSess, PSESSCMD pSessCmd);

// Session command record.

typedef struct _SESSCMD {
  SEQOBJ               seqObj;

  PFNREQCB             pfnCallback;        // User function to get result.
  PVOID                pUser;              // User data for pfnCallback.
  ULONG                ulCommandNo;
  CHAR                 acSessId[SF_MAX_SESS_ID_LENGTH + 1];
  ULONG                cbArg;
  CHAR                 acArg[1];
} SESSCMD;


typedef struct _DYNIPREC {
  ULONG                ulAddr;
  LONG                 lScore;
  time_t               timeExpire;
  ULONG                ulTTL;
} DYNIPREC, *PDYNIPREC;

ADDRLIST        stWhiteAddrList = { 0 };
ADDRLIST        stSpamURIHostList = { 0 };

static LINKSEQ         lsSessCmd;
static HMTX            hmtxSessCmd = NULLHANDLE;
static HEV             hevSessCmd = NULLHANDLE;
static ULONG           cThreads = 0;
static IDFREQ          idfreqClients = { 0 };

// Internal dynamic ip-addresses list of SMTP-clients.
static PDYNIPREC       pDynIPList = NULL;
static ULONG           cDynIPList = 0;
static ULONG           ulMaxDynIPList = 0;
static HMTX            hmtxDynIPList = NULLHANDLE;

// Text messages for answers. The strings must be less than 31 characters.
PSZ             apszReqAnswerResuts[] =
{
  "OK",                // REQ_ANSWER_OK
  "ERROR",             // REQ_ANSWER_ERROR
  "SPAM",              // REQ_ANSWER_SPAM
  "DELAYED"            // REQ_ANSWER_DELAYED
};


//           Utilites
//           --------

/*#define _sessCmdAnswer(sc, ans, fmt, ...) \
  _reqAnswer( sc->pfnCallback, sc->pUser, ans, fmt, ##__VA_ARGS__)*/

static VOID _reqAnswer(PFNREQCB pfnCallback, PVOID pUser, ULONG ulAnswer,
                       PSZ pszFormat, ...)
{
  CHAR       acBuf[1024];
  PCHAR      pcBuf = &acBuf;
  LONG       cBytes;
  va_list    arglist;

  if ( pfnCallback == NULL )
    return;

  pcBuf += sprintf( pcBuf, "%s: ", apszReqAnswerResuts[ulAnswer] );

  if ( pszFormat != NULL )
  {
    va_start( arglist, pszFormat );
    cBytes = vsnprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 4,
                        pszFormat, arglist );
    va_end( arglist );

    if ( cBytes == -1 )
      pcBuf = &acBuf[sizeof(acBuf) - 3];
    else
      pcBuf += cBytes;
  }

  if ( *(pcBuf-1) != ' ' && *(pcBuf-1) != '.' )
  {
    *pcBuf = '.';
    pcBuf++;
  }

  *((PUSHORT)pcBuf) = (USHORT)'\n\r';
  pfnCallback( pUser, (pcBuf - &acBuf) + 2, &acBuf );
}

static VOID _sessCmdAnswer(PSESS pSess, PSESSCMD pSessCmd, ULONG ulAnswer,
                           PSZ pszFormat, ...)
{
  va_list    arglist;
  CHAR       acBuf[512];
  PCHAR      pcBuf = &acBuf, pcEnd = &acBuf[sizeof(acBuf)];

  if ( sessIsCommandTimeout( pSess ) )
  {
    ulAnswer = REQ_ANSWER_ERROR;
    _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, ulAnswer,
                "Command execution timeout.", NULL );
  }
  else
  {
    if ( pszFormat != NULL )
    {
      va_start( arglist, pszFormat );
      vsnprintf( &acBuf, sizeof(acBuf), pszFormat, arglist );
      va_end( arglist );
    }
    else
      acBuf[0] = '\0';

    _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, ulAnswer, "%s",
                &acBuf );
  }

  // Change statictics.

  switch( ulAnswer )
  {
    case REQ_ANSWER_SPAM:
      statChange( STAT_SPAM, 1 );
      break;

    case REQ_ANSWER_DELAYED:
      statChange( STAT_DELAYED, 1 );
      break;

    case REQ_ANSWER_OK:
      if ( pSess->ulCommandNo == 6 ) // @CONTENT, here "OK" means "not a spam".
      {
        statChange( STAT_NOT_SPAM, 1 );
        break;
      }

    default:
      return;
  }

  // Make "final" log record for the session.

  pcBuf += sprintf( &acBuf,
                    "[INFO] Answer: %s, id: %s, client: [%s]",
                    apszReqAnswerResuts[ulAnswer], &pSess->acId,
                    inet_ntoa( pSess->stInAddr ) );
  if ( pSess->pszHostName != NULL )
    pcBuf += sprintf( pcBuf, " %s", pSess->pszHostName );
  if ( pSess->pszSender != NULL )
    pcBuf += sprintf( pcBuf, ", from: %s", pSess->pszSender );
  if ( pSess->cRcpt != 0 )
  {
    ULONG        ulIdx;
    PSZ          pszRcpt;

    pcBuf += sprintf( pcBuf, ", to:" );

    for( ulIdx = 0; ulIdx < min( pSess->cRcpt, 30 ); ulIdx++ )
    {
      pszRcpt = pSess->ppszRcpt[ulIdx];

      if ( (pcEnd - pcBuf) > ( strlen( pszRcpt ) + 24 ) )
        pcBuf += sprintf( pcBuf, " %s", pszRcpt );
      else
      {
        sprintf( pcBuf, " (%u more)", pSess->cRcpt - ulIdx );
        break;
      }
    }
  }
  log( 1, &acBuf );
}


// static BOOL _reqParsePathAddr(ULONG cbStr, PCHAR pcStr,
//                               PULONG pcbAddr, PCHAR *ppcAddr)
//
// "<@hosta.int,@jkl.org:userc@d.bar.org> parameters" --> "userc@d.bar.org"

static BOOL _reqParsePathAddr(ULONG cbStr, PCHAR pcStr,
                              PULONG pcbAddr, PCHAR *ppcAddr)
{
  PCHAR      pcEnd = &pcStr[cbStr];
  PCHAR      pcScan = pcStr;

  // Search end of address: '>' or SPACE.
  while( ( pcScan < pcEnd ) && !isspace( *pcScan ) && ( *pcScan != '>' ) )
    pcScan++;
  if ( pcScan == pcStr )
    return FALSE;
  pcEnd = pcScan;

  // Search begin of address: ':' or '<'.
  do
  {
    if ( ( *(pcScan-1) == ':' ) || ( *(pcScan-1) == '<' ) )
      break;
    pcScan--;
  }
  while( pcScan > pcStr );

  // Address found.
  pcStr = pcScan;
  cbStr = pcEnd - pcScan;
  if ( cbStr < 3 )
    return FALSE;

  // Search domain part.
  while( ( pcScan < pcEnd ) && ( *pcScan != '@' ) )
    pcScan++;
  if ( ( pcScan == pcStr ) || ( pcScan == pcEnd ) )
    return FALSE;
  pcScan++;

  // Verify domain part.
  if ( ( *pcScan == '[' ) && ( *(pcEnd-1) == ']' ) )
  {
    if ( !utilStrToInAddr( (pcEnd - pcScan) - 2, &pcScan[1], NULL ) )
      return FALSE;
  }
  else if ( !utilVerifyDomainName( pcEnd - pcScan, pcScan ) )
    return FALSE;

  *pcbAddr = cbStr;
  *ppcAddr = pcStr;
  return TRUE;
}

// ULONG _reqCheckRWL(struct in_addr stInAddr)
//
// Returns: 0 - unknown,
// 1 - 100% trusted server,
// 2 - ISP level public mail servers who watch their customers closely,
// 3 - IPs after extensive background checks and are currently spam-free,
// 4 - address not listed in WhiteLists.

static ULONG _reqCheckRWL(struct in_addr stInAddr)
{
  ULONG                cbRWLProviders, cbRWL;
  PCHAR                pcRWLProviders, pcRWL;
  LONG                 cbName;
  CHAR                 acName[128];
  ULONG                cBLRes;
  struct in_addr       aBLRes[64];
  struct in_addr       *pBLRes;
  ULONG                ulRC;
  ULONG                ulLevel = 0;
  ULONG                ulIdx;
  CHAR                 acLogMsg[256];
  PCHAR                pcLogMsg;

  if ( pConfig->pcRWLProviders == NULL )
    return 0;

  cbRWLProviders = pConfig->cbRWLProviders;
  pcRWLProviders = pConfig->pcRWLProviders;
  strcpy( &acLogMsg, "[INFO] RWL " );
  while( utilStrCutWord( &cbRWLProviders, &pcRWLProviders, &cbRWL, &pcRWL ) )
  {
    // Make request to RWL system.
    cbName = sprintf( &acName, "%u.%u.%u.%u.",
                      ((PCHAR)&stInAddr)[3], ((PCHAR)&stInAddr)[2],
                      ((PCHAR)&stInAddr)[1], ((PCHAR)&stInAddr)[0] );
    memcpy( &acName[cbName], pcRWL, cbRWL );
    cbName += cbRWL;
    acName[cbName] = '\0';

    // Send request.
    ulRC = dnsRequest( DNSREC_TYPE_A, &acName, sizeof(aBLRes), (PCHAR)&aBLRes,
                       &cBLRes );
    if ( ulRC == DNS_CANCEL )
      return 0;

    if ( ( ulRC != DNS_NOERROR ) && ( ulRC != DNS_NXDOMAIN ) )
    {
      debug( "dnsRequest(), rc = %u", ulRC );
      break;
    }

    if ( cBLRes == 0 )
      // IP not listed in this RWL.
      continue;

    pcLogMsg = &acLogMsg[11]; // 11 - skip "[INFO] RWL "
    memcpy( pcLogMsg, pcRWL, cbRWL );
    pcLogMsg += cbRWL;
    sprintf( pcLogMsg, " for %s,", inet_ntoa( stInAddr ) );

    for( pBLRes = &aBLRes, ulIdx = 0; ulIdx < cBLRes; pBLRes++, ulIdx++ )
    {
      if ( ( ((PCHAR)pBLRes)[0] != 127 ) || ( ((PCHAR)pBLRes)[3] > 3 ) )
      {
        log( 2, "%s unknown result: %s", &acLogMsg, inet_ntoa( *pBLRes ) );
        continue;
      }

      if ( ((PCHAR)pBLRes)[3] == 0 )
        ((PCHAR)pBLRes)[3] = 1;

      if ( ( ulLevel == 0 ) || ( ((PCHAR)pBLRes)[3] < ulLevel ) )
      {
        ulLevel = ((PCHAR)pBLRes)[3];
        log( 4, "%s result: %s, new trust level %u",
             &acLogMsg, inet_ntoa( *pBLRes ), ulLevel );
      }
      else
        log( 4, "%s result: %s, trust level %u not changed",
             &acLogMsg, inet_ntoa( *pBLRes ) );
    }
  }

  return ulLevel;
}

// static LONG _reqScoreURIBL(ULONG cbAddr, PCHAR pcAddr)
//
// Search the host name in URIBL and return result score (SF_SCORE_NONE,
// pConfig->lScoreURIBLNeutral or pConfig->lScoreURIBLPositive).

static LONG _reqScoreURIBL(ULONG cbAddr, PCHAR pcAddr)
{
  CHAR                 acBuf[128];
  ULONG                cbURIBL, cbURIBLProviders = pConfig->cbURIBLProviders;
  PCHAR                pcURIBL, pcURIBLProviders = pConfig->pcURIBLProviders;
  struct in_addr       aBLRes[64];
  ULONG                cBLRes;
  ULONG                ulRC;
  ULONG                cHits = 0;

  if ( cfgIsMatchPtrnList( pConfig->cbLocalDomains, pConfig->pcLocalDomains,
                           cbAddr, pcAddr ) ||
       cfgIsMatchPtrnList( pConfig->cbURIBLNotSpam, pConfig->pcURIBLNotSpam,
                           cbAddr, pcAddr ) )
    return SF_SCORE_NONE;

  // Begin of the request (host name).
  memcpy( &acBuf, pcAddr, cbAddr );

  while( utilStrCutWord( &cbURIBLProviders, &pcURIBLProviders, &cbURIBL,
                         &pcURIBL ) )
  {
    if ( ( cbURIBL + cbAddr ) > ( sizeof(acBuf) - 2 /* '.' and '\0' */ ) )
      continue;

    // Add provider domain name to the request.
    acBuf[cbAddr] = '.';
    memcpy( &acBuf[cbAddr + 1], pcURIBL, cbURIBL );
    acBuf[cbAddr + 1 + cbURIBL] = '\0';

    ulRC = dnsRequest( DNSREC_TYPE_A, &acBuf, sizeof(aBLRes),
                       (PCHAR)&aBLRes, &cBLRes );

    if ( ulRC == DNS_CANCEL )
      break;

    if ( ( ulRC != DNS_NOERROR ) || ( cBLRes == 0 ) )
      continue;

    cHits++;
    acBuf[cbAddr] = '\0';
    acBuf[cbURIBL + cbAddr + 1] = '\0';
    log( 5, "[INFO] Name %s listed in DBL %s, hits: %u",
         &acBuf, &acBuf[cbAddr + 1], cHits );

    if ( cHits >= pConfig->ulURIBLHits )
      return pConfig->lScoreURIBLPositive;
  }

  return cHits != 0 ? pConfig->lScoreURIBLNeutral : SF_SCORE_NONE;
}



//           Internal dynamic ip-addresses list
//           ----------------------------------

static int __dynipCompAddr(const void *pkey, const void *pbase)
{
  ULONG      ulAddr = (ULONG)pkey;
  PDYNIPREC  pDynIPRec = (PDYNIPREC)pbase;

  if ( ulAddr < pDynIPRec->ulAddr )
    return -1;

  return ulAddr > pDynIPRec->ulAddr ? 1 : 0;
}

static BOOL _dynipInit()
{
  xplMutexCreate( &hmtxDynIPList, FALSE );

  return hmtxDynIPList != NULLHANDLE;
}

static VOID _dynipDone()
{
  if ( pDynIPList != NULL )
  {
    debugFree( pDynIPList );
    pDynIPList = NULL;
  }

  if ( hmtxDynIPList != NULLHANDLE )
  {
    xplMutexDestroy( hmtxDynIPList );
    hmtxDynIPList = NULLHANDLE;
  }

  cDynIPList = 0;
  ulMaxDynIPList = 0;
}

// VOID _dynipSet(struct in_addr stInAddr, LONG lScore, ULONG ulLifeTime)
//
// lScore == SF_SCORE_NONE - removes an address stInAddr from the list,
// other - Address not listed: inserts address at the list with score lScore
//         for ulLifeTime sec. Address was listed: increment score on lScore
//         and set new ulLifeTime.

static VOID _dynipSet(struct in_addr stInAddr, LONG lScore, ULONG ulLifeTime)
{
  ULONG      ulAddr = ntohl( stInAddr.s_addr );
  PDYNIPREC  pDynIPRec;
  ULONG      ulIndex;
  time_t     timeExpire = lScore == SF_SCORE_NONE ?
                            0 : time( NULL ) + ulLifeTime;

  xplMutexLock( hmtxDynIPList, XPL_INDEFINITE_WAIT );

  if ( !utilBSearch( (const void *)ulAddr, pDynIPList, cDynIPList,
                     sizeof(DYNIPREC), __dynipCompAddr, &ulIndex ) )
  {
    // Address was not listed - insert a new record.

    if ( lScore == SF_SCORE_NONE )
      // A caller wants to remove non-existent record.
      return;

    if ( cDynIPList == ulMaxDynIPList )
    {
      PDYNIPREC        pNewList = debugReAlloc( pDynIPList,
                                     sizeof(DYNIPREC) * (cDynIPList + 16) );
      if ( pNewList == NULL )
      {
        debug( "Not enough memory" );
        return;
      }
      pDynIPList = pNewList;
      ulMaxDynIPList += 16;
    }

    // Insert the new record at position ulIndex to keep order.
    memmove( &pDynIPList[ulIndex + 1], &pDynIPList[ulIndex],
             (cDynIPList - ulIndex) * sizeof(PADDRITEM) );
    cDynIPList++;

    // Fill a new record.
    pDynIPList[ulIndex].ulAddr = ulAddr;
    pDynIPList[ulIndex].lScore = lScore;
    pDynIPList[ulIndex].timeExpire = timeExpire;
    pDynIPList[ulIndex].ulTTL = ulLifeTime;
  }
  else if ( lScore == SF_SCORE_NONE )
  {
    // A caller wants to remove existing record.
    cDynIPList--;
    memcpy( &pDynIPList[ulIndex], &pDynIPList[ulIndex + 1],
            sizeof(DYNIPREC) * (cDynIPList - ulIndex) );
  }
  else
  {
    // Update existing record.
    pDynIPRec = &pDynIPList[ulIndex];

    if ( lScore == SF_SCORE_SPAM || lScore == SF_SCORE_NOT_SPAM ||
         pDynIPRec->lScore == SF_SCORE_SPAM ||
         pDynIPRec->lScore == SF_SCORE_NOT_SPAM )
      // Sets the absolute value spam/not spam or changes from absolute to
      // the relative value.
      pDynIPRec->lScore = lScore;
    else
    {
      // Increases the relative value.
      pDynIPRec->lScore += lScore;

      if ( pDynIPRec->lScore > pConfig->lStageScoringLimit[0] )
        // Maximum value - scoring limit for stage 0. Dynamic ip list
        // will be checked only on stage 0.
        pDynIPRec->lScore = pConfig->lStageScoringLimit[0];
      else if ( pDynIPRec->lScore < -pConfig->lStageScoringLimit[0] )
        // Minimum value... I haven't a good idea about minimum, let's use
        // -1 * ( scoring limit for stage 0 ).
        pDynIPRec->lScore = -pConfig->lStageScoringLimit[0];
    }

    pDynIPRec->timeExpire = timeExpire;
    pDynIPRec->ulTTL = ulLifeTime;
  }

  xplMutexUnlock( hmtxDynIPList );
}

// LONG _dynipCheck(struct in_addr stInAddr)
//
// Returns score for the given address or SF_SCORE_NONE if address not listed.
// The lifetime of listed address prolongs.

static LONG _dynipCheck(struct in_addr stInAddr)
{
  ULONG      ulAddr = ntohl( stInAddr.s_addr );
  LONG       lScore;
  ULONG      ulIndex;

  xplMutexLock( hmtxDynIPList, XPL_INDEFINITE_WAIT );

  if ( utilBSearch( (const void *)ulAddr, pDynIPList, cDynIPList,
                    sizeof(DYNIPREC), __dynipCompAddr, &ulIndex ) )
  {
    // The existing address is requested - prolong its lifetime.
//    pDynIPRec->timeExpire = time( NULL ) + pDynIPRec->ulTTL;
    lScore = pDynIPList[ulIndex].lScore;
  }
  else
    lScore = SF_SCORE_NONE;

  xplMutexUnlock( hmtxDynIPList );
  return lScore;
}

// VOID _dynipClean()
//
// Removes expired addresses from the list.

static VOID _dynipClean()
{
  LONG       lIdx;
  time_t     timeNow;

  time( &timeNow );
  xplMutexLock( hmtxDynIPList, XPL_INDEFINITE_WAIT );

  for( lIdx = cDynIPList - 1; lIdx >= 0; lIdx-- )
  {
    if ( pDynIPList[lIdx].timeExpire > timeNow )
      continue;

    cDynIPList--;
    memcpy( &pDynIPList[lIdx], &pDynIPList[lIdx+1],
            (cDynIPList - lIdx) * sizeof(DYNIPREC) );
  }

  xplMutexUnlock( hmtxDynIPList );
}


//           Session command routines.
//           -------------------------

// Check functions for commands routines
// (called from command routines _scXXXXX()).
// ------------------------------------------

static BOOL _sCheckEHLO(PSESS pSess,
                        struct in_addr stInAddrEHLO) // EHLO in IP-format or -1
{
  struct in_addr   aARes[64];
  ULONG            cARes, cMXRes, ulIdx, ulRC;
  CHAR             aMXRes[512];
  PCHAR            pcDomain;
  PSZ              pszMXName;

  // Compare EHLO with client's host.
  debug( "EHLO host name: %s, client host: %s",
         pSess->pszEHLO, STR_SAFE( pSess->pszHostName ) );
  if ( // Compare EHLO string with client's host name.
       ( STR_ICMP( pSess->pszEHLO, pSess->pszHostName ) == 0 ) ||
       // IP-address in EHLO - compare with client's IP-address.
       ( stInAddrEHLO.s_addr == pSess->stInAddr.s_addr ) )
    return TRUE;

  if ( stInAddrEHLO.s_addr != (u_long)(-1) ) // IP-address in EHLO.
    return FALSE;

  // EHLO Host name and client's (session) host name is not same.
  // Let's try to get IP for EHLO host name and compare it with
  // client's IP-address.

  debug( "Resolv EHLO %s...", pSess->pszEHLO );
  ulRC = dnsRequest( DNSREC_TYPE_A, pSess->pszEHLO, sizeof(aARes),
                     (PCHAR)&aARes, &cARes );
  if ( ulRC == DNS_CANCEL )
    return FALSE;

  if ( ulRC != DNS_NOERROR )
    debug( "dnsRequest(), rc = %u", ulRC );
  else
  {
    debug( "DNS answers: %u", cARes );
    for( ulIdx = 0; ulIdx < cARes; ulIdx++ )
      if ( aARes[ulIdx].s_addr == pSess->stInAddr.s_addr )
        return TRUE;
  }

  if ( sessIsCommandTimeout( pSess ) )
    return TRUE;

  // No mathes found - try to compare EHLO string with MX servers for client's
  // domain.

  if ( pSess->pszHostName == NULL )
    return FALSE;
  pcDomain = strchr( pSess->pszHostName, '.' );
  if ( pcDomain == NULL )
    return FALSE;
  pcDomain++;
  if ( strchr( &pcDomain[1], '.' ) == NULL ) // It should be at least two parts.
    return FALSE;

  ulRC = dnsRequest( DNSREC_TYPE_MX, pcDomain, sizeof(aMXRes),
                     &aMXRes, &cMXRes );
  if ( ulRC == DNS_CANCEL )
  {
    sessLog( pSess, 5, SESS_LOG_INFO, "No MX-server found for %s.",
             pcDomain );
    return FALSE;
  }

  // MX Record: 2 bytes - MX-server level, ASCIIZ - host name.
  for( pszMXName = &aMXRes[sizeof(USHORT)]; cMXRes > 0; cMXRes-- )
  {
    if ( stricmp( pszMXName, pSess->pszEHLO ) == 0 )
    {
      sessLog( pSess, 5, SESS_LOG_INFO, "EHLO is MX-server for %s.",
               pcDomain );
      return TRUE;
    }

    // Jump to the next name.
    pszMXName = strchr( pszMXName, '\0' ) + 1 + sizeof(USHORT);
  }

  return FALSE;
}

// ULONG _sCheckDNSBL(PSESS pSess)
//
// Returns TRUE on final SPAM/NOT-SPAM score.

static BOOL _sCheckDNSBL(PSESS pSess)
{
  ULONG                ulRC;
  PDNSBL               pDNSBL;
  ULONG                cBLRes;
  struct in_addr       aBLRes[64];
  ULONG                ulDNSBL, ulIdx;
  ULONG                ulHits = 0;
  BOOL                 fHit;
  CHAR                 acLogMsg[256];
  CHAR                 acName[128];
  LONG                 lScore;

  if ( pConfig->paDNSBL == NULL )
    return FALSE;

  if ( sessClientListed( pSess, &pConfig->lsHostListDNSBLIgnore ) )
  {
    sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
             "configured DNSBL ignore list.",
             inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
    return FALSE;
  }

  for( ulDNSBL = 0, pDNSBL = pConfig->paDNSBL;
       ulDNSBL < pConfig->cDNSBL && pDNSBL->pszName != NULL;
       ulDNSBL++, pDNSBL++ )
  {
    // Make request to DNSBL system.
    sprintf( &acName, "%u.%u.%u.%u.%s",
             ((PCHAR)&pSess->stInAddr)[3], ((PCHAR)&pSess->stInAddr)[2],
             ((PCHAR)&pSess->stInAddr)[1], ((PCHAR)&pSess->stInAddr)[0],
             pDNSBL->pszName );
    // Send request.
    ulRC = dnsRequest( DNSREC_TYPE_A, &acName, sizeof(aBLRes), (PCHAR)&aBLRes,
                       &cBLRes );
    if ( ulRC == DNS_CANCEL )
      return TRUE;

    if ( ( ulRC != DNS_NOERROR ) && ( ulRC != DNS_NXDOMAIN ) )
    {
      debug( "dnsRequest(), rc = %u", ulRC );
      break;
    }

    if ( cBLRes == 0 )
      // IP not listed in this DNSBL.
      continue;

    // Scoring answers.

    _bprintf( &acLogMsg, sizeof(acLogMsg), "DNSBL %s for %s",
              pDNSBL->pszName, inet_ntoa( pSess->stInAddr ) );

    for( fHit = FALSE, ulIdx = 0; ulIdx < cBLRes; ulIdx++ )
    {
      if ( cfgHostListCheckIP( &pDNSBL->lsHostListAnswers, aBLRes[ulIdx],
                               &lScore ) )
      {
        if ( sessAddScore( pSess, lScore, "%s, result: %s.", &acLogMsg,
                           inet_ntoa( aBLRes[ulIdx] ) ) )
          return TRUE;

        fHit = TRUE;
      }
    }

    // Limit DNSBL providers hits.
    if ( fHit )
    {
      ulHits++;
      if ( ulHits >= pConfig->ulDNSBLMaxHits )
        break;
    }
  }

  if ( ulHits == 0 )
    sessLog( pSess, 3, SESS_LOG_INFO, "Client's address %s was not found "
             "in DNSBL.", inet_ntoa( pSess->stInAddr ) );

  return FALSE;
}

static BOOL _sCheckMessageId(PSESS pSess, PMSGFILE pFile)
{
  ULONG    cbMsgId, cbIdName;
  PCHAR    pcMsgId, pcIdName;
  LONG     lScore;
  PCHAR    pcEnd, pcDot;
  ULONG    ulDots;
  PSZ      pszMegId;

  if ( sessClientListed( pSess, &pConfig->lsHostListMsgIdIgnore ) )
  {
    sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
             "configured message-id ignore list.",
             inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
    return FALSE;
  }

  if ( !mfGetMessageId( pFile, &cbMsgId, &pcMsgId ) )
    return sessAddScore( pSess, pConfig->lScoreSuspiciousMsgId,
                         "Field Message-ID not found." );

  BUF_SKIP_SPACES( cbMsgId, pcMsgId );
  BUF_RTRIM( cbMsgId, pcMsgId );
  pszMegId = logBufToPSZ( cbMsgId, pcMsgId );

  if ( cfgHostListCheckName( &pConfig->lsHostListMsgId, cbMsgId, pcMsgId,
                             &lScore ) &&
       sessAddScore( pSess, lScore,
                     "Message-ID \"%s\" matches the configured pattern.",
                     pszMegId ) )
    return TRUE;

  pcEnd = &pcMsgId[cbMsgId];
  if ( ( pcEnd > pcMsgId ) && ( *(pcEnd-1) == '>' ) )
    pcEnd--;

  ulDots = 0;
  pcIdName = pcEnd;
  while( ( pcIdName > pcMsgId ) && ( *(pcIdName-1) != '@' ) )
  {
    pcIdName--;
    if ( *pcIdName == '.' )
    {
      ulDots++;
      pcDot = pcIdName;
    }
  }

  cbIdName = pcEnd - pcIdName;
  if ( ( (cbMsgId - cbIdName) < 3 ) || ( cbIdName < 3 ) || ( ulDots == 0 ) ||
       ( pcDot == pcIdName ) ||
       !utilVerifyDomainName( cbIdName, pcIdName ) )
  {
    return sessAddScore( pSess, pConfig->lScoreSuspiciousMsgId,
                    "Message-ID is not like \"*@domain.name\": %s", pszMegId );
  }

  // aaa.bbb.dom -> bbb.dom
  if ( ulDots > 1 )
  {
    pcIdName = pcDot + 1;
    cbIdName = pcEnd - pcIdName;
  }

  // Compare with client hostname.
  if ( ( pSess->pszHostName != NULL ) &&
       BUF_I_ENDS_WITH( strlen( pSess->pszHostName ), pSess->pszHostName,
                        cbIdName, pcIdName ) )
  {
    sessLog( pSess, 5, SESS_LOG_INFO,
             "Message-ID: \"%s\" matches the client hostname: %s",
             pszMegId, pSess->pszHostName );
    return FALSE;
  }

  // Compare with sender's domain.
  if ( ( pSess->pszSender != NULL ) &&
       BUF_I_ENDS_WITH( strlen( pSess->pszSender ), pSess->pszSender,
                        cbIdName, pcIdName ) )
  {
    sessLog( pSess, 5, SESS_LOG_INFO,
             "Message-ID: \"%s\" matches the sender's <%s> domain",
             pszMegId, pSess->pszSender );
    return FALSE;
  }

/*
  // Compare with first received-by host.
  if ( mfGetFirstReceivedByHost( pSess->pFile, &cbHost, &pcHost ) &&
       BUF_I_ENDS_WITH( cbHost, pcHost, cbIdName, pcIdName ) )
  {
    sessLog( pSess, 5, SESS_LOG_INFO,
             "Message-ID: \"%s\" matches received-by: %s",
             pszMegId, logBufToPSZ( cbHost, pcHost ) );
    return FALSE;
  }
*/
  return sessAddScore( pSess, pConfig->lScoreSuspiciousMsgId,
                       "Suspicious Message-ID: %s", pszMegId );
}

// static BOOL _sGetSpamStoreFileName(PSESS pSess, ULONG cbBuf, PCHAR pcBuf)

struct _KEYDATA {
  PSESS      pSess;
  struct tm  stTime;
};

static ULONG __cbMsgFileNameKey(CHAR chKey, ULONG cbBuf, PCHAR pcBuf,
                               PVOID pData)
{
  struct _KEYDATA      *pKeyData = (struct _KEYDATA *)pData;
  PSESS                pSess = pKeyData->pSess;
  ULONG                cbVal;
  PCHAR                pcDiv;

  switch( chKey )
  {
    case 'i':          // Session ID
      cbVal = min( strlen( &pSess->acId ), cbBuf );
      memcpy( pcBuf, &pSess->acId, cbVal );
      return cbVal;

    case 's':          // Sender mailbox (mailbox@domain)
    case 'S':          // Sender domain (mailbox@domain)
      if ( pSess->pszSender == NULL )
        return 0;

      pcDiv = strchr( pSess->pszSender, '@' );
      if ( pcDiv == NULL )
        return 0;

      if ( chKey == 's' )
      {
        cbVal = min( pcDiv - pSess->pszSender, cbBuf );
        memcpy( pcBuf, pSess->pszSender, cbVal );
        return cbVal;
      }

      pcDiv++;
      cbVal = min( strlen( pcDiv ), cbBuf );
      memcpy( pcBuf, pcDiv, cbVal );
      return cbVal;

    case 'r':          // First recipient mailbox
    case 'R':          // First recipient domain
      if ( pSess->cRcpt == 0 )
        return 0;

      pcDiv = strchr( pSess->ppszRcpt[0], '@' );
      if ( pcDiv == NULL )
        return 0;

      if ( chKey == 'r' )
      {
        cbVal = min( pcDiv - pSess->ppszRcpt[0], cbBuf );
        memcpy( pcBuf, pSess->ppszRcpt[0], cbVal );
        return cbVal;
      }

      pcDiv++;
      cbVal = min( strlen( pcDiv ), cbBuf );
      memcpy( pcBuf, pcDiv, cbVal );
      return cbVal;

    case 'y':          // Year YYYY
      return _snprintf( pcBuf, cbBuf, "%.4u", 1900 + pKeyData->stTime.tm_year );

    case 'm':          // Month MM
      return _snprintf( pcBuf, cbBuf, "%.2u", pKeyData->stTime.tm_mon + 1 );

    case 'd':          // Day of month DD
      return _snprintf( pcBuf, cbBuf, "%.2u", pKeyData->stTime.tm_mday );

    case 't':          // Time HHMMSS
      return _snprintf( pcBuf, cbBuf, "%.2u%.2u%.2u",
                        pKeyData->stTime.tm_hour, pKeyData->stTime.tm_min,
                        pKeyData->stTime.tm_sec );
  }

  *pcBuf = chKey;
  return 1;
}

static BOOL _sGetSpamStoreFileName(PSESS pSess, ULONG cbBuf, PCHAR pcBuf)
{
  LONG                 cbPathName;
  struct stat          stStat;
  ULONG                ulIdx;
  struct _KEYDATA      stKeyData;
  time_t               timeCur;

  time( &timeCur ); 
  _localtime( &timeCur, &stKeyData.stTime );
  stKeyData.pSess = pSess;

  cbPathName = utilStrFormat( cbBuf - 5, pcBuf, pConfig->pszSpamStore,
                              __cbMsgFileNameKey, &stKeyData );
  if ( cbPathName == -1 )
  {
    log( 1, "[ERROR] Cannot make filename from the template \"%s\"",
         pConfig->pszSpamStore );
    return FALSE;
  }
  debug( "Name: %s", pcBuf );

  if ( !utilMakePathToFile( cbPathName, pcBuf ) )
  {
    log( 1, "[ERROR] Cannot make directories of the path for the file \"%s\" "
         "to store spam message", pcBuf );
    return FALSE;
  }

  // Make unique filename if file exists.
  for( ulIdx = 0; ulIdx < 100; ulIdx++ )
  {
    if ( stat( pcBuf, &stStat ) == -1 )
      return TRUE;

    pcBuf[cbPathName] = '.';
    ultoa( rand(), &pcBuf[cbPathName + 1], 16 ); 
  }

  return FALSE;
}

static BOOL _sSaveAndClose(PSESS pSess, PMSGFILE pFile, PSZ pszFileName)
{
  BOOL       fSaved;
  CHAR       acBuf[512];
  PSZ        pszAddr = &acBuf;

  // Add X-SF field to the header.
  pszAddr += sprintf( pszAddr, "%s; id=%s; client=%s",
                  pSess->lScore == SF_SCORE_SPAM
                    ? "SPAM" : ( pSess->lScore == SF_SCORE_NOT_SPAM
                                 ? "NOT_SPAM"
                                 : ltoa( pSess->lScore, &acBuf[255],  10 ) ),
                  pSess->acId,
                  pSess->pszHostName != NULL ?
                    pSess->pszHostName : inet_ntoa( pSess->stInAddr ) );
  if ( pSess->ulRWLLevel != 0 )
    pszAddr += sprintf( pszAddr, "; rwl=%u", pSess->ulRWLLevel );
  if ( pSess->pszSpamTrap != NULL )
    pszAddr += sprintf( pszAddr, "; trap=%s", pSess->pszSpamTrap );
  if ( pSess->ulSPFLevel != ~0 )
    pszAddr += sprintf( pszAddr, "; spf=%s", apszSPFResult[pSess->ulSPFLevel] );
  mfSetHeader( pFile, "X-SF", &acBuf );

  fSaved = mfStore( pFile, pszFileName );
  mfClose( pFile );
  return fSaved;
}


static VOID _sOnRSET(PSESS pSess)
{
  if ( pSess->pszSender != NULL )
  {
    debugFree( pSess->pszSender );
    pSess->pszSender = NULL;
  }
  sessClearRecepient( pSess );
  pSess->lScore = pSess->lScoreClient;
  pSess->ulClentFlags &= ~FL_LOCAL_SENDER; // But do not reset local-client here.
  pSess->ulRWLLevel = 0;
  if ( pSess->pszSpamTrap != NULL )
  {
    debugFree( pSess->pszSpamTrap );
    pSess->pszSpamTrap = NULL;
  }
  pSess->ulSPFLevel = ~0;
}

static ULONG _sCheckOnAtAccept(PSESS pSess, struct in_addr stInAddr, PSZ pszHostName)
{
  LONG       lScore;
  PSZ        pszLogDetail;

  pSess->stInAddr = stInAddr;

  // Set host name.

  if ( pSess->pszHostName != NULL )
    debugFree( pSess->pszHostName );

  if ( pszHostName != NULL )
  {
    // Host name specified: same as IP - has no PTR, other - host name.
    pSess->pszHostName = inet_addr( pszHostName ) == stInAddr.s_addr
                           ? NULL : debugStrDup( pszHostName );
  }
  else
  {
    // Host name not specified. Request it at the DNS server.

    CHAR     acPTRRes[512];
    ULONG    cPTRRes;

    dnsPTRRequest( stInAddr, sizeof(acPTRRes), &acPTRRes, &cPTRRes );

    if ( cPTRRes == 0 )
    {
      pSess->pszHostName = NULL;
      debug( "PTR-record for %s not found", inet_ntoa( pSess->stInAddr ) );
    }
    else
    {
      debug( "PTR-record for %s found: %s",
             inet_ntoa( pSess->stInAddr ), &acPTRRes );
      pSess->pszHostName = debugStrDup( &acPTRRes );
    }
  }

  pSess->ulClentFlags &= ~(FL_LOCAL_CLIENT | FL_RELAY);

  // Detect relay.
  if ( cfgHostListCheck( &pConfig->lsHostListRelays,
                         pSess->stInAddr, STR_LEN( pSess->pszHostName ),
                         pSess->pszHostName, &lScore ) )
  {
    pSess->ulClentFlags |= FL_RELAY;
    pszLogDetail = "relay";
  }
  // Detect local client by the ip-address/host name.
  else if ( sessClientListed( pSess, &pConfig->lsHostListLocal ) )
  {
    pSess->ulClentFlags |= FL_LOCAL_CLIENT;
    pszLogDetail = "local";
  }
  else
    pszLogDetail = "external";

  sessLog( pSess, 3, SESS_LOG_INFO, "Client: %s, [%s] %s", pszLogDetail,
           inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );

  if ( (pSess->ulClentFlags & FL_RELAY) != 0 )
  {
    sessAddScore( pSess, lScore, "Relay." );
  }
  else if ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) == 0 &&
            // Scoring address by internal dynamic ip-address list.
            !sessAddScore( pSess, _dynipCheck( pSess->stInAddr ),
                      "IP-addres [%s] was found in the dynamic ip-address list.",
                      inet_ntoa( pSess->stInAddr ) ) )
  {
    if ( // Check the frequency limit.
         ( pConfig->ulIPFreqMaxAtAcceptNum != 0 ) &&
         !sessClientListed( pSess, &pConfig->lsHostListIPFreqIgnore ) &&
         idfrActivation( &idfreqClients, stInAddr.s_addr,
                         pConfig->ulIPFreqExpiration != 0 ) )
    {
      CHAR     acBuf[24];

      utilSecToStrTime( pConfig->ulIPFreqDuration, sizeof(acBuf), &acBuf );
      sessAddScore( pSess, SF_SCORE_SPAM, "Maximum number of @ACCEPT commands "
                    "(%u) for [%s] per %s.", pConfig->ulIPFreqMaxAtAcceptNum,
                    inet_ntoa( pSess->stInAddr ), &acBuf );

      if ( pConfig->ulIPFreqExpiration != 0 )
        _dynipSet( stInAddr, SF_SCORE_SPAM, pConfig->ulIPFreqExpiration );

      statChange( STAT_IP_FREQ_LIMIT, 1 );
    }
    else
    if ( // Scoring client w/o PTR record.
         ( ( pSess->pszHostName != NULL ) ||
           !sessAddScore( pSess, pConfig->lScoreNoPTR,
                          "Client %s has no PTR-record.",
                          inet_ntoa( pSess->stInAddr ) ) )
       && // Scoring client ip-address/host name.
         cfgHostListCheck( &pConfig->lsHostListScore, pSess->stInAddr,
                           STR_LEN( pSess->pszHostName ), pSess->pszHostName,
                           &lScore ) )
      sessAddScore( pSess, lScore, "Client [%s] %s scored by configured list.",
                    inet_ntoa( pSess->stInAddr ),
                    STR_SAFE( pSess->pszHostName ) );
  }

  return pSess->lScore == SF_SCORE_SPAM ? REQ_ANSWER_SPAM : REQ_ANSWER_OK;
}

static ULONG _sCheckOnMAILFROM(PSESS pSess, ULONG cbFrom, PCHAR pcFrom)
{
  ULONG      cbDomain, cbSender;
  PCHAR      pcDomain;
  LONG       lScore;

/*
  // pSess->fLocalClient is TRUE when  client is not a relay and from local
  // network  OR  client is a host behind relays and from local network.
  pSess->fLocalSender = pSess->fLocalClient;
*/

  // Session already have "final" score.
  switch( pSess->lScore )
  {
    case SF_SCORE_SPAM:
      return REQ_ANSWER_SPAM;

    case SF_SCORE_NOT_SPAM:
      return REQ_ANSWER_OK;
  }

  if ( pSess->pszSender != NULL )
  {
    cbSender = strlen( pSess->pszSender );
    pcDomain = utilEMailDomain( cbSender, pSess->pszSender, &cbDomain );
    if ( pcDomain == NULL )
    {
      sessAddScore( pSess, SF_SCORE_SPAM, "Malformed MAIL FROM address: <%s>.",
                    pSess->pszSender );
      return REQ_ANSWER_SPAM;
    }

    // Detect local sender by e-mail address (domain part).
    if ( cfgIsLocalEMailDomain( cbDomain, pcDomain ) )
    {
      pSess->ulClentFlags |= FL_LOCAL_SENDER;
      sessLog( pSess, 3, SESS_LOG_INFO, "Sender <%s> is local.",
                    pSess->pszSender );
    }
  } // if ( pSess->pszSender != NULL )

  // Search MAIL FROM address in the white list - it is not a SPAM if listed.
  if ( addrlstCheck( &stWhiteAddrList, pSess->pszSender ) )
  {
    sessAddScore( pSess, SF_SCORE_NOT_SPAM,
                  "Sender <%s> found in the whitelist.", pSess->pszSender );
    return REQ_ANSWER_OK;
  }

  // Do not check MAIL FROM by configured patterns, client's IP with RWL, EHLO
  // for senders in local networs or relays (for relays will be second pass.).
  if ( pSess->ulClentFlags != 0 )
    return REQ_ANSWER_OK;

  do
  {
    // Check full MAIL FROM string as it given, with <, > and any extra
    // characters by configured patterns for MAIL FROM.
    if ( ( cbFrom != 0 ) && ( pcFrom != NULL ) &&
         cfgHostListCheckName( &pConfig->lsHostListMailFrom, cbFrom, pcFrom,
                               &lScore ) &&
         sessAddScore( pSess, lScore,
                       "MAIL FROM \"%s\" matches the configured pattern.",
                       pcFrom ) )
      break;

    // Check client's ip-address with RWL.
    if ( sessClientListed( pSess, &pConfig->lsHostListRWLIgnore ) )
      sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
               "configured RWL ignore list.",
               inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
    else
    {
      pSess->ulRWLLevel = _reqCheckRWL( pSess->stInAddr );
      if ( sessIsCommandTimeout( pSess ) )
        return REQ_ANSWER_ERROR;

      if ( ( pSess->ulRWLLevel != 0 ) &&
           sessAddScore( pSess, pConfig->alScoreRWL[pSess->ulRWLLevel - 1],
                         "IP-addres %s was found in RWL (level %u).",
                         inet_ntoa( pSess->stInAddr ), pSess->ulRWLLevel ) )
        break;
    }

    // Check EHLO

    if ( pSess->pszEHLO != NULL )
    {
      ULONG              cbEHLO = strlen( pSess->pszEHLO );
      struct in_addr     stInAddr;

      // Name of the local domain is specified in EHLO - spam!
      if ( ( (pSess->ulClentFlags & FL_LOCAL_SENDER) == 0 ) &&
           cfgIsMatchPtrnList( pConfig->cbLocalDomains, pConfig->pcLocalDomains,
                               cbEHLO, pSess->pszEHLO ) )
      {
        sessAddScore( pSess, SF_SCORE_SPAM,
                      "Local domain is specified in EHLO: %s.", pSess->pszEHLO );
        break;
      }

      // Search EHLO in configured patterns.
      if ( cfgHostListCheckName( &pConfig->lsHostListEHLO, cbEHLO, pSess->pszEHLO,
                                 &lScore ) &&
           sessAddScore( pSess, lScore,
                         "EHLO \"%s\" matches the configured pattern.",
                         pSess->pszEHLO ) )
        break;

      if ( ( pSess->ulRWLLevel != 0 ) &&
           ( pSess->ulRWLLevel < pConfig->ulCheckEHLOOnRWL ) )
      {
        sessLog( pSess, 3, SESS_LOG_INFO, "RWL level is %u, it is less than "
                 "the configured value %u to check EHLO.",
                 pSess->ulRWLLevel, pConfig->ulCheckEHLOOnRWL );
      }
      else
      {
        // Try to convert EHLO string [x.x.x.x] or x.x.x.x to IP-address.
        if ( ( ( pSess->pszEHLO[0] != '[' ) || ( pSess->pszEHLO[1] == '\0' ) ||
               !utilStrToInAddr( cbEHLO - 2, &pSess->pszEHLO[1], &stInAddr ) )
             &&
               !utilStrToInAddr( cbEHLO, pSess->pszEHLO, &stInAddr ) )
          stInAddr.s_addr = (u_long)(-1);

        // Comparing EHLO IP/hostname with client's IP or hostname.

        if ( ( pConfig->lScoreInvalidEHLO != SF_SCORE_NONE ) &&
             !_sCheckEHLO( pSess, stInAddr ) &&
             sessAddScore( pSess, pConfig->lScoreInvalidEHLO,
                           "Invalid host name/address at the EHLO: %s.",
                           pSess->pszEHLO ) )
          break;

        if ( sessIsCommandTimeout( pSess ) )
          return REQ_ANSWER_ERROR;

        // Scoring EHLO by URIBL.

        if ( stInAddr.s_addr == (u_long)(-1) ) // EHLO is not IP.
        {
          if ( sessClientListed( pSess, &pConfig->lsHostListEHLOURIBLIgnore ) )
            sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
                     "configured URIBL ignore list for EHLO.",
                     inet_ntoa( pSess->stInAddr ),
                     STR_SAFE( pSess->pszHostName ) );
          else if ( sessAddScore( pSess, _reqScoreURIBL( cbEHLO, pSess->pszEHLO ),
                                  "EHLO host name %s listed in URIBL.",
                                  pSess->pszEHLO ) )
            break;
          else if ( sessIsCommandTimeout( pSess ) )
            return REQ_ANSWER_ERROR;
        }
      } // if ( pSess->ulRWLLevel < pConfig->ulCheckEHLOOnRWL ) else
    } // if ( pSess->pszEHLO != NULL )
  }
  while( FALSE );

  return pSess->lScore == SF_SCORE_SPAM ? REQ_ANSWER_SPAM : REQ_ANSWER_OK;
}

static int __compMX(const void *pRec1, const void *pRec2)
{
  PUSHORT    pusLevel1 = *(PUSHORT *)pRec1;
  PUSHORT    pusLevel2 = *(PUSHORT *)pRec2;

  return ((int)*pusLevel1) - ((int)*pusLevel2);
}

static ULONG _sCheckOnDATA(PSESS pSess)
{
  ULONG      ulIdx;
  ULONG      cbAddr;
  PSZ        pszAddr;
  ULONG      cbDomain;
  PCHAR      pcDomain;
  ULONG      ulRC;

  // Session already have "final" score.
  switch( pSess->lScore )
  {
    case SF_SCORE_SPAM:
      return REQ_ANSWER_SPAM;

    case SF_SCORE_NOT_SPAM:
      return REQ_ANSWER_OK;
  }

  if ( (pSess->ulClentFlags & FL_RELAY) != 0 )
    return REQ_ANSWER_OK;

  if ( ( (pSess->ulClentFlags & FL_LOCAL_SENDER) != 0 ) &&
       ( pConfig->ulTTLAutoWhiteListed != 0 ) &&
       !cfgIsMatchPtrnList( pConfig->cbAutoWhitelistIgnoreSenders,
                            pConfig->pcAutoWhitelistIgnoreSenders,
                            STR_LEN( pSess->pszSender ), pSess->pszSender ) )
  {
    // Sender is local user - add not local recepients to the auto-whitelist.
    for( ulIdx = 0; ulIdx < pSess->cRcpt; ulIdx++ )
    {
      pszAddr = pSess->ppszRcpt[ulIdx];
      cbAddr = strlen( pszAddr );

      // Detect local recepient.
      pcDomain = utilEMailDomain( cbAddr, pszAddr, &cbDomain );
      if ( ( pcDomain != NULL ) &&
           !cfgIsLocalEMailDomain( cbDomain, pcDomain ) )
      {
        addrlstAdd( &stWhiteAddrList, pszAddr, pConfig->ulTTLAutoWhiteListed );
        sessLog( pSess, 4, SESS_LOG_INFO,
                 "<%s> is local sender, add recepient <%s> to the whitelist",
                 STR_SAFE( pSess->pszSender ), pszAddr );
      }
    }
  }

  // Search spamtrap addresses in the list of recipients.

  if ( pSess->pszSpamTrap != NULL )
  {
    debugFree( pSess->pszSpamTrap );
    pSess->pszSpamTrap = NULL;
  }

  if ( pConfig->cbSpamTrap != 0 )
  {
    ULONG              cbSpamTrap = pConfig->cbSpamTrap;
    PCHAR              pcSpamTrap = pConfig->pcSpamTrap;

    while( ( pSess->pszSpamTrap == NULL) &&
           utilStrCutWord( &cbSpamTrap, &pcSpamTrap, &cbAddr, &pszAddr ) )
    {
      for( ulIdx = 0; ulIdx < pSess->cRcpt; ulIdx++ )
      {
        if ( BUF_STR_IEQ( cbAddr, pszAddr, pSess->ppszRcpt[ulIdx] ) )
        {
          pSess->pszSpamTrap = utilStrNewSZ( cbAddr, pszAddr );
          sessLog( pSess, 3, SESS_LOG_INFO, "From <%s> to the spamtrap <%s>",
                   STR_SAFE( pSess->pszSender ), pSess->pszSpamTrap );
          break;
        }
      }
    }

    if ( ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) == 0 ) &&
         ( pSess->pszSpamTrap != NULL ) )
    {
      statChange( STAT_SPAM_TRAP, 1 );

      if ( ( pConfig->lScoreSpamTrapClient != SF_SCORE_NONE ) &&
           ( pConfig->ulSpamTrapClientTTL != 0 ) )
        _dynipSet( pSess->stInAddr, pConfig->lScoreSpamTrapClient,
                   pConfig->ulSpamTrapClientTTL );

      // Now, we need wait a message.
      return REQ_ANSWER_OK;
    }
  }


  if ( (pSess->ulClentFlags & FL_LOCAL_SENDER) != 0 )
  {
    if ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) == 0 )
    {
      // Sender is local user and connected not from local network.
      for( ulIdx = 0; ulIdx < pSess->cRcpt; ulIdx++ )
      {
        pszAddr = pSess->ppszRcpt[ulIdx];
        cbAddr = strlen( pszAddr );

        // Detect local recepient.
        pcDomain = utilEMailDomain( cbAddr, pszAddr, &cbDomain );
        if ( ( pcDomain != NULL ) &&
             cfgIsLocalEMailDomain( cbDomain, pcDomain ) )
        {
          // Local sender and local recepient but sender connected not from
          // the local network.
          sessAddScore( pSess, pConfig->lScoreExtClntLocSndrLocRcpt,
                        "Sender <%s> and recepient <%s> are local but client "
                        "[%s] is not local", STR_SAFE( pSess->pszSender ),
                        pszAddr, inet_ntoa( pSess->stInAddr ) );
          break;
        }
      }
    } // if ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) == 0 )

    // Do not other checks when sender is local user.

  } // if ( (pSess->ulClentFlags & FL_LOCAL_SENDER) != 0 )
  else
    if ( ( pSess->ulRWLLevel != 0 ) &&
         ( pSess->ulRWLLevel < pConfig->ulCheckMailFromOnRWL ) )
  {
    // Don't check MAIL FROM when RWL result lower than the configured value.
    sessLog( pSess, 3, SESS_LOG_INFO, "RWL level is %u, it is less than "
             "the configured value %u to check sender address.",
             pSess->ulRWLLevel, pConfig->ulCheckMailFromOnRWL );
  }
  else
  {
    // Greylist
    LONG     lAdded = glAdd( pSess );

    if ( lAdded > 0 )
    {
      // There are new records (recepients) added in the greylist for this sender
      // - delay message.

      sessLog( pSess, 3, SESS_LOG_DELAYED,
               "Client %s, sender <%s>: new greylist records: %d",
               inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszSender ),
               lAdded );
      pSess->lScore = SF_SCORE_NONE;
      return REQ_ANSWER_DELAYED;
    }
    else if ( lAdded == 0 )
    {
      // All recepients for external sender's ip/address presents in the greylist.
      sessLog( pSess, 3, SESS_LOG_INFO,
               "Client %s, sender <%s>: all recepiens are found in the greylist.",
               inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszSender ) );
    }
    // lAdded == -1 - no needed to use greylist for given addresses.

    // Check ip-address with DNSBL.
    if ( !_sCheckDNSBL( pSess ) && !sessIsCommandTimeout( pSess ) )
    do
    {
      // Check sender.

      pcDomain = utilEMailDomain( STR_LEN( pSess->pszSender ), pSess->pszSender,
                                  &cbDomain );
      if ( ( pcDomain != NULL ) && pConfig->fMailBoxCheck )
      {
        if ( sessClientListed( pSess, &pConfig->lsMailBoxCheckIgnore ) )
          sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
                "configured mailbox check ignore list.",
                inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
        else if ( cfgIsMatchPtrnList( pConfig->cbMailBoxCheckIgnoreSenders,
                              pConfig->pcMailBoxCheckIgnoreSenders,
                              STR_LEN( pSess->pszSender ), pSess->pszSender ) )
          sessLog( pSess, 5, SESS_LOG_INFO,
                   "Ignore mailbox check for sender <%s>", pSess->pszSender );
        else
        {
          ULONG              cMX;
          PCHAR              apMX[16]; // Array size - max. number of MXes for domain.
          PCHAR              pMX;
          CHAR               aMXRes[512];
          ULONG              cMXRes;
          struct in_addr     aARes[512];
          LONG               cARes;
          ULONG              ulChkRC;

          if ( *pcDomain != '[' )
          {
            // Scoring sender by URIBL.
            if ( sessClientListed( pSess, &pConfig->lsHostListMailFromURIBLIgnore ) )
              sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
                       "configured URIBL for senders ignore list.",
                       inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
            else
            {
              if ( sessAddScore( pSess, _reqScoreURIBL( cbDomain, pcDomain ),
                                 "Sender <%s> domain name found in URIBL.",
                                 pSess->pszSender ) )
                break;

              if ( sessIsCommandTimeout( pSess ) )
                return REQ_ANSWER_ERROR;
            }

            // Checking the sender mailbox.
            // Get MX records for the sender's domain.
            // utilEMailDomain() was for zero-ended addr => pcDomain is zero-ended too.
            debug( "Search MX records for the domain %s...", pcDomain );
            ulRC = dnsRequest( DNSREC_TYPE_MX, pcDomain, sizeof(aMXRes),
                               &aMXRes, &cMXRes );
            if ( ulRC == DNS_CANCEL )
              return REQ_ANSWER_ERROR;

            if ( cMXRes == 0 )
            {
              debug( "MX records for the domain %s not found", pcDomain );
              ulRC = dnsRequest( DNSREC_TYPE_A, pcDomain, sizeof(aMXRes),
                                 &aMXRes, &cMXRes );
              if ( cMXRes != 0 )
              {
                // Domain part of address is a host name.
                debug( "Domain %s is a host name", pcDomain );
                pMX = strchr( pcDomain, '.' );
                if ( pMX != NULL )
                  ulRC = dnsRequest( DNSREC_TYPE_MX, &pMX[1], sizeof(aMXRes),
                                     &aMXRes, &cMXRes );
              }
            }

            if ( sessIsCommandTimeout( pSess ) )
              return REQ_ANSWER_ERROR;

            if ( cMXRes == 0 )
            {
              sessAddScore( pSess, SF_SCORE_SPAM,
                            "No MX servers for the sernder's domain %s.", pcDomain );
              break;
            }

            // Collect pointers to MX-records at apMX[], number of pointers - cMX.
            // Record: 2 bytes - MX-server level, ASCIIZ - host name.
            pMX = &aMXRes;
            for( cMX = 0; ( cMX < cMXRes ) && ( cMX < ARRAY_SIZE(apMX) ); cMX++ )
            {
              apMX[cMX] = pMX;                                 // Store pointer.
              pMX = strchr( &pMX[sizeof(USHORT)], '\0' ) + 1;  // Jump to next record.
            }
            // Sort pointers to MX-records by MX-levels.
            qsort( &apMX, cMX, sizeof(PCHAR), __compMX );

            // Check MAIL FROM address on the MX-server.

            debug( "Check MAIL FROM address on the MX-server..." );
            if ( cMXRes > 10 )
              cMXRes = 10;
            for( cMX = 0, ulChkRC = MBC_FAIL; cMX < cMXRes && ulChkRC >= MBC_FAIL;
                 cMX++ )
            {
              pMX = apMX[cMX];
              debug( "Search host %s", &pMX[2] );
              // Get all IPs of MX server name.
              ulRC = dnsRequest( DNSREC_TYPE_A, &pMX[2], sizeof(aARes),
                                 (PCHAR)&aARes, (PULONG)&cARes );
              if ( ulRC == DNS_CANCEL )
                return REQ_ANSWER_ERROR;

              if ( cARes > 10 )
                cARes = 10;
              for( cARes--; (cARes >= 0) && (ulChkRC >= MBC_FAIL); cARes-- )
              {
                ulChkRC = MailBoxCheck( aARes[cARes], pSess->pszSender );
                if ( sessIsCommandTimeout( pSess ) )
                  return REQ_ANSWER_ERROR;
              }
            }
          } // if ( *pcDomain != '[' )
          else
            // Sender domain part is an ip-address in square brackets.
            ulChkRC = utilStrToInAddr( cbDomain - 2, &pcDomain[1], &aARes[0] )
                        ? MailBoxCheck( aARes[0], pSess->pszSender ) : MBC_FAIL;

          if ( sessAddScore( pSess, pConfig->alScoreMailBoxCheck[ulChkRC],
                             "Mailbox %s checking result: %s.",
                             pSess->pszSender, apszMBCResult[ulChkRC] ) )
            break;
        }
      } // if ( ( pcDomain != NULL ) && pConfig->fMailBoxCheck )

      // Scoring by SPF.
      if ( pSess->pszSender != NULL )
      {
        if ( sessClientListed( pSess, &pConfig->lsHostListSPFIgnore ) )
          sessLog( pSess, 4, SESS_LOG_INFO, "Client [%s] %s is listed in the "
                   "configured SPF ignore list.",
                   inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );
        else
        {
          CHAR     acExp[256];

          ulRC = spfCheckHost( pSess->stInAddr, NULL, pSess->pszSender,
                               pSess->pszEHLO, sizeof(acExp), &acExp );
          pSess->ulSPFLevel = ulRC;

          if ( sessAddScore( pSess, pConfig->alScoreSPF[ulRC],
                             "SPF check: %s (%s)",
                             apszSPFResult[ulRC], &acExp ) )
            break;
        }
      } // if ( pSess->pszSender != NULL )
    }
    while( FALSE );
  } // if ( pSess->ulRWLLevel < pConfig->ulCheckMailFromOnRWL ) else

  return pSess->lScore == SF_SCORE_SPAM ? REQ_ANSWER_SPAM : REQ_ANSWER_OK;
}

static ULONG _sCheckOnAtContent(PSESS pSess, PMSGFILE pFile)
{
  struct in_addr       stInAddr;
  ADDRLIST             stList;
  ULONG                ulIdx;
  PSZ                  pszAddr;
  CHAR                 acHostName[512];

  if ( (pSess->ulClentFlags & FL_RELAY) != 0 )
  {
    switch( pSess->lScore )
    {
      case SF_SCORE_SPAM:
        return REQ_ANSWER_SPAM;

      case SF_SCORE_NOT_SPAM:
        return REQ_ANSWER_OK;
    }

    if ( !mfGetOutsideHost( pFile, &stInAddr, sizeof(acHostName),
                            &acHostName ) )
    {
      sessLog( pSess, 1, SESS_LOG_WARNING, "Cannot find outside host in "
               "fields \"Received\" of the message header." );
    }
    else
    {
      ULONG  ulAnswer = _sCheckOnAtAccept( pSess, stInAddr,
                                  acHostName[0] == '\0' ? NULL : &acHostName );

      if ( ulAnswer == REQ_ANSWER_OK )
      {
        PSZ  pszEHLO = pSess->pszEHLO;

        // No need to check EHLO received from the relay. We set it to NULL
        // before checks and return it later.
        pSess->pszEHLO = NULL;

        ulAnswer = _sCheckOnMAILFROM( pSess, 0, NULL );
        if ( ulAnswer == REQ_ANSWER_OK )
          ulAnswer = _sCheckOnDATA( pSess );

        pSess->pszEHLO = pszEHLO;
      }

      // Error or delayed message - stop checking right now.
      if ( ( ulAnswer != REQ_ANSWER_OK ) && ( ulAnswer != REQ_ANSWER_SPAM ) )
        return ulAnswer;
    }
  }

  // Check the message.

  if ( pSess->pszSpamTrap != NULL )
  {
    // Message sended to SpamTrap address. Collecting hostnames from links.
    ULONG  ulCount = addrlstGetCount( &stSpamURIHostList );

    mfScanBody( pFile, &stSpamURIHostList );

    ulCount = addrlstGetCount( &stSpamURIHostList ) - ulCount;
    if ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) == 0 )
    {
      sessAddScore( pSess, SF_SCORE_SPAM, "Found %u new spam URL host names",
                    ulCount );
      return REQ_ANSWER_SPAM;
    }
    else
      sessLog( pSess, 4, SESS_LOG_INFO, "Collected %u spam URL host names",
               ulCount );
  }

  if ( (pSess->ulClentFlags & FL_LOCAL_CLIENT) != 0 )
    return REQ_ANSWER_OK;

  if ( // Have "final" score - no need checks any more.
       ( ( pSess->lScore & (SF_SCORE_SPAM | SF_SCORE_NOT_SPAM) ) == 0 ) &&
       // Check the field "Message-ID:".
       !_sCheckMessageId( pSess, pFile ) )
  {
    // Explore the content of the message.

    if ( !addrlstInit( &stList, 16 ) )
    {
      debug( "addrlstInit() failed" );
      return REQ_ANSWER_OK;
    }
    mfScanBody( pFile, &stList );

    // Check addresses by SpamTrap list.
    for( ulIdx = 0; ulIdx < stList.cItems; ulIdx++ )
    {
      pszAddr = stList.ppItems[ulIdx]->szAddr;
      if ( addrlstCheck( &stSpamURIHostList, pszAddr ) )
      {
        statChange( STAT_SPAM_URIHOSTS_FOUND, 1 );

        if ( sessAddScore( pSess, pConfig->lScoreSpamURIHost,
                           "Spam hostname at the message: %s.", pszAddr ) )
          break;
      }
    }

    if ( ( pSess->lScore & (SF_SCORE_SPAM | SF_SCORE_NOT_SPAM) ) == 0 )
    {
      // Check addresses by URIBL.
      if ( ( pSess->ulRWLLevel != 0 ) &&
           ( pSess->ulRWLLevel < pConfig->ulCheckMsgBodyOnRWL ) )
        sessLog( pSess, 3, SESS_LOG_INFO, "RWL level is %u, it is less than "
                 "the configured value %u to check message body (URIBL).",
                 pSess->ulRWLLevel, pConfig->ulCheckMsgBodyOnRWL );
      else
      {
        for( ulIdx = 0; ulIdx < stList.cItems; ulIdx++ )
        {
          pszAddr = stList.ppItems[ulIdx]->szAddr;
          if ( sessAddScore( pSess, _reqScoreURIBL( strlen( pszAddr ), pszAddr ),
                             "Host name from the message found in URIBL: %s.",
                             pszAddr ) ||
               sessIsCommandTimeout( pSess ) )
            break;
        }
      }
    }

    addrlstDone( &stList );
  }

  return pSess->lScore == SF_SCORE_SPAM ? REQ_ANSWER_SPAM : REQ_ANSWER_OK;
}


// Commands routines.
// ------------------

static BOOL _scAtAccept(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG                cbIP, cbHostName, cbArg = pSessCmd->cbArg;
  PCHAR                pcIP, pcHostName, pcArg = &pSessCmd->acArg;
  struct in_addr       stInAddr;

  sessLog( pSess, 5, SESS_LOG_INFO, "@ACCEPT %s session",
           pSess->stInAddr.s_addr != 0 ? "reuse" : "new" );

  // First word - IP-address of SMTP client,
  if ( !utilStrCutWord( &cbArg, &pcArg, &cbIP, &pcIP ) )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "IP-address not specified" );
    return FALSE;
  }

  // Stripping square brackets around IP-address.
  if ( ( *pcIP == '[' ) && ( pcIP[cbIP-1] == ']' ) )
  {
    pcIP++;
    cbIP -= 2;
  }

  if ( !utilStrToInAddr( cbIP, pcIP, &stInAddr ) )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Invalid IP-address" );
    return FALSE;
  }

  // Second word - host name of SMTP client,
  if ( utilStrCutWord( &cbArg, &pcArg, &cbHostName, &pcHostName ) )
  {
    // Stripping square brackets around host name.
    if ( ( *pcHostName == '[' ) && ( pcHostName[cbHostName-1] == ']' ) )
    {
      pcHostName++;
      cbHostName -= 2;
    }
    pcHostName[cbHostName] = '\0';
  }
  else
    pcHostName = NULL;

  statChange( STAT_SESSIONS, 1 );

  // Reset session's data.
  pSess->lScoreClient = 0;
  _sOnRSET( pSess );
  if ( pSess->pszHostName != NULL )
  {
    debugFree( pSess->pszHostName );
    pSess->pszHostName = NULL;
  }
  if ( pSess->pszEHLO != NULL )
  {
    debugFree( pSess->pszEHLO );
    pSess->pszEHLO = NULL;
  }

  _sessCmdAnswer( pSess, pSessCmd,
                  _sCheckOnAtAccept( pSess, stInAddr, pcHostName ),
                  NULL );

  // Score on RSET, EHLO, MAIL FROM (in _sOnRSET()) will be resets to this
  // initial value.
  pSess->lScoreClient = pSess->lScore;

  return TRUE;
}

static BOOL _scRSET(PSESS pSess, PSESSCMD pSessCmd)
{
  _sOnRSET( pSess );
//  _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, REQ_ANSWER_OK, NULL );
  _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_OK, NULL );
  return TRUE;
}

static BOOL _scEHLO(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG      cbEHLO, cbArg = pSessCmd->cbArg;
  PCHAR      pcEHLO, pcArg = &pSessCmd->acArg;

  if ( pSess->stInAddr.s_addr == 0 )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Bad sequence of commands" );
    debug( "Bad sequence of commands, id: %s", &pSess->acId );
    return TRUE;
  }

  if ( pSess->pszEHLO != NULL )
    debugFree( pSess->pszEHLO );

  sessLog( pSess, 5, SESS_LOG_INFO, "EHLO: %s", pcArg );

  // First word - host name.
  pSess->pszEHLO = utilStrCutWord( &cbArg, &pcArg, &cbEHLO, &pcEHLO ) ?
                     utilStrNewSZ( cbEHLO, pcEHLO ) : NULL;

  _scRSET( pSess, pSessCmd );
  return TRUE;
}

static BOOL _scMAIL(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG      cbAddr, cbArg = pSessCmd->cbArg;
  PCHAR      pcAddr, pcArg = &pSessCmd->acArg;
  ULONG      ulAnswer;

  if ( pSess->pszEHLO == NULL )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Bad sequence of commands" );
    debug( "Bad sequence of commands, id: %s", &pSess->acId );
    return TRUE;
  }

  do
  {
    // Begin of arguments - "FROM:" (ignore spaces around colon).
    if ( ( cbArg < 4 ) || ( memicmp( pcArg, "FROM", 4 ) != 0 ) )
      break;
    cbArg -= 4;
    pcArg += 4;
    BUF_SKIP_DELIM( cbArg, pcArg, ':' );

    // <-- test MAIL FROM pattern here...
    //     or save MAIL FROM to check it in right time? -->

    // Get e-mail address from the arguments string.
    if ( *((PUSHORT)pcArg) == (USHORT)'><' )
    {
      sessLog( pSess, 4, SESS_LOG_INFO, "Empty MAIL FROM address" );
      cbAddr = 0;
      pcAddr = NULL;
    }
    else
    {
      if ( !_reqParsePathAddr( cbArg, pcArg, &cbAddr, &pcAddr ) )
        break;
      sessLog( pSess, 5, SESS_LOG_INFO, "MAIL FROM:%s", pcArg );
    }

    // Reset session's data.
    _sOnRSET( pSess );

    pSess->pszSender = utilStrNewSZ( cbAddr, pcAddr );

    ulAnswer = _sCheckOnMAILFROM( pSess, cbArg, pcArg );
    _sessCmdAnswer( pSess, pSessCmd,
                    ( ulAnswer == REQ_ANSWER_SPAM ) && pConfig->pszSpamStore
                      ? REQ_ANSWER_OK : ulAnswer,
                    NULL );
    return TRUE;
  }
  while( FALSE );

  _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR, "Syntax error" );
  return TRUE;
}

static BOOL _scRCPT(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG      cbAddr, cbArg = pSessCmd->cbArg;
  PCHAR      pcAddr, pcArg = &pSessCmd->acArg;

/* --- MAIL FROM may be <> ! ---
  if ( pSess->pszSender == NULL )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Bad sequence of commands" );
    debug( "Bad sequence of commands, id: %s", &pSess->acId );
    return TRUE;
  }*/

  do
  {
    // Begin of arguments - "TO:" (ignore spaces around colon).
    if ( ( cbArg < 2 ) || ( memicmp( pcArg, "TO", 2 ) != 0 ) )
      break;
    cbArg -= 2;
    pcArg += 2;
    BUF_SKIP_DELIM( cbArg, pcArg, ':' );

    // Get e-mail address from the arguments string.
    if ( !_reqParsePathAddr( cbArg, pcArg, &cbAddr, &pcAddr ) )
      break;

    sessLog( pSess, 5, SESS_LOG_INFO, "RCPT TO:%s", pcArg );
    sessAddRecepient( pSess, cbAddr, pcAddr );

//    _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, REQ_ANSWER_OK, NULL );
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_OK, NULL );
    return TRUE;
  }
  while( FALSE );

  _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR, "Syntax error" );
  return TRUE;
}

static BOOL _scDATA(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG      ulAnswer;

  if ( pSess->cRcpt == 0 )
  {
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Bad sequence of commands" );
    debug( "Bad sequence of commands, id: %s", &pSess->acId );
    return TRUE;
  }

  sessLog( pSess, 5, SESS_LOG_INFO, "DATA" );
  ulAnswer = _sCheckOnDATA( pSess );
  _sessCmdAnswer( pSess, pSessCmd,
                  ( ulAnswer == REQ_ANSWER_SPAM ) && pConfig->pszSpamStore
                    ? REQ_ANSWER_OK : ulAnswer,
                  NULL );
  return TRUE;
}

static BOOL _scAtContent(PSESS pSess, PSESSCMD pSessCmd)
{
  ULONG      ulAnswer;
  PMSGFILE   pFile;
  CHAR       acPathName[_MAX_PATH];

  sessLog( pSess, 5, SESS_LOG_INFO, "@CONTENT" );

  pFile = mfOpen( &pSessCmd->acArg );
  if ( pFile == NULL )
  {
    sessLog( pSess, 1, SESS_LOG_ERROR, "Cannot open message file: %s.",
             &pSessCmd->acArg );
//    ulAnswer = REQ_ANSWER_ERROR;
    _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_ERROR,
                    "Cannot open message file: %s.", &pSessCmd->acArg );
    _sOnRSET( pSess );
    return TRUE;
  }
//  else
  {
    ulAnswer = _sCheckOnAtContent( pSess, pFile );

    if ( ( ulAnswer == REQ_ANSWER_OK ) && pConfig->fUpdateHeader )
    {
      PCHAR  pcPathEnd;
      BOOL   fSaved;

      // Make temporary file name.
      strlcpy( &acPathName, &pSessCmd->acArg, sizeof(acPathName) );
      pcPathEnd = strrchr( &acPathName, '\\' );
      if ( pcPathEnd != NULL )
        pcPathEnd++;
      else
      {
        pcPathEnd = strchr( &acPathName, ':' );
        if ( pcPathEnd != NULL )
          pcPathEnd++;
        else
          pcPathEnd = &acPathName;
      }
      _snprintf( pcPathEnd, sizeof(acPathName) - (pcPathEnd - &acPathName),
                 "%P.sf", pSess );

      // Save message (with changed header) to the temporary file, delete
      // original file, rename temporary file to original file name.
      _sSaveAndClose( pSess, pFile, &acPathName );

      if ( fSaved )
      {
        fSaved = ( unlink( &pSessCmd->acArg ) == 0 ) &&
                 ( rename( &acPathName, &pSessCmd->acArg ) == 0 );
        if ( !fSaved )
        {
          unlink( &acPathName );
          debug( "Cannot rename file %s to %s", &acPathName, &pSessCmd->acArg );
        }
      }

      if ( !fSaved )
        sessLog( pSess, 1, SESS_LOG_ERROR, "Cannot update the message header." );
    }
    else if ( ( ulAnswer == REQ_ANSWER_SPAM ) && ( pConfig->pszSpamStore != NULL )
           && ( pConfig->fSpamTrapStore || ( pSess->pszSpamTrap == NULL ) ) )
    {
      _sGetSpamStoreFileName( pSess, sizeof(acPathName), &acPathName );
      sessLog( pSess, 3, SESS_LOG_INFO, "The spam message was%s saved: %s",
               _sSaveAndClose( pSess, pFile, &acPathName )
                 ? "" : " NOT", &acPathName );
    }
    else
      mfClose( pFile );
  }

  if ( pSess->pszSpamTrap )
    _sessCmdAnswer( pSess, pSessCmd, ulAnswer, "spamtrap=%s",
                    pSess->pszSpamTrap );
  else
    _sessCmdAnswer( pSess, pSessCmd, ulAnswer, NULL );

  _sOnRSET( pSess );
  return TRUE;
}

static BOOL _scQUIT(PSESS pSess, PSESSCMD pSessCmd)
{
  sessLog( pSess, 5, SESS_LOG_INFO, "QUIT" );
  _sessCmdAnswer( pSess, pSessCmd, REQ_ANSWER_OK, NULL );
  return FALSE;
}


//           Session requests
//           ----------------

static VOID _sessCmdDestroy(PSESSCMD pSessCmd)
{
  if ( lnkseqIsLinked( pSessCmd ) )
  {
    debugCP( "We should not be here" );
  }

  debugFree( pSessCmd );
}

// static VOID _sessCmdPush(PFNREQCB pfnCallback, PVOID pUser, PSZ pszSessId,
//                          ULONG ulCommandNo, ULONG cbArg, PCHAR pcArg)
//
// Creates a new session command object, pushes it to the command sequence and
// and signal to thread.

static VOID _sessCmdPush(PFNREQCB pfnCallback, PVOID pUser, PSZ pszSessId,
                         ULONG ulCommandNo, ULONG cbArg, PCHAR pcArg)
{
  PSESSCMD             pSessCmd = debugMAlloc( sizeof(SESSCMD) + cbArg );

  pSessCmd->pfnCallback = pfnCallback;
  pSessCmd->pUser = pUser;
  pSessCmd->ulCommandNo = ulCommandNo;
  strlcpy( &pSessCmd->acSessId, pszSessId, sizeof(pSessCmd->acSessId) );

  if ( pcArg == NULL )
  {
    pSessCmd->cbArg = 0;
    pSessCmd->acArg[0] = '\0';
  }
  else
  {
    BUF_SKIP_SPACES( cbArg, pcArg );
    pSessCmd->cbArg = cbArg;
    memcpy( &pSessCmd->acArg, pcArg, cbArg );
    pSessCmd->acArg[cbArg] = '\0';
  }

  // Insert a new session command object at the sequence.
  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
  lnkseqAddFirst( &lsSessCmd, pSessCmd );
  xplMutexUnlock( hmtxSessCmd );

  // Inform thereads that we have a new session command.
  xplEventPost( hevSessCmd );
}

static VOID _sessCmdProcess(PSESSCMD pSessCmd, BOOL fExecute)
{
  static PFNCMD  afnCmd[] = { _scAtAccept, _scEHLO, _scRSET,
                              _scMAIL, _scRCPT, _scDATA, _scAtContent,
                              _scQUIT };
  PSESS      pSess = sessOpen( &pSessCmd->acSessId, pSessCmd->ulCommandNo );

  if ( pSess == NULL )
  {
    _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, REQ_ANSWER_ERROR,
                "Cannot open/create session" );
  }
  else if ( !fExecute )
  {
    _reqAnswer( pSessCmd->pfnCallback, pSessCmd->pUser, REQ_ANSWER_ERROR,
                "Shutdown" );
    sessClose( pSess );
  }
  else if ( (afnCmd[pSessCmd->ulCommandNo])( pSess, pSessCmd ) )
  {
    sessClose( pSess );
  }
  else
    sessDestroy( pSess );
}


//           Threads
//           -------

void threadReq(void *pData)
{
  PSESSCMD   pSessCmd;

  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
  debug( "Thread %u started", cThreads );
  cThreads++;
  xplMutexUnlock( hmtxSessCmd );

  do
  {
    if ( !cfgReadLock() )
    {
      debug( "cfgReadLock() failed" );
      break;
    }

    xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );

    // Increase the number of threads if need.
    if ( cThreads < pConfig->ulThreads )
      _beginthread( threadReq, NULL, THREAD_STACK_SIZE, NULL );

    // Too much threads - end thread.
    if ( cThreads > pConfig->ulThreads )
    {
      // Let other thread to process the request or exit.
      cfgReadUnlock();
      DosPostEventSem( hevSessCmd );
      goto l00;
    }

    // Get session command object from sequence.

    pSessCmd = (PSESSCMD)lnkseqGetFirst( &lsSessCmd );
    if ( pSessCmd == NULL )
    {
      // Have no session commands. Wait for semaphore.
      xplMutexUnlock( hmtxSessCmd );
    }
    else
    {
      // Extract session command object from the sequence.
      lnkseqRemove( &lsSessCmd, pSessCmd );
      xplMutexUnlock( hmtxSessCmd );
      // Process the session command and call user function.
      _sessCmdProcess( pSessCmd, TRUE );
      _sessCmdDestroy( pSessCmd );
    }

    cfgReadUnlock();
  }
  while( xplEventWait( hevSessCmd, XPL_INDEFINITE_WAIT ) == XPL_EV_SIGNAL );

  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
l00:
  cThreads--;
  debug( "Thread ended, left: %u", cThreads );
  xplMutexUnlock( hmtxSessCmd );
  _endthread();
}


//           Public routines
//           ---------------

BOOL reqInit()
{
  if ( hmtxSessCmd != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  lnkseqInit( &lsSessCmd );
  xplMutexCreate( &hmtxSessCmd, FALSE );
  xplEventCreate( &hevSessCmd, XPL_EV_AUTO_RESET, FALSE );

  if ( ( hmtxSessCmd != NULLHANDLE ) &&
       ( hevSessCmd != NULLHANDLE ) &&
       idfrInit( &idfreqClients, pConfig->ulIPFreqDuration,
                 pConfig->ulIPFreqMaxAtAcceptNum ) &&
       _dynipInit() &&
       addrlstInit( &stWhiteAddrList, 128 ) &&
       addrlstInit( &stSpamURIHostList, 256 ) &&
       glInit() &&
       dnsInit() &&
       sessInit( pConfig->ulCommandTimeout ) &&
       dnsSetServer( &pConfig->stNSAddr, pConfig->usNSPort ) &&
       ( xplThreadStart( threadReq, NULL ) != XPL_THREAD_START_FAIL ) )
  {
    addrlstLoad( &stWhiteAddrList, _WHITELIST_FILE );
    log( 5, "%u item(s) loaded from "_WHITELIST_FILE,
         addrlstGetCount( &stWhiteAddrList ) );

    addrlstLoad( &stSpamURIHostList, _SPAM_URL_HOSTLIST_FILE );
    log( 5, "%u item(s) loaded from "_SPAM_URL_HOSTLIST_FILE,
         addrlstGetCount( &stSpamURIHostList ) );

    return TRUE;
  }

  debug( "Initialization failed" );

  if ( hmtxSessCmd != NULLHANDLE )
  {
    xplMutexDestroy( hmtxSessCmd );
    hmtxSessCmd = NULLHANDLE;
  }

  if ( hevSessCmd != NULLHANDLE )
  {
    xplEventDestroy( hevSessCmd );
    hevSessCmd = NULLHANDLE;
  }

  idfrDone( &idfreqClients );
  _dynipDone();
  addrlstDone( &stWhiteAddrList );
  addrlstDone( &stSpamURIHostList );
  glDone();
  dnsDone();
  sessDone();
  return FALSE;
}

VOID reqDone()
{
  PSESSCMD   pSessCmd;

  if ( hmtxSessCmd == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
  pConfig->ulThreads = 0;
  dnsDone();

  if ( hevSessCmd != NULLHANDLE )
  {
    debug( "Wait threads..." );
    while( cThreads != 0 )
    {
      xplEventPost( hevSessCmd );
      xplMutexUnlock( hmtxSessCmd );
      if ( xplSleep( 1 ) != NO_ERROR )
      {
        debug( "Dirty shutdown" );
        break;
      }
      xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
    }
    debug( "End of waiting threads" );
    xplEventDestroy( hevSessCmd );
    hevSessCmd = NULLHANDLE;
  }

  while( ( pSessCmd = (PSESSCMD)lnkseqGetFirst( &lsSessCmd ) ) != NULL )
  {
    lnkseqRemove( &lsSessCmd, pSessCmd );

    // Call user function for request with result code "cancel".
    _sessCmdProcess( pSessCmd, FALSE );
  }

  if ( pConfig->ulIPFreqMaxAtAcceptNum != 0 )
  {
    idfrDone( &idfreqClients );
    bzero( &idfreqClients, sizeof(idfreqClients) );
  }
  _dynipDone();
  addrlstDone( &stWhiteAddrList );
  addrlstDone( &stSpamURIHostList );
  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
  glDone();
  sessDone();
  xplMutexUnlock( hmtxSessCmd );
  xplMutexDestroy( hmtxSessCmd );
  hmtxSessCmd = NULLHANDLE;
}

// BOOL reqNew(ULONG cbText, PCHAR pcText, PFNREQCB pfnCallback, PVOID pUser)
//

BOOL reqNew(ULONG cbText, PCHAR pcText, PFNREQCB pfnCallback, PVOID pUser)
{
  PCHAR      pcVal;
  ULONG      cbVal;
  LONG       lRequest;

  BUF_RTRIM( cbText, pcText );
  if ( cbText == 0 )
    return FALSE;

  // First word - request name.
  utilStrCutWord( &cbText, &pcText, &cbVal, &pcVal );
  lRequest = utilStrWordIndex( "SESSION SHUTDOWN RECONFIGURE DEBUGSTAT",
                               cbVal, pcVal );

  switch( lRequest )
  {
    case -1: // Unknown request
      _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR, "Unknown request" );
      break;

    case 0:  // SESSION
      {
        ULONG      cbSessId, cbCmd;
        PCHAR      pcSessId, pcCmd;
        LONG       lCmd;

        if ( !utilStrCutWord( &cbText, &pcText, &cbSessId, &pcSessId ) )
        {
          _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR, "No session ID" );
          break;
        }

        if ( !utilStrCutWord( &cbText, &pcText, &cbCmd, &pcCmd ) )
        {
          _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR, "No command" );
          break;
        }

        pcSessId[cbSessId] = '\0';

        lCmd = utilStrWordIndex( COMMAND_LIST, cbCmd, pcCmd );
        if ( lCmd == -1 )
          _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR, "Unknown command" );
        else
          _sessCmdPush( pfnCallback, pUser, pcSessId, lCmd, cbText, pcText );

        break;
      }

    case 1:  // SHUTDOWN
      log( 1, "The request SHUTDOWN received." );

    case 2:  // RECONFIGURE
      _reqAnswer( pfnCallback, pUser,
                  sqPost( lRequest == 1 ? SIG_SHUTDOWN : SIG_RECONFIGURE )
                    ? REQ_ANSWER_OK : REQ_ANSWER_ERROR,
                  NULL );
      break;

    case 3:  // DEBUGSTAT
#ifdef DEBUG_FILE
      _reqAnswer( pfnCallback, pUser, REQ_ANSWER_OK,
                  "Memory allocated: %u", debugMemUsed() );
      debugStat();
#else
      _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR,
                  "This is not a debug version" );
#endif
      break;

    default:
      _reqAnswer( pfnCallback, pUser, REQ_ANSWER_ERROR,
                  "Request is not released" );
  }

  return TRUE;
}

// VOID reqClean()
//
// Clean Up internal SpamFilter data, delete outdated entries from lists

VOID reqClean()
{
  // Expired IP-addresses of dynamic list cleaning.
  _dynipClean();
  // Expired sessions cleaning.
  sessClean();
  // Expired greylist records cleaning.
  glClean();
  // Expired white list records cleaning.
  addrlstClean( &stWhiteAddrList );
  // Expired hosts from spammers messages links cleaning.
  addrlstClean( &stSpamURIHostList );

  if ( pConfig->ulIPFreqMaxAtAcceptNum != 0 )
    idfrClean( &idfreqClients );
}

VOID reqStoreLists()
{
  if ( !addrlstSave( &stWhiteAddrList, _WHITELIST_FILE ) )
    log( 1, "[WARNING] Cannot store whitelist to the file %s", _WHITELIST_FILE );

  if ( !addrlstSave( &stSpamURIHostList, _SPAM_URL_HOSTLIST_FILE ) )
    log( 1, "[WARNING] Cannot store spam links hosts list to the file %s",
         _SPAM_URL_HOSTLIST_FILE );

  if ( !statSaveChanges() )
    log( 1, "[WARNING] Cannot store statistics" );

  if ( !glSave() )
    log( 1, "[WARNING] Cannot store greylist" );
}

ULONG reqGetCount()
{
  ULONG      ulCount;

  xplMutexLock( hmtxSessCmd, XPL_INDEFINITE_WAIT );
  ulCount = lnkseqGetCount( &lsSessCmd );
  xplMutexUnlock( hmtxSessCmd );
  return ulCount;
}

ULONG reqDynIPGetCount()
{
  ULONG      ulCount;

  xplMutexLock( hmtxDynIPList, XPL_INDEFINITE_WAIT );
  ulCount = cDynIPList;
  xplMutexUnlock( hmtxDynIPList );
  return ulCount;
}

VOID reqCloseSession(PSZ pszSessId)
{
  LONG       lIdx = utilStrWordIndex( COMMAND_LIST, 4, "QUIT" );

  if ( lIdx != -1 )
    _sessCmdPush( NULL, NULL, pszSessId, lIdx, 0, NULL );
  else
    debug( "Index of the command \"QUIT\" was not found." );
}

VOID reqReconfigured()
{
  if ( !cfgReadLock() )
  {
    debug( "cfgReadLock() failed" );
    return;
  }

  idfrSetLimit( &idfreqClients, pConfig->ulIPFreqDuration,
                pConfig->ulIPFreqMaxAtAcceptNum );
  sessSetCommandTimeout( pConfig->ulCommandTimeout );

  cfgReadUnlock();
}
