#include <string.h>
#include <stdarg.h>
#include "debug.h"
#include "sf.h"
#include "xpl.h"
#include "config.h"
#include "log.h"
#include "util.h"
#include "stat.h"
#include "sockets.h"
#define SESSIONS_C
#include "sessions.h"

static LINKSEQ         lsSessions;
static HMTX            hmtxSessions;
static ULONG           ulSessMaxOpenTimeInt;
static PSZ             apszTypes[] =
{
  "SPAM",              // 0 SESS_LOG_SPAM
  "NOT SPAM",          // 1 SESS_LOG_NOT_SPAM
  "INFO",              // 2 SESS_LOG_INFO
  "SCORE",             // 3 SESS_LOG_SCORE
  "WARINIG",           // 4 SESS_LOG_WARNING
  "DELAYED",           // 5 SESS_LOG_DELAYED
  "ERROR"              // 6 SESS_LOG_ERROR
};


static VOID _sessDestroy(PSESS pSess)
{
  if ( pSess->pszHostName != NULL )
    debugFree( pSess->pszHostName );

  if ( pSess->pszEHLO != NULL )
    debugFree( pSess->pszEHLO );

  if ( pSess->pszSender != NULL )
    debugFree( pSess->pszSender );

  sessClearRecepient( pSess );

  if ( pSess->pszSpamTrap != NULL )
    debugFree( pSess->pszSpamTrap );

  debugFree( pSess );
}

static PSESS _sessFind(PSZ pszId)
{
  PSESS      pSess;

  for( pSess = (PSESS)lnkseqGetFirst( &lsSessions ); pSess != NULL;
       pSess = (PSESS)lnkseqGetNext( pSess ) )
  {
    if ( stricmp( &pSess->acId, pszId ) == 0 )
      return pSess;
  }

  return NULL;
}

static VOID _sessLog(PSESS pSess, ULONG ulLevel, ULONG ulType, PSZ pszFormat,
                     va_list arglist)
{
  CHAR       acBuf[1024];
  PCHAR      pcBuf = &acBuf;

  pcBuf += sprintf( pcBuf, "Session %s [%s] ",
                    &pSess->acId, apszTypes[ulType] );

  if ( pszFormat != NULL )
  {
    acBuf[sizeof(acBuf) - 1] = '\0';
    vsnprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 1, pszFormat, arglist );
  }

  log( ulLevel, &acBuf );
}



BOOL sessInit(ULONG ulCommandTimeout)
{
  if ( hmtxSessions != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxSessions, FALSE );
  if ( hmtxSessions == NULLHANDLE )
    return FALSE;

  lnkseqInit( &lsSessions );
  ulSessMaxOpenTimeInt = ulCommandTimeout * 1000;
  debug( "Session max. open time interval [msec.]: %u", ulSessMaxOpenTimeInt );
  return TRUE;
}

VOID sessDone()
{
  if ( hmtxSessions == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  xplMutexDestroy( hmtxSessions );
  hmtxSessions = NULLHANDLE;
  lnkseqFree( &lsSessions, PSESS, _sessDestroy );
}

// VOID sessClean()
//
// Removes from list and destroys expired sessions.

VOID sessClean()
{
  ULONG                ulTime;
  PSESS                pSess, pNext;
  ULONG                ulCount = 0;

  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return;
  }

  // Clear sessions list.

  xplTime( &ulTime );
  for( pSess = (PSESS)lnkseqGetFirst( &lsSessions ); pSess != NULL; )
  {
    pNext = (PSESS)lnkseqGetNext( pSess );

    if ( lockFlag0( &pSess->ulFlags ) != 0 )
    {
      if ( ( (ulTime - pSess->ulExpire) & 0x80000000 ) == 0 )
      {
        log( 4, "[INFO] Session %s timed out.", &pSess->acId );
        lnkseqRemove( &lsSessions, pSess );
        _sessDestroy( pSess );
        ulCount++;
      }
      else
        clearFlag0( &pSess->ulFlags );
    }
    else if ( ( testFlag1( &pSess->ulFlags ) == 0 ) &&
              ( ulTime - pSess->ulOpenTime ) >= ulSessMaxOpenTimeInt )
    {
      socketCancel( pSess->ulTID );
      setFlag1( &pSess->ulFlags );
      log( 1, "[INFO] Session %s command execution timeout.", &pSess->acId );
      statChange( STAT_COMMAND_TIMEOUT, 1 );
    }

    pSess = pNext;
  }

  if ( ulCount != 0 )
    statChange( STAT_SESS_TIMEDOUT, ulCount );

  xplMutexUnlock( hmtxSessions );
}

PSESS sessOpen(PSZ pszId, ULONG ulCommandNo)
{
  PSESS      pSess;

  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return NULL;
  }

  pSess = _sessFind( pszId );
  if ( pSess != NULL )
  {
    if ( lockFlag0( &pSess->ulFlags ) == 0 )
    {
      debug( "Session %s already open and locked!", pszId );
      xplMutexUnlock( hmtxSessions );
      return NULL;
    }

//    debug( "Session %s already open - reuse", pszId );
  }
  else
  {
    // Allocate a new session record and insert it into the list.
    pSess = debugCAlloc( 1, sizeof(SESS) );
    if ( pSess == NULL )
    {
      debug( "Not enough memory" );
      xplMutexUnlock( hmtxSessions );
      return NULL;
    }

    strlcpy( &pSess->acId, pszId, sizeof(pSess->acId) );
    pSess->ulSPFLevel = ~0;

    lnkseqAdd( &lsSessions, pSess );
  }

  pSess->ulCommandNo = ulCommandNo;
  pSess->ulExpire = 0;
  xplThreadId( &pSess->ulTID );
  xplTime( &pSess->ulOpenTime );
  setFlag0( &pSess->ulFlags );
  clearFlag1( &pSess->ulFlags );

  xplMutexUnlock( hmtxSessions );

  return pSess;
}

BOOL sessDestroy(PSESS pSess)
{
  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return FALSE;
  }

  if ( lockFlag0( &pSess->ulFlags ) != 0 )
  {
    debug( "Session %s was not locked!", &pSess->acId );
    clearFlag0( &pSess->ulFlags );
    xplMutexUnlock( hmtxSessions );
    return FALSE;
  }

  lnkseqRemove( &lsSessions, pSess );
  _sessDestroy( pSess );
  xplMutexUnlock( hmtxSessions );

  return TRUE;
}

BOOL sessClose(PSESS pSess)
{
  ULONG      ulTime;

  if ( lockFlag0( &pSess->ulFlags ) != 0 )
  {
    debug( "Session %s was not locked", &pSess->acId );
    clearFlag0( &pSess->ulFlags );
    return FALSE;
  }

  if ( testFlag1( &pSess->ulFlags ) != 0 )
  {
    lnkseqRemove( &lsSessions, pSess );
    _sessDestroy( pSess );
    debug( "Command execution timeout, session destroyed." );
    return TRUE;
  }

  xplTime( &ulTime );
  pSess->ulExpire = ulTime +
                    ( pConfig->aCmdParam[pSess->ulCommandNo].ulTTL * 1000 );

  clearFlag0( &pSess->ulFlags );
  return TRUE;
}

VOID sessLog(PSESS pSess, ULONG ulLevel, ULONG ulType, PSZ pszFormat, ...)
{
  va_list  arglist;

  va_start( arglist, pszFormat );
  _sessLog( pSess, ulLevel, ulType, pszFormat, arglist );
  va_end( arglist );
}

VOID sessAddRecepient(PSESS pSess, ULONG cbAddr, PCHAR pcAddr)
{
  PSZ        pszAddr = utilStrNewSZ( cbAddr, pcAddr );

  if ( pszAddr == NULL )
  {
    debug( "Not enough memory" );
    return;
  }

  // Expand array for every 16 records.
  if ( (pSess->cRcpt & 0x0F) == 0 )
  {
    PSZ      *ppszNew = debugReAlloc( pSess->ppszRcpt,
                                      sizeof(PSZ) * (pSess->cRcpt + 0x10) );
    if ( ppszNew == NULL )
    {
      debugFree( pszAddr );
      debug( "Not enough memory" );
      return;
    }
    pSess->ppszRcpt = ppszNew;
  }
  // Add a new address to the end of the array.
  pSess->ppszRcpt[pSess->cRcpt] = pszAddr;
  pSess->cRcpt++;
}

VOID sessClearRecepient(PSESS pSess)
{
  ULONG      ulIdx;

  if ( pSess->ppszRcpt != NULL )
  {
    for( ulIdx = 0; ulIdx < pSess->cRcpt; ulIdx++ )
    {
      if ( pSess->ppszRcpt[ulIdx] != NULL )
        debugFree( pSess->ppszRcpt[ulIdx] );
    }

    debugFree( pSess->ppszRcpt );
    pSess->ppszRcpt = NULL;
  }
  pSess->cRcpt = 0;
}

// BOOL sessAddScore(PSESS pSess, LONG lScore, PSZ pszFormat, ...)
//
// Returns TRUE when score reached the limit, lScore is SF_SCORE_NOT_SPAM
// or SF_SCORE_SPAM. If result is TRUE - session have "final" answer.

BOOL sessAddScore(PSESS pSess, LONG lScore, PSZ pszFormat, ...)
{
  va_list    arglist;

  if ( lScore == SF_SCORE_NONE )
    return FALSE;

  va_start( arglist, pszFormat );

  if ( lScore == SF_SCORE_NOT_SPAM )
  {
    pSess->lScore = SF_SCORE_NOT_SPAM;
    _sessLog( pSess, 2, SESS_LOG_NOT_SPAM, pszFormat, arglist );
  }
  else if ( lScore == SF_SCORE_SPAM )
  {
    pSess->lScore = SF_SCORE_SPAM;
    _sessLog( pSess, 2, SESS_LOG_SPAM, pszFormat, arglist );
  }
  else if ( pSess->lScore != SF_SCORE_NOT_SPAM )
  {
    CHAR       acBuf[256];
    LONG       cbBuf;
    BOOL       fSpam;
    LONG       lLimit = pConfig->aCmdParam[pSess->ulCommandNo].lScoreLimit;

    pSess->lScore += lScore;
    fSpam = ( pSess->lScore >= lLimit );

    cbBuf = sprintf( &acBuf,
                     "The new session score %d (%+d) %s the limit (%d). ",
                     pSess->lScore, lScore, ( fSpam ? "reached" : "is below" ),
                     lLimit );
    if ( pszFormat != NULL )
      strlcpy( &acBuf[cbBuf], pszFormat, sizeof(acBuf) - cbBuf ); 
    _sessLog( pSess, fSpam ? 1 : 2, fSpam ? SESS_LOG_SPAM : SESS_LOG_SCORE,
              &acBuf, arglist );

    if ( fSpam )
      pSess->lScore = SF_SCORE_SPAM;
  }

  va_end( arglist );

  return ( pSess->lScore == SF_SCORE_NOT_SPAM ) ||
         ( pSess->lScore == SF_SCORE_SPAM );
}

// BOOL sessClientListed(PSESS pSess, PLINKSEQ plsHostList)
//
// Returns TRUE if client's address (IP/host name) listed in plsHostList.
// plsHostList is an object of configuration.

BOOL sessClientListed(PSESS pSess, PLINKSEQ plsHostList)
{
  if ( pSess->pszHostName == NULL )
    return cfgHostListCheckIP( plsHostList, pSess->stInAddr,
                               NULL );

  return cfgHostListCheck( plsHostList, pSess->stInAddr,
                           strlen( pSess->pszHostName ), pSess->pszHostName,
                           NULL );
}

ULONG sessCount()
{
  ULONG      ulCount;

  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return 0;
  }

  ulCount = lnkseqGetCount( &lsSessions );
  xplMutexUnlock( hmtxSessions );

  return ulCount;
}

// ULONG sessIPCount(struct in_addr stInAddr)
//
// Returns number of sessions with given client IP-address.

ULONG sessIPCount(struct in_addr stInAddr)
{
  PSESS      pSess;
  ULONG      ulCount = 0;

  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return 0;
  }

  for( pSess = (PSESS)lnkseqGetFirst( &lsSessions ); pSess != NULL;
       pSess = (PSESS)lnkseqGetNext( pSess ) )
  {
    if ( stInAddr.s_addr == pSess->stInAddr.s_addr )
      ulCount++;
  }

  xplMutexUnlock( hmtxSessions );

  return ulCount;
}

VOID sessSetCommandTimeout(ULONG ulCommandTimeout)
{
  if ( xplMutexLock( hmtxSessions, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return;
  }
 
  ulSessMaxOpenTimeInt = ulCommandTimeout * 1000;
  debug( "Session new max. open time interval: %u", ulSessMaxOpenTimeInt );
  xplMutexUnlock( hmtxSessions );
}
