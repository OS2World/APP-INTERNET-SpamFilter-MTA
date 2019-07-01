#define INCL_DOSSEMAPHORES
#define INCL_DOSDATETIME
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#include <os2.h>
#include "events.h"
#include "log.h"
#include "debug.h"

#define _SEM_NUMBER    6

typedef struct _EVITEM {
  PSZ        pszName;                      // Event semaphore name.
  ULONG      ulInterval;                   // Auto-post interval.
  HEV        hEv;                          // Event semaphore handle.
  HTIMER     hTimer;                       // Timer handle, if ulInterval != 0.
} EVITEM, *PEVITEM;

static EVITEM   aEvList[_SEM_NUMBER] =
{
  // 0 - EV_SHUTDOWN
  { "\\SEM32\\SpamFilter\\shutdown",       // Event semaphore name.
    0,                                     // Auto-post interval.
    NULLHANDLE, NULLHANDLE },              // Will be filled by evInit().

  // 1 - EV_RECONFIGURE
  { "\\SEM32\\SpamFilter\\reconfigure",
    0,
    NULLHANDLE, NULLHANDLE },

  // 2 - EV_CLEANING
  { NULL,
    1000 * 5,
    NULLHANDLE, NULLHANDLE },

  // 3 - EV_LISTS_STORE
  { NULL,
    1000 * 60 * 2,
    NULLHANDLE, NULLHANDLE },

  // 4 - EV_PIPE
  { NULL,
    0,
    NULLHANDLE, NULLHANDLE },

  // 5 - EV_POSTPONDED_BACKUP
  { NULL,
    1000 * 2,
    NULLHANDLE, NULLHANDLE }
};

static HMUX  hMuxSem = NULLHANDLE;


static VOID _closeAllEvents()
{
  ULONG      ulRC;
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < _SEM_NUMBER; ulIdx++ )
  {
    if ( aEvList[ulIdx].hTimer != NULLHANDLE )
    { 
      ulRC = DosStopTimer( aEvList[ulIdx].hTimer );
      if ( ulRC != NO_ERROR )
        debug( "#%lu DosStopTimer(), rc = %lu", ulIdx, ulRC );
      aEvList[ulIdx].hTimer = NULLHANDLE;
    }

    if ( aEvList[ulIdx].hEv != NULLHANDLE )
    {
      ulRC = DosCloseEventSem( aEvList[ulIdx].hEv );
      if ( ulRC != NO_ERROR )
        debug( "#%lu DosCloseEventSem(), rc = %lu", ulIdx, ulRC );
      aEvList[ulIdx].hEv = NULLHANDLE;
    }
  }
}


BOOL evInit()
{
  ULONG      ulRC;
  SEMRECORD  aSemRec[_SEM_NUMBER];
  ULONG      ulIdx;

  if ( hMuxSem != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  for( ulIdx = 0; ulIdx < _SEM_NUMBER; ulIdx++ )
  {
    ulRC = DosCreateEventSem( aEvList[ulIdx].pszName, &aEvList[ulIdx].hEv,
                              DC_SEM_SHARED, FALSE );
    if ( ulRC == ERROR_DUPLICATE_NAME )
    {
      /* Named semaphore already exists. It seems, SpamFilter already running.
         Try to create not named semaphore. */

      debug( "#%lu Semaphore %s already exists, try to create not named",
             ulIdx, aEvList[ulIdx].pszName );
      ulRC = DosCreateEventSem( NULL, &aEvList[ulIdx].hEv, 0, FALSE );
    }

    if ( ulRC != NO_ERROR )
    {
      debug( "#%lu DosCreateEventSem(), rc = %lu", ulIdx, ulRC );
      break;
    }

    if ( aEvList[ulIdx].ulInterval != 0 )
    { 
      ulRC = DosStartTimer( aEvList[ulIdx].ulInterval, (HSEM)aEvList[ulIdx].hEv,
                            &aEvList[ulIdx].hTimer );
      if ( ulRC != NO_ERROR )
      {
        debug( "#%lu DosStartTimer(), rc = %lu", ulIdx, ulRC );
        break;
      }
    }

    aSemRec[ulIdx].hsemCur = (HSEM)aEvList[ulIdx].hEv;
    aSemRec[ulIdx].ulUser = ulIdx;
  }

  if ( ulRC != NO_ERROR )
  {
    _closeAllEvents();
    return FALSE;
  }

  ulRC = DosCreateMuxWaitSem( NULL, &hMuxSem, _SEM_NUMBER, aSemRec,
                              DCMW_WAIT_ANY );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMuxWaitSem(), rc = %lu", ulRC );
    _closeAllEvents();
    return FALSE;
  }

  return TRUE;
}

VOID evDone()
{
  ULONG      ulRC;

  if ( hMuxSem == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  _closeAllEvents();

  ulRC = DosCloseMuxWaitSem( hMuxSem );
  if ( ulRC != NO_ERROR )
    debug( "DosCloseMuxWaitSem(), rc = %lu", ulRC );

  hMuxSem = NULLHANDLE;
}

BOOL evPost(ULONG ulEvent)
{
  ULONG      ulRC;

  if ( aEvList[ulEvent].hEv == NULLHANDLE )
    return FALSE;

  ulRC = DosPostEventSem( aEvList[ulEvent].hEv );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosPostEventSem(), rc = %lu", ulRC );
    return FALSE;
  }

  return TRUE;
}

ULONG evWait(ULONG ulTimeout)
{
  ULONG      ulEvent;
  ULONG      ulRC;
  ULONG      ulPostCount;

  ulRC = DosWaitMuxWaitSem( hMuxSem, ulTimeout, &ulEvent );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
    {
      debug( "DosWaitMuxWaitSem(), rc = %lu", ulRC );
      return EV_ERROR;
    }

    return EV_NO_EVENT;
  }

  ulRC = DosResetEventSem( aEvList[ulEvent].hEv, &ulPostCount );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosResetEventSem(), rc = %lu", ulRC );
    return EV_ERROR;
  }

  return ulEvent;
}

HEV evGetEvSemHandle(ULONG ulEvent)
{
  return aEvList[ulEvent].hEv;
}
