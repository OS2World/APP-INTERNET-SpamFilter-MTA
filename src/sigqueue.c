#include "debug.h"
#include "xpl.h"
#include "linkseq.h"
#include "sigqueue.h"

#define QUEUE_LENGTH   4

typedef struct _SIGTIMER {
  SEQOBJ               seqObj;

  ULONG                ulSignal;
  ULONG                ulTimeout;
  ULONG                ulExpire;
} SIGTIMER, *PSIGTIMER;

static HEV             hevSignal = NULLHANDLE;
static HMTX            hmtxQueue = NULLHANDLE;
static LINKSEQ         lsTimers;
static ULONG           aulQueue[QUEUE_LENGTH];
static ULONG           ulWPos = 0;
static ULONG           ulRPos = 0;
static ULONG           cQueue = 0;

BOOL sqInit()
{
  if ( hevSignal != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplEventCreate( &hevSignal, XPL_EV_AUTO_RESET, FALSE );
  if ( hevSignal == NULLHANDLE )
  {
    debug( "xplEventCreate() failed" );
    return FALSE;
  }

  xplMutexCreate( &hmtxQueue, FALSE );
  if ( hmtxQueue == NULLHANDLE )
  {
    debug( "xplMutexCreate() failed" );
    xplEventDestroy( hevSignal );
    hevSignal = NULLHANDLE;
    return FALSE;
  }

  lnkseqInit( &lsTimers );
  return TRUE;
}

VOID sqDone()
{
  if ( hevSignal == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  xplEventDestroy( hevSignal );
  hevSignal = NULLHANDLE;
  xplMutexDestroy( hmtxQueue );
  hmtxQueue = NULLHANDLE;

  lnkseqFree( &lsTimers, PSIGTIMER, debugFree );
}

BOOL sqSetTimer(ULONG ulSignal, ULONG ulTimeout)
{
  PSIGTIMER            pTimer;

  xplMutexLock( hmtxQueue, XPL_INDEFINITE_WAIT );

  for( pTimer = (PSIGTIMER)lnkseqGetFirst( &lsTimers );
       ( pTimer != NULL ) && ( pTimer->ulSignal != ulSignal );
       pTimer = (PSIGTIMER)lnkseqGetNext( pTimer ) );

  if ( pTimer == NULL )
  {
    pTimer = debugMAlloc( sizeof(SIGTIMER) );
    if ( pTimer == NULL )
    {
      debug( "Not enough memory" );
      xplMutexUnlock( hmtxQueue );
      return FALSE;
    }

    pTimer->ulSignal = ulSignal;
    lnkseqAdd( &lsTimers, pTimer );
  }

  pTimer->ulTimeout = ulTimeout;
  xplTime( &pTimer->ulExpire );
  pTimer->ulExpire += ulTimeout;
  xplMutexUnlock( hmtxQueue );
  return TRUE;
}

BOOL sqPost(ULONG ulSignal)
{
  if ( cQueue == QUEUE_LENGTH )
    return FALSE;

  xplMutexLock( hmtxQueue, XPL_INDEFINITE_WAIT );

  aulQueue[ulWPos] = ulSignal;
  ulWPos = (ulWPos + 1) % QUEUE_LENGTH;
  cQueue++;
  xplEventPost( hevSignal );

  xplMutexUnlock( hmtxQueue );

  return TRUE;
}

ULONG sqWait()
{
  ULONG                ulTime;
  PSIGTIMER            pTimer;
  ULONG                ulSignal = SIG_ERROR;

  // Check timers.

  while( TRUE )
  {
    xplTime( &ulTime );
    xplMutexLock( hmtxQueue, XPL_INDEFINITE_WAIT );

    for( pTimer = (PSIGTIMER)lnkseqGetFirst( &lsTimers ); pTimer != NULL;
         pTimer = (PSIGTIMER)lnkseqGetNext( pTimer ) )
    {
      if ( ( (ulTime - pTimer->ulExpire) & 0x80000000 ) == 0 )  // time >= expire
      {
        do {
          pTimer->ulExpire += pTimer->ulTimeout;
        } while( ( (ulTime - pTimer->ulExpire) & 0x80000000 ) == 0 );

        ulSignal = pTimer->ulSignal;
        break;
      }
    }

    // Check queue.

    if ( ( ulSignal == SIG_ERROR ) && ( cQueue != 0 ) )
    {
      ulSignal = aulQueue[ulRPos];
      ulRPos = (ulRPos + 1) % QUEUE_LENGTH;
      cQueue--;
    }

    xplMutexUnlock( hmtxQueue );

    if ( ulSignal != SIG_ERROR )
      break;

    xplEventWait( hevSignal, 100 );
  }

  return ulSignal;
}
