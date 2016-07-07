#include <string.h>
#include "debug.h"
#include "util.h"
#include "idfreq.h"

typedef struct _IDREC {
  ULONG      ulId;
  ULONG      ulValue;
} IDREC, *PIDREC;


static int cbComp(const void *pkey, const void *pbase)
{
  register ULONG       ulListId = *(PULONG)pbase;

  if ( (ULONG)pkey < ulListId )
    return -1;

  if ( (ULONG)pkey > ulListId )
    return 1;

  return 0;
}


// BOOL idfrInit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit)
//
// Initializes user structure pointed by pIDFreq. It sets a limit in up to
// ulActivLimit events per ulTimeWindow seconds.

BOOL idfrInit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit)
{
  ulTimeWindow *= 1000;
  if ( ulActivLimit > ulTimeWindow )
    return FALSE;

  xplMutexCreate( &pIDFreq->hmtxList, FALSE );
  if ( pIDFreq->hmtxList == NULLHANDLE )
    return FALSE;

  pIDFreq->ulTimeWindow = ulTimeWindow;
  pIDFreq->ulActivLimit = ulActivLimit;
  pIDFreq->paList = NULL;
  pIDFreq->cList = 0;
  pIDFreq->ulListMax = 0;
  return TRUE;
}

// VOID idfrDone(PIDFREQ pIDFreq)
//
// Destroy data in the user structure pointed by pIDFreq. Free any allocated
// memory.

VOID idfrDone(PIDFREQ pIDFreq)
{
  if ( pIDFreq->hmtxList != NULLHANDLE )
  {
    xplMutexDestroy( pIDFreq->hmtxList );
    pIDFreq->hmtxList = NULLHANDLE;
  }

  if ( pIDFreq->paList != NULL )
  {
    debugFree( pIDFreq->paList );
    pIDFreq->paList = NULL;
  }
}

// BOOL idfrActivation(PIDFREQ pIDFreq, ULONG ulId, BOOL fRemoveOnLimit)
//
// Registers event for the object ulId. Returns TRUE if the number of events
// (ulActivLimit) per the time interval (ulTimeWindow) is reached limit.

BOOL idfrActivation(PIDFREQ pIDFreq, ULONG ulId, BOOL fRemoveOnLimit)
{
  ULONG      ulIndex;
  BOOL       fFound;
  PIDREC     pIdRec;
  ULONG      ulActivTimeWeight;
  ULONG      ulTime;

  if ( xplMutexLock( pIDFreq->hmtxList, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return FALSE;
  }

  if ( ( pIDFreq->ulTimeWindow == 0 ) || ( pIDFreq->ulActivLimit == 0 ) )
  {
    fFound = FALSE;
  }
  else
  {
    fFound = utilBSearch( (PVOID)ulId, pIDFreq->paList, pIDFreq->cList,
                         sizeof(IDFREQ), cbComp, &ulIndex );
    xplTime( &ulTime );
    ulActivTimeWeight = pIDFreq->ulTimeWindow / pIDFreq->ulActivLimit;

    if ( !fFound )
    {
      PIDREC   paList;

      if ( pIDFreq->cList == pIDFreq->ulListMax )
      {
        // Expand list.
        paList = debugReAlloc( pIDFreq->paList,
                               (pIDFreq->ulListMax + 128) * sizeof(IDREC) );

        if ( paList == NULL )
        {
          debug( "Not enough memory" );
          xplMutexUnlock( pIDFreq->hmtxList );
          return FALSE;
        }
        pIDFreq->paList = paList;
        pIDFreq->ulListMax += 128;
      }
      else
        paList = pIDFreq->paList;

      // Insert the new record at position ulIndex to keep order.
      memmove( &paList[ulIndex + 1], &paList[ulIndex],
               (pIDFreq->cList - ulIndex) * sizeof(IDREC) );
      pIDFreq->cList++;
      pIdRec = &pIDFreq->paList[ulIndex];
      pIdRec->ulId = ulId;
      pIdRec->ulValue = ulTime + ulActivTimeWeight;
    }
    else // if ( !fFound )
    {
      pIdRec = &pIDFreq->paList[ulIndex];

      if ( pIdRec->ulValue < ulTime )
      {
        pIdRec->ulValue = ulTime + ulActivTimeWeight;
        debug( "Record is expired. Does idfrClean() called frequently enough? "
               "(this is not an error)" );
      }
      else
      {
        ulActivTimeWeight += pIdRec->ulValue;

        // fFound is TRUE when activations limit reached.
        fFound = ulActivTimeWeight > (ulTime + pIDFreq->ulTimeWindow);
        if ( fFound && fRemoveOnLimit )
        {
          pIDFreq->cList--;
          memcpy( &pIDFreq->paList[ulIndex], &pIDFreq->paList[ulIndex + 1],
                  (pIDFreq->cList - ulIndex) * sizeof(IDREC) );
        }
        else
          pIdRec->ulValue = ulActivTimeWeight;
      }
    } // if ( !fFound ) else
  } // if ( pIDFreq->ulTimeWindow == 0 ) else

  xplMutexUnlock( pIDFreq->hmtxList );

  return fFound;
}

// VOID idfrClean(PIDFREQ pIDFreq)
//
// Rmoves from the list all expired records (objects registered by
// idfrActivation()). This function should be called with sufficient frequency.

VOID idfrClean(PIDFREQ pIDFreq)
{
  LONG      lIdx;
  ULONG     ulTime;

  if ( pIDFreq->hmtxList == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  xplTime( &ulTime );

  if ( xplMutexLock( pIDFreq->hmtxList, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return;
  }

  for( lIdx = pIDFreq->cList - 1; lIdx >= 0; lIdx-- )
  {
    if ( pIDFreq->paList[lIdx].ulValue < ulTime )
    {
      pIDFreq->cList--;
      memcpy( &pIDFreq->paList[lIdx], &pIDFreq->paList[lIdx + 1],
              (pIDFreq->cList - lIdx) * sizeof(IDREC) );
    }
  }

  xplMutexUnlock( pIDFreq->hmtxList );
}

// VOID idfrSetLimit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit)
//
// Sets a new events limit for objects in pIDFreq.

BOOL idfrSetLimit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit)
{
  ulTimeWindow *= 1000;
  if ( ulActivLimit > ulTimeWindow )
    return FALSE;

  if ( xplMutexLock( pIDFreq->hmtxList, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return FALSE;
  }

  pIDFreq->ulTimeWindow = ulTimeWindow;
  pIDFreq->ulActivLimit = ulActivLimit;

  xplMutexUnlock( pIDFreq->hmtxList );

  return TRUE;
}

