#include "rwmutex.h"

BOOL rwmtxInit(PRWMTX pRWMtx)
{
  xplMutexCreate( &pRWMtx->hmtxRWLock, FALSE );
  if ( pRWMtx->hmtxRWLock == NULLHANDLE )
    return FALSE;

  xplEventCreate( &pRWMtx->hevWriteAllow, XPL_EV_AUTO_RESET, FALSE );
  if ( pRWMtx->hevWriteAllow == NULLHANDLE )
  {
    xplMutexDestroy( pRWMtx->hmtxRWLock );
    return FALSE;
  }

  return TRUE;
}

VOID rwmtxDone(PRWMTX pRWMtx)
{
  xplMutexDestroy( pRWMtx->hmtxRWLock );
  xplEventDestroy( pRWMtx->hevWriteAllow );
}

BOOL rwmtxLockRead(PRWMTX pRWMtx)
{
  if ( xplMutexLock( pRWMtx->hmtxRWLock, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
    return FALSE;
  pRWMtx->ulReadLock++;
  xplMutexUnlock( pRWMtx->hmtxRWLock );
  return TRUE;
}

VOID rwmtxUnlockRead(PRWMTX pRWMtx)
{
  xplMutexLock( pRWMtx->hmtxRWLock, XPL_INDEFINITE_WAIT );
  pRWMtx->ulReadLock--;
  if ( ( pRWMtx->ulReadLock == 0 ) && ( pRWMtx->ulWriteWait != 0 ) )
    xplEventPost( pRWMtx->hevWriteAllow );
  xplMutexUnlock( pRWMtx->hmtxRWLock );
}

BOOL rwmtxLockWrite(PRWMTX pRWMtx)
{
  if ( xplMutexLock( pRWMtx->hmtxRWLock, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
    return FALSE;

  if ( pRWMtx->ulReadLock != 0 )
  {
    pRWMtx->ulWriteWait++;
    while( pRWMtx->ulReadLock != 0 )
    {
      xplMutexUnlock( pRWMtx->hmtxRWLock );
      xplEventWait( pRWMtx->hevWriteAllow, XPL_INDEFINITE_WAIT );
      if ( xplMutexLock( pRWMtx->hmtxRWLock, XPL_INDEFINITE_WAIT )
           != XPL_NO_ERROR )
        return FALSE;
    }
    pRWMtx->ulWriteWait--;
  }

  return TRUE;
}

VOID rwmtxUnlockWrite(PRWMTX pRWMtx)
{
  xplMutexUnlock( pRWMtx->hmtxRWLock );
}
