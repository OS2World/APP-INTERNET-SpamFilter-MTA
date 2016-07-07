#include "debug.h"
#include "xpl.h"

#define _MAX_SOCKETS   64

typedef struct _SOCKET {
  int        aiSocket;
  ULONG      ulTID;
} SOCKET, *PSOCKET;

static SOCKET          aSockets[_MAX_SOCKETS];
static ULONG           cSockets = 0;
static HMTX            hmtxSockets = NULLHANDLE;

BOOL socketInit()
{
  if ( hmtxSockets != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxSockets, FALSE );
  if ( hmtxSockets == NULLHANDLE )
    return FALSE;

  return TRUE;
}

VOID socketDone()
{
  HMTX       hmtxSocketsSave = hmtxSockets;

  if ( hmtxSockets == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  hmtxSockets = NULLHANDLE;
  xplMutexLock( hmtxSocketsSave, XPL_INDEFINITE_WAIT );

  while( cSockets > 0 )
  {
    cSockets--;
    xplSockClose( aSockets[cSockets].aiSocket );
  }

  xplMutexDestroy( hmtxSocketsSave );
}

// int socketNew(BOOL fTCP)
//
// Creates and returns a new socket. fTCP: TRUE for TCP or FALSE for UDP.
// The return value -1 indicates an error.

int socketNew(BOOL fTCP)
{
  int        iSock;
  int        iType, iProtocol;

  if ( xplMutexLock( hmtxSockets, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return -1;
  }

  if ( fTCP )
  {
    iType = SOCK_STREAM;
    iProtocol = IPPROTO_TCP;
  }
  else
  {
    iType = SOCK_DGRAM;
    iProtocol = IPPROTO_UDP;
  }

  iSock = socket( PF_INET, iType, iProtocol );
/*  debug( "socket(PF_INET,%s,%s): %d",
         iType == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM",
         iProtocol == IPPROTO_TCP ? "IPPROTO_TCP" : "IPPROTO_UDP", iSock );*/
  if ( iSock == -1 )
  {
    debug( "Cannot create socket, error: %d", sock_errno() );
  }
  else if ( cSockets == _MAX_SOCKETS )
  {
    debug( "Too many sockets" );
  }
  else
  {
    aSockets[cSockets].aiSocket = iSock;
    xplThreadId( &aSockets[cSockets].ulTID );
    cSockets++;
    debugInc( "sockets" );
  }

  xplMutexUnlock( hmtxSockets );
  return iSock;
}

VOID socketDestroy(int iSock)
{
  ULONG      ulIdx = 0;

  if ( xplMutexLock( hmtxSockets, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return;
  }

  while( ulIdx < cSockets )
  {
    if ( aSockets[ulIdx].aiSocket == iSock )
    {
      cSockets--;
      aSockets[ulIdx] = aSockets[cSockets];
#ifdef DEBUG_FILE
      debugDec( "sockets" );
//      ulIdx = ~0;
#endif
      break;
    }
    ulIdx++;
  }

  xplMutexUnlock( hmtxSockets );
  xplSockClose( iSock );

/*#ifdef DEBUG_FILE
  if ( ulIdx != ~0 )
    debug( "Socket %d not found", iSock );
#endif*/
}

VOID socketCancel(ULONG ulTID)
{
  LONG       lIdx;

  if ( xplMutexLock( hmtxSockets, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "xplMutexLock() failed" );
    return;
  }

  for( lIdx = cSockets - 1; lIdx >= 0; lIdx-- )
  {
    if ( aSockets[lIdx].ulTID == ulTID )
    {
      cSockets--;
      aSockets[lIdx] = aSockets[cSockets];
    }
  }

  xplMutexUnlock( hmtxSockets );
}
