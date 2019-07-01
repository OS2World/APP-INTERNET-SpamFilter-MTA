#include <string.h>
#include "log.h"
#include "requests.h"
#include "linkseq.h"
#include "ifsock.h"
#include "hmem.h"
#include "debug.h"     // Must be the last.

#define THREAD_STACK_SIZE        65535

#define _CLNTFL_CLOSE            0x01

typedef struct _CLIENT {
  SEQOBJ               seqObj;

  HSOCKET              hSocket;
  ULONG                ulReqMax;
  ULONG                cbRequest;
  PCHAR                pcRequest;
  ULONG                ulFlags;
} CLIENT, *PCLIENT;

static HSOCKET         hSocket = -1;
static TID             tid = ((TID)(-1));
static LINKSEQ         lsClients;
static HMTX            hmtxClients = NULLHANDLE;


static VOID _closeClient(PCLIENT pClient)
{
  int        iVal = 0;

  xplSockIOCtl( hSocket, FIONBIO, &iVal );
  shutdown( pClient->hSocket, 2 );
  xplSockClose( pClient->hSocket );
  if ( pClient->pcRequest != NULL )
    hfree( pClient->pcRequest );

  hfree( pClient );
  debugDec( "ifsock_clients" );
}


static VOID fnAnswer(PVOID pUser, ULONG cbAnswer, PCHAR pcAnswer)
{
  PCLIENT    pClient;
  int        iRC;

  xplMutexLock( hmtxClients, XPL_INDEFINITE_WAIT );

  pClient = (PCLIENT)lnkseqGetFirst( &lsClients );
  for( pClient = (PCLIENT)lnkseqGetFirst( &lsClients );
       ( pClient != NULL ) && ( pClient->hSocket != (HSOCKET)pUser );
       pClient = (PCLIENT)lnkseqGetNext( pClient ) );

  if ( pClient != NULL )
  {
    iRC = send( (HSOCKET)pUser, pcAnswer, cbAnswer, 0 );
    if ( iRC == -1 )
    {
      debug( "send(), error %d", xplSockError() );
    }
    pClient->ulFlags = iRC == -1 ? _CLNTFL_CLOSE : 0;
  }

  xplMutexUnlock( hmtxClients );
}

void threadSockets(void *pData)
{
  fd_set               fdsRead, fdsWrite;
  struct timeval       stTimeVal;
  HSOCKET              hSockMax;
  int                  iRC = 0;
  PCLIENT              pClient, pNextClient;
  PCHAR                pcEOL, pcEnd, pcLine;

  if ( xplMutexLock( hmtxClients, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return;
  }

  while( TRUE )
  {
    FD_ZERO( &fdsRead );
    FD_ZERO( &fdsWrite );

    // Add to the lists the listening socket.
    FD_SET( hSocket, &fdsRead );
    FD_SET( hSocket, &fdsWrite );
    hSockMax = hSocket;

    // Add to the lists client's sockets.
    // Close the session that should be closed.

    pClient = (PCLIENT)lnkseqGetFirst( &lsClients );
    while( pClient != NULL )
    {
      pNextClient = (PCLIENT)lnkseqGetNext( pClient );

      if ( pClient->ulFlags == _CLNTFL_CLOSE )
      {
        lnkseqRemove( &lsClients, pClient );
        _closeClient( pClient );
      }
      else if ( pClient->ulFlags == 0 )
      {
        FD_SET( pClient->hSocket, &fdsRead );
        if ( pClient->hSocket > hSockMax )
          hSockMax = pClient->hSocket;
      }

      pClient = pNextClient;
    }

    // Unlock mutex while we sleep in select().
    xplMutexUnlock( hmtxClients );

    // Wait for the events on sockets.

    stTimeVal.tv_sec  = 0;
    stTimeVal.tv_usec = 50000;

    iRC = select( hSockMax + 1, &fdsRead, &fdsWrite, NULL, &stTimeVal );
    if ( iRC < 0 )
    {
      if ( hmtxClients != NULLHANDLE ) // Socked was destroyed in ifsockDone().
      {
        debug( "select(), error %d", xplSockError() );
      }
      break;
    }

    if ( xplMutexLock( hmtxClients, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
    {
      debug( "Mutex lock failed" );
      break;
    }

    if ( iRC == 0 )
      continue;

    // Receive the data from clients.

    for( pClient = (PCLIENT)lnkseqGetFirst( &lsClients ); pClient != NULL;
         pClient = (PCLIENT)lnkseqGetNext( pClient ) )
    {
      if ( ( pClient->ulFlags != 0 ) || !FD_ISSET(pClient->hSocket, &fdsRead) )
        continue;

      if ( pClient->cbRequest == pClient->ulReqMax )
      {
        PCHAR          pcNewBuf = hrealloc( pClient->pcRequest,
                                                pClient->ulReqMax + 128 );
        if ( pcNewBuf == NULL )
        {
          pClient->ulFlags = _CLNTFL_CLOSE;
          continue;
        }

        pClient->pcRequest = pcNewBuf;
        pClient->ulReqMax += 128;
      }

      iRC = recv( pClient->hSocket, &pClient->pcRequest[pClient->cbRequest],
                  pClient->ulReqMax - pClient->cbRequest, 0 );
      if ( iRC <= 0 )
      {
        pClient->ulFlags = _CLNTFL_CLOSE;
        continue;
      }
      pClient->cbRequest += iRC;

      // Get all buffered lines ended with LF and make new requests.
      pcEnd = &pClient->pcRequest[pClient->cbRequest];
      pcLine = pClient->pcRequest;
      while( pClient->ulFlags != _CLNTFL_CLOSE )
      {
        pClient->cbRequest = pcEnd - pcLine;
        pcEOL = memchr( pcLine, '\n', pClient->cbRequest );
        if ( pcEOL == NULL )
        {
          // No left LFs at the buffer. Move remaining characters in the
          // beginning of the buffer.
          memcpy( pClient->pcRequest, pcLine, pClient->cbRequest );
          break;
        }
        pcEOL++;

        if ( !reqNew( pcEOL - pcLine, pcLine, fnAnswer,
                      (PVOID)pClient->hSocket ) )
          pClient->ulFlags = _CLNTFL_CLOSE;

        pcLine = pcEOL;
      }
    }

    if ( FD_ISSET(hSocket, &fdsRead) || FD_ISSET(hSocket, &fdsWrite) )
    {
      // New client connected.

      struct sockaddr_in         sClientSockAddr;
      int                        cbSockAddr = sizeof(struct sockaddr_in);
      HSOCKET                    hClientSocket;
      int                        iVal = 1;

      hClientSocket = accept( hSocket, (struct sockaddr *)&sClientSockAddr,
                              &cbSockAddr );
      if ( hClientSocket == -1 )
      {    
        debug( "accept(), error %d", xplSockError() );
        xplMutexUnlock( hmtxClients );
        continue;
      }

      pClient = hcalloc( 1, sizeof(CLIENT) );
      if ( pClient == NULL )
      {
        debug( "Not enough memory" );
        xplSockClose( hClientSocket );
        continue;
      }
      
      debugInc( "ifsock_clients" );
      xplSockIOCtl( hClientSocket, FIONBIO, &iVal );
      pClient->hSocket = hClientSocket;
      lnkseqAdd( &lsClients, pClient );
    }

  }

  if ( iRC >= 0 )
    xplMutexUnlock( hmtxClients );

  tid = ((TID)(-1));
  _endthread();
}


BOOL ifsockInit()
{
  struct sockaddr_un   stUn;
  int                  iVal = 1;
  PSZ                  pszSocket;

  if ( hmtxClients != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxClients, FALSE );
  if ( hmtxClients == NULLHANDLE )
  {
    debug( "xplMutexCreate() failed" );
    return FALSE;
  }

  lnkseqInit( &lsClients );

  hSocket = socket( PF_UNIX, SOCK_STREAM, 0 );

  stUn.sun_len = sizeof(stUn);
  stUn.sun_family = AF_UNIX;

  pszSocket = memicmp( pConfig->pszSocket, "\\socket\\", 8 ) == 0 ?
                &pConfig->pszSocket[8] : pConfig->pszSocket;

  if ( _snprintf( stUn.sun_path, sizeof(stUn.sun_path), "\\socket\\%s",
                  pszSocket ) == -1 )
  {
    puts( "Socket name too long" );
    return FALSE;
  }

  if ( bind( hSocket, (struct sockaddr *)&stUn, sizeof(stUn) ) == -1 )
  {
#ifdef DEBUG_FILE
    xplSockPError( "bind" );
#endif
    if ( xplSockError() == SOCEADDRINUSE );
      printf( "Socket %s already in use.\n", &stUn.sun_path );
    xplSockClose( hSocket );
    hSocket = -1;
    return FALSE;
  }

  if ( listen( hSocket, 16 ) == -1 )
  {
#ifdef DEBUG_FILE
    xplSockPError( "listen" );
#endif
    xplSockClose( hSocket );
    hSocket = -1;
    return FALSE;
  }

  xplSockIOCtl( hSocket, FIONBIO, &iVal );

  tid = _beginthread( threadSockets, NULL, THREAD_STACK_SIZE, NULL );
  if ( tid == ((TID)(-1)) )
  {
    debug( "_beginthread() failed" );
    ifsockDone();
    return FALSE;
  }

  return TRUE;
}

VOID ifsockDone()
{
  if ( hmtxClients == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  xplMutexLock( hmtxClients, XPL_INDEFINITE_WAIT );
  xplMutexDestroy( hmtxClients );
  hmtxClients = NULLHANDLE;

  xplSockClose( hSocket );
  hSocket = -1;

  while( tid != ((TID)(-1)) )
    xplSleep( 1 );

  lnkseqFree( &lsClients, PCLIENT, _closeClient );
}

VOID ifsockRequest(ULONG cReq, PSZ *apszReq)
{
  struct sockaddr_un   stUn;
  ULONG                ulIdx;
  int                  iRC;
  CHAR                 szBuf[512];

  if ( _snprintf( stUn.sun_path, sizeof(stUn.sun_path), "\\socket\\%s",
                  pConfig->pszSocket ) == -1 )
  {
    debug( "Socket name too long" );
    return;
  }
  stUn.sun_len = sizeof(stUn);
  stUn.sun_family = AF_UNIX;

  hSocket = socket( PF_UNIX, SOCK_STREAM, 0 );

  if ( connect( hSocket, (struct sockaddr *)&stUn, SUN_LEN( &stUn ) ) == -1 )
  {
    puts( "Cannot connect to the program. Does it launched?" );
    xplSockClose( hSocket );
    return;
  }

  szBuf[sizeof(szBuf) - 1] = '\0';

  for( ulIdx = 0; ulIdx < cReq; ulIdx++ )
  {
    iRC = _snprintf( &szBuf, sizeof(szBuf) - 1, "%s\n", apszReq[ulIdx] );
    if ( iRC == -1 )
      continue;

    iRC = send( hSocket, &szBuf, iRC, 0 );
    if ( iRC == -1 )
    {
      printf( "send() failed, error %u\n", xplSockError() );
      break;
    }

    printf( &szBuf );

    iRC = recv( hSocket, &szBuf, sizeof(szBuf) - 1, 0 );
    if ( iRC == -1 )
      printf( "send() failed, error %u\n", xplSockError() );
    else
    {
      szBuf[iRC] = '\0';
      printf( "> %s", szBuf );
    }
  }

  shutdown( hSocket, 1 );
  xplSockClose( hSocket );
}
