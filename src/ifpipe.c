#include <stdio.h>
#include <ctype.h>
#include <string.h>
#define INCL_DOSSEMAPHORES   /* Semaphore values */
#define INCL_DOSERRORS       /* DOS error values */
#define INCL_DOSNMPIPES
#define INCL_DOSPROCESS
#include <os2.h>
#include "log.h"
#include "requests.h"
#include "debug.h"
#include "ifpipe.h"

#define THREAD_STACK_SIZE        65535
#define WRITE_BUF_SIZE           1024
#define READ_BUF_SIZE            (1024 * 10)

typedef struct _SRVPIPE {
  HPIPE                hPipe;
  ULONG                ulState;
} SRVPIPE, *PSRVPIPE;

static PSRVPIPE        paPipes = NULL;
static ULONG           cPipes = 0;
static HEV             hevPipes = NULLHANDLE;
static TID             tid = ((TID)(-1));


static BOOL createPipe(PSRVPIPE pPipe, PSZ pszName, ULONG ulKey)
{
  ULONG                ulRC;

  ulRC = DosCreateNPipe( pszName, &pPipe->hPipe,
                         NP_NOINHERIT | NP_ACCESS_DUPLEX,
                         NP_NOWAIT | NP_TYPE_BYTE | NP_READMODE_BYTE |
                         pConfig->ulPipes,
                         WRITE_BUF_SIZE, READ_BUF_SIZE, 0 );
  if ( ulRC != NO_ERROR )  
  {
    log( 1, "Cannot create named pipe %s, rc = %u", pszName, ulRC );
    if ( ulRC == ERROR_PIPE_BUSY )
      printf( "Named pipe %s is busy.\n", pszName );
    return FALSE;
  }

  ulRC = DosSetNPipeSem( pPipe->hPipe, (HSEM)hevPipes, ulKey );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosSetNPipeSem(), rc = %u", ulRC );
    DosClose( pPipe->hPipe );
    return FALSE;
  }

  ulRC = DosConnectNPipe( pPipe->hPipe );
  if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
  {
    log( 1, "Cannot connect named pipe %s, rc = %u", pszName, ulRC );
    DosClose( pPipe->hPipe );
    return FALSE;
  }

  return TRUE;
}

static VOID fnAnswer(PVOID pUser, ULONG cbAnswer, PCHAR pcAnswer)
{
  ULONG      ulRC;
  ULONG      ulActual;
  HPIPE      hPipe = paPipes[(ULONG)pUser].hPipe;

  // Shutdown signal from ifpipeDone().
  if ( tid == ((TID)(-1)) )
    return;

  ulRC = DosWrite( hPipe, pcAnswer, cbAnswer, &ulActual );
  if ( ulRC != NO_ERROR )
  {
    debug( "pipe #%u, DosWrite(), rc = %u", (ULONG)pUser, ulRC );
    DosDisConnectNPipe( hPipe );
    DosConnectNPipe( hPipe );
  }
}

void threadPipes(void *pData)
{
  ULONG                ulRC;
  ULONG                cbPipeState;
  PPIPESEMSTATE        paPipeState, pPipeState;
  ULONG                ulIdx;
  PCHAR                pcBuf;
  ULONG                cbBuf;

  pcBuf = debugMAlloc( READ_BUF_SIZE );
  if ( pcBuf == NULL )
  {
    debug( "Not enough memory" );
    _endthread();
    return;
  }

  cbPipeState = (cPipes + 2) * sizeof(PIPESEMSTATE);
  paPipeState = debugMAlloc( cbPipeState );
  if ( paPipeState == NULL )
  {
    debug( "Not enough memory" );
    debugFree( pcBuf );
    _endthread();
    return;
  }

  while( TRUE )
  {
    // Wait event from pipes or ifpipeDone().
    ulRC = DosWaitEventSem( hevPipes, SEM_INDEFINITE_WAIT );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosWaitEventSem(), rc = %u", ulRC );
      break;
    }

    // Shutdown signal from ifpipeDone().
    if ( tid == ((TID)(-1)) )
      break;

    // Query information about pipes that are attached to the semaphore. 
    ulRC = DosQueryNPipeSemState( (HSEM)hevPipes, paPipeState, cbPipeState );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosQueryNPipeSemState(), rc = %u", ulRC );
      continue;
    }

    // Check pipe states.
    for( ulIdx = 0, pPipeState = paPipeState; ulIdx < cPipes;
         ulIdx++, pPipeState++ )
    {
      switch( pPipeState->fStatus )
      {
        case 1:        // NPSS_RDATA
          ulRC = DosRead( paPipes[pPipeState->usKey].hPipe, pcBuf,
                          pPipeState->usAvail, &cbBuf );
          if ( ulRC == NO_ERROR )
          {
            while( ( cbBuf > 0 ) && isspace( pcBuf[cbBuf-1] ) )
              cbBuf--;
            if ( cbBuf != 0 )
            {
              if ( !reqNew( cbBuf, pcBuf, fnAnswer,
                             (PVOID)pPipeState->usKey ) )
                DosWrite( paPipes[pPipeState->usKey].hPipe, "ERROR-INT:\n",
                          11, &cbBuf );
              break;
            }
          }
          else
            debug( "DosRead(), rc = %u", ulRC );

        case 3:        // NPSS_CLOSE 
          DosDisConnectNPipe( paPipes[pPipeState->usKey].hPipe );
// ???
//DosSleep( 1 );
          DosConnectNPipe( paPipes[pPipeState->usKey].hPipe );
          break;
      }
    }
  }

  debugFree( paPipeState );
  debugFree( pcBuf );
  _endthread();
}


BOOL ifpipeInit()
{
  CHAR                 szBuf[_MAX_PATH];
  ULONG                ulRC;

  if ( ( pConfig->pszPipe == NULL ) || ( pConfig->ulPipes = 0 ) )
  {
    debug( "Pipe interface is not configured" );
    return TRUE;
  }

  if ( paPipes != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  if ( _snprintf( &szBuf, sizeof(szBuf), "\\PIPE\\%s", pConfig->pszPipe )
       == -1 )
  {
    debug( "Pipe name too long" );
    return FALSE;
  }

  paPipes = debugMAlloc( pConfig->ulPipes * sizeof(SRVPIPE) );
  if ( paPipes == NULL )
  {
    debug( "Not enough memory" );
    return FALSE;
  }

  ulRC = DosCreateEventSem( NULL, &hevPipes, DC_SEM_SHARED | DCE_AUTORESET,
                            FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(), rc = %u", ulRC );
    debugFree( paPipes );
    return FALSE;
  }

  // Create pipes and attach event semaphore.
  for( cPipes = 0;
       ( cPipes < pConfig->ulPipes ) &&
       createPipe( &paPipes[cPipes], &szBuf, cPipes ); cPipes++ );

  if ( cPipes < pConfig->ulPipes )
  {
    debug( "createPipe() failed" );
    ifpipeDone();
    return FALSE;
  }

  tid = _beginthread( threadPipes, NULL, THREAD_STACK_SIZE, NULL );
  if ( tid == ((TID)(-1)) )
  {
    debug( "_beginthread() failed" );
    ifpipeDone();
    return FALSE;
  }

  return TRUE;
}

VOID ifpipeDone()
{
  ULONG      ulRC;
  TID        tidWait = tid;

  if ( paPipes == NULL )
    return;

  // Signal to shutdown for the thread.
  tid = ((TID)(-1));
  DosPostEventSem( hevPipes );
  // Wait until thread ended.
  ulRC = DosWaitThread( &tidWait, DCWW_WAIT );
  if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_INVALID_THREADID ) )
    debug( "DosWaitThread(), rc = %u", ulRC );

  for( ; cPipes != 0; cPipes-- )
    DosClose( paPipes[cPipes - 1].hPipe );

  DosCloseEventSem( hevPipes );
  hevPipes = NULLHANDLE;
  debugFree( paPipes );
  paPipes = NULL;
}


VOID ifpipeRequest(ULONG cReq, PSZ *apszReq)
{
  ULONG    ulRC;
  HPIPE    hPipe;
  ULONG    ulIdx;
  ULONG    ulActual;
  CHAR     szBuf[_MAX_PATH];

  if ( pConfig->pszPipe == NULL )
  {
    puts( "Pipe interface was not configured" );
    return;
  }

  _snprintf( &szBuf, sizeof(szBuf), "\\PIPE\\%s", pConfig->pszPipe );

  ulRC = DosWaitNPipe( &szBuf, 500 );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC == ERROR_FILE_NOT_FOUND || ulRC == ERROR_PATH_NOT_FOUND )
      puts( "No pipe. Does program launched?" );
    else
      printf( "DosWaitNPipe(), rc = %u\n", ulRC );

    return;
  }

  ulRC = DosOpen( &szBuf, &hPipe, &ulActual, 0, FILE_NORMAL, FILE_OPEN,
                  OPEN_ACCESS_READWRITE | OPEN_SHARE_DENYNONE, NULL );
  if ( ulRC != NO_ERROR )
  {
    printf( "DosOpen(), rc = %u\n", ulRC );
    return;
  }

  for( ulIdx = 0; ulIdx < cReq; ulIdx++ )
  {
    ulActual = (ULONG)_snprintf( &szBuf, sizeof(szBuf) - 1, "%s\n",
                                 apszReq[ulIdx] );
    if ( (LONG)ulActual == -1 )
      continue;

    ulRC = DosWrite( hPipe, &szBuf, ulActual, &ulActual );
    if ( ulRC != NO_ERROR )
    {
      printf( "DosWrite(), rc = %u\n", ulRC );
      continue;
    }

    printf( &szBuf );
    ulRC = DosRead( hPipe, &szBuf, sizeof(szBuf) - 1, &ulActual );
    if ( ulRC != NO_ERROR )
      printf( "DosRead(), rc = %u\n", ulRC );
    else
    {
      // Print obtained data.
      szBuf[ulActual] = '\0';
      printf( "> %s", szBuf );
    }
  }
  DosClose( hPipe );
}
