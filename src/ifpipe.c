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
#include "ifpipe.h"
#include "hmem.h"
#include "piper.h"     // prExpandPipeName()
#include "debug.h"     // Must be the last.

// #define _EXPAND_PIPE_SEM_STATE_BUFFER 1

#define THREAD_STACK_SIZE        65535
#define WRITE_BUF_SIZE           1024
#define READ_BUF_SIZE            1024

static PHPIPE          pahPipes = NULL;
static ULONG           cPipes = 0;
static HEV             hevPipes = NULLHANDLE;
static PSZ             pszPipe = NULL;
volatile static TID    tid = ((TID)(-1));

static BOOL _createPipe(PHPIPE phPipe, PSZ pszName, ULONG ulKey)
{
  ULONG                ulRC;

  ulRC = DosCreateNPipe( pszName, phPipe, NP_NOINHERIT | NP_ACCESS_DUPLEX,
                         NP_NOWAIT | NP_TYPE_BYTE | NP_READMODE_BYTE |
                         pConfig->ulPipes, WRITE_BUF_SIZE, READ_BUF_SIZE, 0 );
  if ( ulRC != NO_ERROR )  
  {
    log( 1, "Cannot create named pipe %s, rc = %lu", pszName, ulRC );
    if ( ulRC == ERROR_PIPE_BUSY )
      printf( "Named pipe %s is busy.\n", pszName );
    return FALSE;
  }

  ulRC = DosSetNPipeSem( *phPipe, (HSEM)hevPipes, ulKey );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosSetNPipeSem(), rc = %lu", ulRC );
    DosClose( *phPipe );
    return FALSE;
  }

  ulRC = DosConnectNPipe( *phPipe );
  if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
  {
    debug( "DosConnectNPipe(), rc = %s", ulRC );
    log( 1, "Cannot connect named pipe %s, rc = %lu", pszName, ulRC );
    DosClose( *phPipe );
    return FALSE;
  }

  debug( "Pipe %s created (key: %lu)", pszName, ulKey );
  return TRUE;
}

static VOID fnAnswer(PVOID pUser, ULONG cbAnswer, PCHAR pcAnswer)
{
  ULONG      ulRC;
  ULONG      ulActual;
  HPIPE      hPipe = pahPipes[(ULONG)pUser];

  // Shutdown signal from ifpipeDone().
  if ( tid == ((TID)(-1)) )
  {
    debugCP( "Shutdown state, exit" );
    return;
  }

  if ( cbAnswer <= 3 )
    debug( "Answer too short: only %lu bytes: 0x%X 0x%X 0x%X",
           cbAnswer, pcAnswer[0], pcAnswer[1], pcAnswer[2] );
  else if ( isspace( pcAnswer[0] ) )
    debug( "Answer starts with one of \"space\" characters: 0x%X 0x%X 0x%X",
           pcAnswer[0], pcAnswer[1], pcAnswer[2] );

  ulRC = DosWrite( hPipe, pcAnswer, cbAnswer, &ulActual );
  if ( ulRC != NO_ERROR )
  {
    debug( "pipe #%lu, DosWrite(), rc = %lu", (ULONG)pUser, ulRC );

    ulRC = DosDisConnectNPipe( hPipe );
    if ( ulRC != NO_ERROR )
      debug( "DosDisConnectNPipe(), rc = %lu", ulRC );

    ulRC = DosConnectNPipe( hPipe );
    if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
      debug( "DosConnectNPipe(), rc = %lu", ulRC );
  }
  else if ( ulActual != cbAnswer )
  {
    debug( "Only %lu bytes out of %lu are written to the pipe",
           ulActual, cbAnswer );
  }
}

void threadPipes(void *pData)
{
  ULONG                ulRC;
  ULONG                cbPipeState = (cPipes + 2) * sizeof(PIPESEMSTATE);
  PPIPESEMSTATE        paPipeState, pPipeState;
  PCHAR                pcBuf;
  ULONG                cbBuf;

  pcBuf = malloc( READ_BUF_SIZE ); // Low memory, will be given to DosRead.
  if ( pcBuf == NULL )
  {
    debugCP( "Not enough memory" );
    _endthread();
    return;
  }

  paPipeState = malloc( cbPipeState ); // Low memory, will be given to DosQueryNPipeSemState.
  if ( paPipeState == NULL )
  {
    debugCP( "Not enough memory" );
    free( pcBuf );
    _endthread();
    return;
  }

  while( TRUE )
  {
    // Wait event from pipes or ifpipeDone().
    ulRC = DosWaitEventSem( hevPipes, SEM_INDEFINITE_WAIT );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosWaitEventSem(), rc = %lu", ulRC );
      break;
    }

    // Shutdown signal from ifpipeDone().
    if ( tid == ((TID)(-1)) )
      break;

#ifdef _EXPAND_PIPE_SEM_STATE_BUFFER
l00:
#endif
    // Query information about pipes that are attached to the semaphore. 
    ulRC = DosQueryNPipeSemState( (HSEM)hevPipes, paPipeState, cbPipeState );
    if ( ulRC != NO_ERROR )
    {
      log( 1, "Pipe interface error. DosQueryNPipeSemState(), rc = %lu", ulRC );

#ifdef _EXPAND_PIPE_SEM_STATE_BUFFER
      if ( ulRC == ERROR_BUFFER_OVERFLOW )
      {
        PPIPESEMSTATE  pNew;

        debug( "Expand buffer for DosQueryNPipeSemState() from %lu to %lu bytes",
               cbPipeState, cbPipeState * 2 );
        cbPipeState *= 2;
        if ( cbPipeState > (10 * cPipes * sizeof(PIPESEMSTATE)) )
        {
          debugCP( "Too big buffer for DosQueryNPipeSemState(), end thread" );
          break;
        }

        pNew = realloc( paPipeState, cbPipeState ); // Low memory, will be given to DosQueryNPipeSemState.
        if ( pNew == NULL )
        {
          debugCP( "Not enough memory" );
          break;
        }
        paPipeState = pNew;
        goto l00;
      }
#endif

      continue;
    }

    // Check pipe states.
    for( pPipeState = paPipeState; pPipeState->fStatus != NPSS_EOI;
         pPipeState++ )
    {
      if ( pPipeState->usKey >= cPipes )
      {
        debug( "Unknow pPipeState->usKey: %lu, status: %lu, total pipes: %lu",
               pPipeState->usKey, pPipeState->fStatus, cPipes );
        continue;
      }

      switch( pPipeState->fStatus )
      {
        case NPSS_RDATA:
          ulRC = DosRead( pahPipes[pPipeState->usKey], pcBuf,
                          pPipeState->usAvail, &cbBuf );
          if ( ulRC == NO_ERROR )
          {
            while( ( cbBuf > 0 ) && isspace( pcBuf[cbBuf-1] ) )
              cbBuf--;
            if ( cbBuf != 0 )
            {
              if ( !reqNew( cbBuf, pcBuf, fnAnswer,
                             (PVOID)pPipeState->usKey ) )
                DosWrite( pahPipes[pPipeState->usKey], "ERROR-INT:\n",
                          11, &cbBuf );
              break;
            }
          }
          else
            debug( "DosRead(), rc = %lu", ulRC );

        case NPSS_CLOSE:
          {
            ulRC = DosDisConnectNPipe( pahPipes[pPipeState->usKey] );
            if ( ulRC != NO_ERROR )
            {
              debug( "DosDisConnectNPipe(), rc = %lu (key: %lu)",
                     ulRC, pPipeState->usKey );
              log( 1, "Cannot disconnect named pipe %s, rc = %lu",
                   pszPipe, ulRC );
            }
            else
            {
              ulRC = DosConnectNPipe( pahPipes[pPipeState->usKey] );
              if ( (ulRC != NO_ERROR) && (ulRC != ERROR_PIPE_NOT_CONNECTED) )
              {
                debug( "DosConnectNPipe(), rc = %lu (key: %lu)",
                       ulRC, pPipeState->usKey );
                log( 1, "Cannot connect named pipe %s, rc = %lu",
                     pszPipe, ulRC );
              }
            }

            if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
            {
              ulRC = DosClose( pahPipes[pPipeState->usKey] );
              if ( ulRC != NO_ERROR )
                debug( "DosClose(), rc = %s", ulRC );

              _createPipe( &pahPipes[pPipeState->usKey], pszPipe,
                           pPipeState->usKey );
            }
          }
          break;
      }
    }  // for( pPipeState ...
  }

  free( paPipeState );
  free( pcBuf );
  _endthread();
}


BOOL ifpipeInit()
{
  CHAR                 szBuf[CCHMAXPATH];
  ULONG                ulRC;

  if ( pahPipes != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  if ( ( pConfig->pszPipe == NULL ) || ( pConfig->ulPipes == 0 ) )
  {
    debug( "Pipe interface is not configured" );
    return TRUE;
  }

  // Make a pipe name. Add the prefix \PIPE\ if it is missing.
  if ( prExpandPipeName( sizeof(szBuf), szBuf, pConfig->pszPipe ) == 0 )
  {
    debug( "Too long pipe name: %s", szBuf );
    return FALSE;
  }

  pahPipes = hmalloc( pConfig->ulPipes * sizeof(HPIPE) );
  if ( pahPipes == NULL )
  {
    debugCP( "Not enough memory" );
    return FALSE;
  }

  ulRC = DosCreateEventSem( NULL, &hevPipes, DC_SEM_SHARED | DCE_AUTORESET,
                            FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(), rc = %lu", ulRC );
    hfree( pahPipes );
    return FALSE;
  }

  // Create pipes and attach event semaphore.
  debug( "Create %lu named pipes %s...", pConfig->ulPipes, &szBuf );
  for( cPipes = 0;
       ( cPipes < pConfig->ulPipes ) &&
       _createPipe( &pahPipes[cPipes], szBuf, cPipes ); cPipes++ );

  if ( cPipes < pConfig->ulPipes )
  {
    debug( "_createPipe() failed" );
    ifpipeDone();
    return FALSE;
  }

  pszPipe = strdup( szBuf );

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
  ULONG                ulRC;
  volatile TID         tidWait = tid;

  if ( pahPipes == NULL )
  {
    debug( "Was not initialized" );
    return;
  }

  if ( tid != ((TID)(-1)) )
  {
    // Signal to shutdown for the thread.
    tid = ((TID)(-1));
    DosPostEventSem( hevPipes );
    // Wait until thread ended.
    ulRC = DosWaitThread( (PULONG)&tidWait, DCWW_WAIT );
    if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_INVALID_THREADID ) )
      debug( "DosWaitThread(), rc = %lu", ulRC );
  }

  for( ; cPipes != 0; cPipes-- )
    DosClose( pahPipes[cPipes - 1] );

  DosCloseEventSem( hevPipes );
  hevPipes = NULLHANDLE;

  if ( pszPipe != NULL )
    free( pszPipe );

  hfree( pahPipes );
  pahPipes = NULL;
}


VOID ifpipeRequest(ULONG cReq, PSZ *apszReq)
{
  ULONG    ulRC;
  HPIPE    hPipe;
  ULONG    ulIdx = 0;
  ULONG    ulActual;
  CHAR     szBuf[CCHMAXPATH];

  if ( pConfig->pszPipe == NULL )
  {
    puts( "Pipe interface was not configured" );
    return;
  }

  // Make a pipe name. Add the prefix \PIPE\ if it is missing.
  if ( prExpandPipeName( sizeof(szBuf), szBuf, pConfig->pszPipe ) == 0 )
  {
    debug( "Too long pipe name: %s", pConfig->pszPipe );
    return;
  }

  // Connect to the pipe.
  do
  {
    ulRC = DosOpen( szBuf, &hPipe, &ulActual, 0, FILE_NORMAL, FILE_OPEN,
                    OPEN_ACCESS_READWRITE | OPEN_SHARE_DENYNONE, NULL );
    if ( ( ulRC != ERROR_PIPE_BUSY ) || ( ulIdx != 0 ) )
      break;

    ulIdx++;
    /* DosWaitNPipe enables a client process to wait for a named-pipe instance
       to become available when all instances are busy. It should be used only
       when ERROR_PIPE_BUSY is returned from a call to DosOpen. */
    ulRC = DosWaitNPipe( szBuf, 1000 );
  }
  while( ulRC == NO_ERROR );

  if ( ulRC != NO_ERROR )
  {
    if ( ulRC == ERROR_FILE_NOT_FOUND || ulRC == ERROR_PATH_NOT_FOUND )
      puts( "No pipe. Does program launched?" );
    else
      printf( "Could not open the pipe (rc: %lu)\n", ulRC );
    return;
  }

  // Send the user requests and print replies.

  for( ulIdx = 0; ulIdx < cReq; ulIdx++ )
  {
    ulActual = (ULONG)_snprintf( &szBuf, sizeof(szBuf) - 1, "%s\n",
                                 apszReq[ulIdx] );
    if ( (LONG)ulActual == -1 )
      continue;

    ulRC = DosWrite( hPipe, &szBuf, ulActual, &ulActual );
    if ( ulRC != NO_ERROR )
    {
      printf( "DosWrite(), rc = %lu\n", ulRC );
      continue;
    }

    printf( &szBuf );
    ulRC = DosRead( hPipe, &szBuf, sizeof(szBuf) - 1, &ulActual );
    if ( ulRC != NO_ERROR )
      printf( "DosRead(), rc = %lu\n", ulRC );
    else
    {
      // Print obtained data.
      szBuf[ulActual] = '\0';
      printf( "> %s", szBuf );
    }
  }
  DosClose( hPipe );
}
