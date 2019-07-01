#include <signal.h>
#include <dos.h>
#include <direct.h>
#include <string.h>
#include "config.h"
#include "log.h"
#include "sockets.h"
#include "ifpipe.h"
#include "ifsock.h"
#include "events.h"
#include "stat.h"
#include "requests.h"
#include "datafile.h"
//#include "weasel.h"
#include "piper.h"
#include "debug.h"     // Must be the last.

#define _DEF_CONFIG_FILE         "config.xml"

#ifndef VERSION
#define VERSION                  ""
#endif

#ifdef DEBUG_CODE
#define VERSION_STRING           VERSION" (debug)"
#else
#define VERSION_STRING           VERSION
#endif

static PSZ             pszCfgFile = _DEF_CONFIG_FILE;
static PPIPER          pWLogPiper = NULL;


// Callback function for piper module events.
static VOID _cbPREvent(PPIPER pPiper, ULONG ulCode, PSZ pszData)
{
  static BOOL    fReported = FALSE;

  switch( ulCode )
  {
    case PREVENT_CONNECTED:
      log( 5, "[INFO] Weasel log pipe %s is open", pszData );
      fReported = TRUE;
      return;

    case PREVENT_DISCONNECTED:
      log( 5, "[INFO] Weasel log pipe %s closed", pszData );
      return;

    case PREVENT_CONNECTERROR:
      if ( !fReported )
      {
        log( 1, "[INFO] Error connecting to the Weasel log pipe. "
                "Operation postponed." );
        fReported = TRUE;
      }
      return;

    case PREVENT_PIPECREATEERROR:
      log( 1, "[INFO] Error creating named pipe(s) %s", pszData );
      return;

    case PREVENT_INPUTLINE:
      break;

    default:
      debugCP( "WTF?!" );
      return;
  }

  if ( pConfig->fWeaselLogToScreen )
    puts( pszData );

  // Text string has been received.
  // Search a string like "2016-01-19 09:36:05 S    57  End of session"

  if ( ( strlen( pszData ) > 20 ) && ( pszData[20] == 'S' ) )
  {
    // SMTP log record.
    PCHAR  pcSessId = &pszData[21];
    ULONG  cbSessId = 0;
    PCHAR  pcPos;

    // Move to session id.
    while( isspace( *pcSessId ) )
      pcSessId++;
    // Scan numeric session id.
    pcPos = pcSessId;
    while( isdigit( *pcPos ) )
      pcPos++;

    cbSessId = pcPos - pcSessId;
    if ( cbSessId != 0 && isspace( *pcPos ) ) // Skip "Sorter","Send_NN"...
    {
      *pcPos = '\0';

      // Skip spaces, move to text.
      do { pcPos++; } while( isspace( *pcPos ) );

      // We have Weasel message and session Id.

      if ( ( strcmp( pcPos, "End of session" ) == 0 ) ||
           ( strcmp( pcPos, "Client rejected by filter" ) == 0 ) )
      {
        log( 5, "[INFO] Weasel log pipe: %s (session: %s).", pcPos, pcSessId );
        reqCloseSession( pcSessId );
      }
      else if ( strcmp( pcPos, "> 535 Authentication failed" ) == 0 )
      {
        log( 5, "[INFO] Weasel log pipe: %s (session: %s).", pcPos, pcSessId );
        reqSessionAuthFail( pcSessId );
      }
    }
  }  // if ( ( strlen( pszData ) > 20 ) && ( pszData[20] == 'S' ) )
}

// Break signal handler.
VOID sigBreak(int sinno)
{
  log( 1, "The system BREAK signal received." );
  evPost( EV_SHUTDOWN );
}

static BOOL _getOpt(int argc, char **argv)
{
  int                  iOpt;
  CHAR                 acBuf[_MAX_PATH];
  PSZ                  pszDrv, pszDir, pszFile, pszExt;
  unsigned int         uiTotal;
  PSZ                  pszReq[128];
  ULONG                cReq = 0;
  BOOL                 fSendReqToPipe = FALSE;
  BOOL                 fVerifyConfig = FALSE;

  _splitpath2( argv[0], &acBuf, &pszDrv, &pszDir, &pszFile, &pszExt );

  if ( pszDrv != NULL )
    _dos_setdrive( pszDrv[0] - 'A' + 1, &uiTotal );

  if ( pszDir != NULL )
  {
    uiTotal = strlen( pszDir );
    pszDir[uiTotal - 1] = '\0';

    if ( chdir( pszDir ) != 0 )
      debug( "chdir() for %s failed", pszDir );
  }

  opterr = 0;
  while( ( iOpt = getopt( argc, argv, "c:vr:Rh?" ) ) != -1 )
  { 
    switch( iOpt )
    { 
      case 'c':
        pszCfgFile = optarg;
        break; 

      case 'v':
        fVerifyConfig = TRUE;
        break;

      case 'r':
        if ( cReq < ARRAY_SIZE( pszReq ) )
        {
          pszReq[cReq] = optarg;
          cReq++;
        }
        break;

      case 'R':
        fSendReqToPipe = TRUE;
        break;

      case ':': 
      case '?':
      case 'h':
        printf( "SpamFilter "VERSION_STRING"\n\n"
                "Usage: %s%s [options]\nOptions:\n"
                "  -h, -?         Show this help.\n"
                "  -c <file>      Use given configuration file instead of "
                _DEF_CONFIG_FILE".\n"
                "  -v             Verify configuration file and exit.\n"
                "  -r <request>   Parse configuration file, then send query "
                "to running copy\n"
                "                 and exit. For example: -r reconfigure, -r "
                "\"shutdown\"\n"
                "                 It can be specified multiple times.\n"
                "  -R             Send queries specified by switch -r through a"
                " named pipe\n                 instead of a socket.",
                pszFile, pszExt );
        return FALSE;
    }
  }

  if ( !cfgInit( pszCfgFile ) )
    return FALSE;

  if ( fVerifyConfig )
  {
    cfgDone();

    if ( uiTotal )
    {
      printf( "Configuration has been verified: %s", pszCfgFile );
      xplDone();
      debugDone();
      exit( 0 );
    }
    return FALSE;
  }

  if ( cReq != 0 )
  {
    if ( fSendReqToPipe )
      ifpipeRequest( cReq, &pszReq );
    else
      ifsockRequest( cReq, &pszReq );
    cfgDone();
    xplDone();
    exit( 0 );
  }

  return TRUE;
}

static VOID _appDone()
{
  prDone( pWLogPiper );
  statDone();
  socketDone(); // Closes sockets ==> cancel waits...
  reqDone();
  ifpipeDone();
  ifsockDone();
  dfDone();
  evDone();
  logDone();
  cfgDone();
  debugDone();
  xplDone();
}


void main(int argc, char **argv)
{
  ULONG      ulEvent;

  debugInit();
  xplInit();

  if ( !_getOpt( argc, argv ) )
  {
    debugDone();
    xplDone();
    exit( 1 );
  }

  if ( !evInit() || !logInit() || !socketInit() || !dfInit() || !reqInit() ||
       !statInit() || !ifsockInit() || !ifpipeInit() )
  {
    puts( "Initialization failed." );
    _appDone();
    exit( 2 );
  }

  if ( pConfig->fWeaselLogPipe )
  {
    ULONG      ulRC;
    PRINIT     stInit;
    PSZ        pszErr;

    stInit.pcPipes = pConfig->pcWeaselLogPipes;
    stInit.ulReconnectPeriod = 10000;
    stInit.pszServerPipe = pConfig->pszServerLogPipe;
    stInit.cServerPipes = pConfig->ulServerLogPipes;
    stInit.fnUser = _cbPREvent;
    stInit.ulWriteBufSize = 1024;
    stInit.ulReadBufSize = 1024;
    stInit.hevInputPipe = evGetEvSemHandle( EV_PIPE );
    stInit.ulInputPipeKey = 0xFFFF;

    ulRC = prInit( &pWLogPiper, &stInit );
    if ( ulRC != PRRC_OK )
    {
      debug( "prInit() failed, rc = %lu", ulRC );

      switch( ulRC )
      {
        case PRRC_INVALIDPIPENAME:
          pszErr = "invalid alternative pipe name";
          break;

        case PRRC_NOTENOUGHMENORY:
          pszErr = "not enough memory";
          break;

        case PRRC_SRVPIPECREATEERR:
          pszErr = "failed to create Weasel log server pipe";
          break;

        case PRRC_INVALIDSRVPIPENAME:
          pszErr = "invalid Weasel log server pipe name";
          break;

        case PRRC_NAMECOLLISION:
          pszErr = "same names for Weasel log listening pipe and server pipe";
          break;

        default:
          pszErr = "";
      }

      log( 1, "Error creating Weasel log pipe: %s", pszErr );
      printf( "Error creating Weasel log pipe: %s", pszErr );
      _appDone();
      exit( 2 );
    }
  }

  signal( SIGINT, sigBreak );
  signal( SIGTERM, sigBreak );

/*{
  PMSGFILE   pMsgFile;
  ADDRLIST   stList = { 0 };
  ULONG      ulIdx;

  pMsgFile = mfOpen( "a.eml" );

  addrlstInit( &stList, 256 );
  mfScanBody( pMsgFile, &stList );

  printf( "List (%lu):\n", stList.cItems );
  for( ulIdx = 0; ulIdx < stList.cItems; ulIdx++ )
    printf( "#%lu %s\n", ulIdx, stList.ppItems[ulIdx]->szAddr );

  addrlstDone( &stList );
  mfClose( pMsgFile );

  return;
}*/

  while( TRUE )
  {
    ulEvent = evWait( 31 );
    if ( ulEvent == EV_SHUTDOWN || ulEvent == EV_ERROR )
      break;

    switch( ulEvent )
    {
      case EV_CLEANING:
        reqClean();
        break;

      case EV_LISTS_STORE:
        reqStoreLists();
        break;

      case EV_POSTPONDED_BACKUP:
        dfExecPostpond( FALSE );
        break;

      case EV_RECONFIGURE:
        reqReconfigure();
        break;

      case EV_PIPE:
        prProcess( pWLogPiper, TRUE );
        break;

      case EV_NO_EVENT:
        prProcess( pWLogPiper, FALSE );
        break;

      default:
        debug( "Unknown event: %lu", ulEvent );
    }
  }

  reqStoreLists();
  _appDone();
#ifdef DEBUG_FILE
  puts( "Done." );
#endif
}
