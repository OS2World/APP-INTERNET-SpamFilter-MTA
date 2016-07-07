#include <signal.h>
#include <dos.h>
#include <direct.h>
#include <string.h>
#include "debug.h"
#include "config.h"
#include "log.h"
#include "sockets.h"
#include "ifpipe.h"
#include "ifsock.h"
#include "sigqueue.h"
#include "stat.h"
#include "requests.h"
#include "datafile.h"
#include "weasel.h"

#include "dns.h"
#include "msgfile.h"

#define _DEF_CONFIG_FILE         "config.xml"

static PSZ   pszCfgFile = _DEF_CONFIG_FILE;

VOID sigBreak(int sinno)
{
  log( 1, "The system BREAK signal received." );
  sqPost( SIG_SHUTDOWN );
}

static BOOL _getOpt(int argc, char **argv)
{
  int                  iOpt;
  CHAR                 acBuf[_MAX_PATH];
  PSZ                  pszDrv, pszDir, pszFile, pszExt;
  unsigned int         uiTotal;
  PSZ                  pszReq[32];
  ULONG                cReq = 0;
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
  while( ( iOpt = getopt( argc, argv, "c:vr:h?" ) ) != -1 )
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

      case ':': 
      case '?':
      case 'h':
        printf( "Usage: %s%s [options]\nOptions:\n"
                "  -h, -?         Show this help.\n"
                "  -c <file>      Use given configuration file instead of "
                _DEF_CONFIG_FILE".\n"
                "  -v             Verify configuration file and exit.\n"
                "  -r <request>   Parse configuration file, then send query "
                "to running copy\n"
                "                 and exit. For example: -r reconfigure, -r "
                "\"shutdown\"\n"
                "                 It can be specified multiple times.",
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
    ifsockRequest( cReq, &pszReq );
    cfgDone();
    xplDone();
    exit( 0 );
  }

  return TRUE;
}

int compar(const void *pkey, const void *pbase)
{
  return (LONG)pkey - *(PLONG)pbase;
}


void main(int argc, char **argv)
{
  ULONG      ulSignal;

  debugInit();
  xplInit();

  if ( !_getOpt( argc, argv ) )
  {
    debugDone();
    xplDone();
    exit( 1 );
  }

  if ( !logInit() || !socketInit() || !sqInit() || !dfInit() || !reqInit() ||
       !statInit() || !ifsockInit() )
  {
    puts( "Initialization failed." );
    debugDone();
    xplDone();
    exit( 2 );
  }

  ifpipeInit();
  if ( pConfig->fWeaselLogPipe )
    weaselInit( pConfig->fWeaselLogToScreen );

  signal( SIGINT, sigBreak );
  signal( SIGTERM, sigBreak );
  sqSetTimer( SIG_CLEANING, 1000 * 3 );              // Internal data clean up.
  sqSetTimer( SIG_LISTS_STORE, 1000 * 60 * 2 );      // Save data files.
  sqSetTimer( SIG_POSTPONDED_BACKUP, 1000 );         // Delayed rename tasks.

  while( ( ulSignal = sqWait() ) != SIG_SHUTDOWN )
  {
    switch( ulSignal )
    {
      case SIG_CLEANING:
        reqClean();
        break;

      case SIG_LISTS_STORE:
        reqStoreLists();
        break;

      case SIG_POSTPONDED_BACKUP:
        dfExecPostpond( FALSE );
        break;

      case SIG_RECONFIGURE:
        cfgReconfigure();
        reqReconfigured();
        break;
    }

    weaselListenLog();
  }

  weaselDone();
  reqStoreLists();
  statDone();
  socketDone(); // Closes sockets ==> cancel waits...
  reqDone();
  ifpipeDone();
  ifsockDone();
  dfDone();
  sqDone();
  logDone();
  cfgDone();
  debugDone();
  xplDone();
#ifdef DEBUG_FILE
  puts( "Done." );
#endif
}
