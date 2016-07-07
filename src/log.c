#ifndef LOG_H
#define LOG_H

#include <stdio.h> 
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include "xpl.h"
#include "config.h"
#include "debug.h"

#define LOG_NAME                 "sf"
#define BUFPSZ_RECORDS           8

static FILE            *fdLog = NULL;
static HMTX            hmtxLog = NULLHANDLE;
static PSZ             apszBufPSZ[BUFPSZ_RECORDS] = { 0 };
static ULONG           ulBufPSZPos = 0;
static struct tm       stLastTime = { 0 };
static PSZ             pszLogPath = NULL;

VOID logWrite(PSZ pszFormat, ...);

static BOOL _logOpen()
{
  struct stat          stStat;
  CHAR                 acBuf[_MAX_PATH];
  FILE                 *fdNew;

  if ( ( fdLog != NULL ) &&
       ( stricmp( pConfig->pszLogPath, pszLogPath ) == 0 ) )
    return TRUE;

  if ( stat( pConfig->pszLogPath, &stStat ) == -1 || !S_ISDIR(stStat.st_mode) )
  {
    logWrite( "The log-path does not exist: %s\n", pConfig->pszLogPath );
    return FALSE;
  }

  _snprintf( &acBuf, sizeof(acBuf), "%s\\"LOG_NAME".log", pConfig->pszLogPath );

  fdNew = fopen( &acBuf, "a" ); 
  if ( fdNew == NULL )
  {
    logWrite( "Cannot open logfile: %s\n", &acBuf );
    return FALSE;
  }

  if ( fdLog != NULL )
    fclose( fdLog );
  fdLog = fdNew;

  if ( pszLogPath != NULL )
    debugFree( pszLogPath );
  pszLogPath = debugStrDup( pConfig->pszLogPath );

  return TRUE;
}

static VOID _logClose()
{
  if ( fdLog != NULL )
  {
    fclose( fdLog );
    fdLog = NULL;
  }

  if ( pszLogPath != NULL )
  {
    debugFree( pszLogPath );
    pszLogPath = NULL;
  }
}

static VOID _logRotate()
{
  ULONG       ulIdx;
  CHAR       acFrom[_MAX_PATH];
  CHAR       acTo[_MAX_PATH];

  if ( pConfig->ulLogHistory == 0 )
  {
    _snprintf( &acFrom, sizeof(acFrom), "%s\\"LOG_NAME".log",
               pConfig->pszLogPath );
    unlink( &acFrom );
    return;
  }

  _snprintf( &acTo, sizeof(acTo), "%s\\"LOG_NAME".%.3u",
             pConfig->pszLogPath, pConfig->ulLogHistory - 1 );
  unlink( &acTo );

  for( ulIdx = pConfig->ulLogHistory - 1; ulIdx > 0; ulIdx-- )
  {
    _snprintf( &acFrom, sizeof(acFrom), "%s\\"LOG_NAME".%.3u",
               pConfig->pszLogPath, ulIdx - 1 );

    rename( &acFrom, &acTo );
    strcpy( &acTo, &acFrom );
  }

  _snprintf( &acFrom, sizeof(acFrom), "%s\\"LOG_NAME".log",
             pConfig->pszLogPath );
  if ( rename( &acFrom, &acTo ) != 0 )
    debug( "Rename failed: %s TO %s", &acFrom, &acTo );
}

static VOID _logDateRename()
{
  CHAR       acFrom[_MAX_PATH];
  CHAR       acTo[_MAX_PATH];
  ULONG      cbTo = _bprintf( &acTo, sizeof(acTo) - 12, "%s\\"LOG_NAME,
                              pConfig->pszLogPath );
  time_t     timeOld;
  struct tm  stTime;

  // Remove oldest file.
  time( &timeOld );
  timeOld -= ( (pConfig->ulLogHistory + 1) * (24*60*60) );
  _localtime( &timeOld, &stTime );
  strftime( &acTo[cbTo], sizeof(acTo) - cbTo, "-%Y%m%d.log", &stTime );
  unlink( &acTo );

  _snprintf( &acFrom, sizeof(acFrom) - 4, "%s\\"LOG_NAME".log",
             pConfig->pszLogPath );
  // Make name for the new history file.
  strftime( &acTo[cbTo], sizeof(acTo) - cbTo, "-%Y%m%d.log", &stLastTime );
 
  unlink( &acTo );
  if ( rename( &acFrom, &acTo ) != 0 )
    debug( "Rename failed: %s TO %s", &acFrom, &acTo );
}


BOOL logInit()
{
  if ( !_logOpen() )
    return FALSE;

  xplMutexCreate( &hmtxLog, FALSE );
  if ( hmtxLog == NULLHANDLE )
  {
    _logClose();
    return FALSE;
  }

  return TRUE;
}

VOID logDone()
{
  ULONG      ulIdx;

  if ( hmtxLog != NULLHANDLE )
    xplMutexDestroy( hmtxLog );

  _logClose();

  for( ulIdx = 0; ulIdx < BUFPSZ_RECORDS; ulIdx++ )
    if ( apszBufPSZ[ulIdx] != NULL )
      debugFree( apszBufPSZ[ulIdx] );
  bzero( apszBufPSZ, sizeof(apszBufPSZ) );
}

BOOL logReOpen()
{
  BOOL       fRes;

  xplMutexLock( hmtxLog, XPL_INDEFINITE_WAIT );
  fRes = _logOpen();
  xplMutexUnlock( hmtxLog );

  return fRes;
}

VOID logWrite(PSZ pszFormat, ...)
{
  va_list    arglist;
  time_t     timeLog;
  struct tm  stTime;
  char       acBuf[32];
  BOOL       fMtx;

  time( &timeLog );
  strftime( &acBuf, sizeof(acBuf), "%Y%m%d %H%M%S ", 
            _localtime( &timeLog, &stTime ) );

  va_start( arglist, pszFormat );
  fMtx = ( xplMutexLock( hmtxLog, XPL_INDEFINITE_WAIT ) == XPL_NO_ERROR );

  if ( fdLog == NULL )
  {
    vprintf( pszFormat, arglist );
    puts( "" );
  }
  else
  {
    if ( pConfig->ulLogSize == 0 )
    {
      if ( ( stLastTime.tm_mday != 0 ) &&
           ( stLastTime.tm_mday != stTime.tm_mday ) )
      {
        // Size of logfile not limited and a new day has begun - rename logfile.
        _logClose();
        _logDateRename();
        _logOpen();
      }
      stLastTime = stTime;
    }

    fputs( &acBuf, fdLog ); 
    vfprintf( fdLog, pszFormat, arglist );
    fputs( "\n", fdLog );
    fflush( fdLog );

    if ( ( pConfig->ulLogSize != 0 ) &&
         ( ftell( fdLog ) >= pConfig->ulLogSize ) )
    {
      // Size of the logfile exceeded configured limit - rotate logfiles.
      _logClose();
      _logRotate();
      _logOpen();
    }

  }

  if ( fMtx )
    xplMutexUnlock( hmtxLog );

  va_end( arglist );
}

PSZ logBufToPSZ(ULONG cbBuf, PCHAR pcBuf)
{
  PSZ        pszRecord;

  if ( ( cbBuf == 0 ) || ( pcBuf == NULL ) )
    return "";

  pszRecord = debugMAlloc( cbBuf + 1 );
  if ( pszRecord == NULL )
  {
    debug( "Not enough memory" );
    return "";
  }
  memcpy( pszRecord, pcBuf, cbBuf );
  pszRecord[cbBuf] = '\0';

  xplMutexLock( hmtxLog, XPL_INDEFINITE_WAIT );

  if ( apszBufPSZ[ulBufPSZPos] != NULL )
    debugFree( apszBufPSZ[ulBufPSZPos] );

  apszBufPSZ[ulBufPSZPos] = pszRecord;
  ulBufPSZPos = (ulBufPSZPos + 1) % BUFPSZ_RECORDS;

  xplMutexUnlock( hmtxLog );

  return pszRecord;
}

#endif // LOG_H
