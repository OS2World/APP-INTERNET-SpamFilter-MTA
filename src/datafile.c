#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "config.h"
#include "linkseq.h"
#include "log.h"
#include "util.h"
#include "datafile.h"

typedef struct _DFPPTASK {
  SEQOBJ               seqObj;

  PSZ        pszSrc;
  PSZ        pszBakupExt;
  CHAR       szDest[1];
} DFPPTASK, *PDFPPTASK;


static HMTX            hmtxPPTasks = NULLHANDLE;
static LINKSEQ         lsPPTasks;


static VOID _taskFree(PDFPPTASK pTask)
{
  if ( pTask->pszSrc != NULL )
  {
    unlink( pTask->pszSrc );
    debugFree( pTask->pszSrc );
  }

  if ( pTask->pszBakupExt != NULL )
    debugFree( pTask->pszBakupExt );

  debugFree( pTask );
}

static ULONG _backupFileReplace(PSZ pszDest, PSZ pszSrc, PSZ pszBakupExt)
{
  struct stat          stStat;
  CHAR                 acBuf[_MAX_PATH];
  CHAR                 szDest[_MAX_PATH];

  if ( ( stat( pszSrc, &stStat ) == -1 ) || S_ISDIR( stStat.st_mode ) )
  {
    debug( "File does not exist: %s", pszSrc );
    return 1;
  }

  if ( strchr( pszDest, '\\' ) == NULL )
  {
    if ( _snprintf( &szDest, sizeof(szDest), "%s\\%s", pConfig->pszDataPath,
                    pszDest ) < 0 )
      return 1;
    pszDest = &szDest;
  }

  if ( pszBakupExt != NULL )
  {
    if ( utilSetExtension( sizeof(acBuf), &acBuf, pszDest, pszBakupExt ) == -1 )
    {
      debug( "File name is too long: %s", pszDest );
      return 1;
    }

    unlink( &acBuf );
    rename( pszDest, &acBuf );
  }
  else
    unlink( pszDest );

  return rename( pszSrc, pszDest ) == 0 ? 0 : 2; 
}


BOOL dfInit()
{
  if ( hmtxPPTasks != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxPPTasks, FALSE );
  if ( hmtxPPTasks == NULLHANDLE )
    return FALSE;

  lnkseqInit( &lsPPTasks );
  return TRUE;
}

VOID dfDone()
{
  if ( hmtxPPTasks == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  if ( dfExecPostpond( TRUE ) != 0 )
  {
    debug( "Not all of tasks have been executed." );
  }

  xplMutexDestroy( hmtxPPTasks );
  hmtxPPTasks = NULLHANDLE;
}

// LONG dfBackupGetName(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile, PSZ pszBakupExt)
//
// Writes file name pszFile to pcBuf. If the path is not specified -
// pConfig->pszDataPath will be inserted before the file name. If the resulting
// file does not exist, function checks the file with extension pszBakupExt
// exists and writes this name to pcBuf.
// Returns the number of characters written into pcBuf, not counting the
// terminating null character, or -1 if more than cbBuf or _MAX_PATH characters
// were requested to be generated or file (or file with backup-extension) does
// not exist. 

LONG dfBackupGetName(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile, PSZ pszBakupExt)
{
  CHAR                 szFile[_MAX_PATH];
  CHAR                 szBackupFile[_MAX_PATH];
  struct stat          stStat;
  LONG                 cbName = strlen( pszFile );

  if ( memchr( pszFile, '\\', cbName ) == NULL )
  {
    cbName = _snprintf( &szFile, sizeof(szFile), "%s\\%s", pConfig->pszDataPath,
                        pszFile );
    if ( cbName < 0 )
      return -1;
    pszFile = &szFile;
  }

  if ( ( stat( pszFile, &stStat ) == -1 ) || S_ISDIR( stStat.st_mode ) )
  {
    cbName = utilSetExtension( sizeof(szBackupFile), &szBackupFile, pszFile,
                               pszBakupExt );
    if ( ( cbName == -1 ) ||
         ( stat( pszFile, &stStat ) == -1 ) || S_ISDIR( stStat.st_mode ) )
    {
      log( 5, "[WARNING] The file does not exist and backup is not found:"
           " %s", &szFile );
      return -1;
    }
    pszFile = &szBackupFile;
    log( 4, "[WARNING] The backup file will be used: %s", &szFile );
  }

  if ( cbName < cbBuf )
  {
    strcpy( pcBuf, pszFile );
    return cbName;
  }

  return -1;
}

// FILE *dfBackupOpenFile(PSZ pszFile, PSZ pszBakupExt)
//
// Opens file pszFile or backup file for reading. Function dfBackupGetName()
// will be used to generate file name.
// Returns a pointer to the object controlling the stream or NULL if the open
// operation fails or file/backup-file does not exist.

FILE *dfBackupOpenFile(PSZ pszFile, PSZ pszBakupExt)
{
  CHAR       szFile[_MAX_PATH];
  FILE       *fd;

  if ( dfBackupGetName( sizeof(szFile), &szFile, pszFile, "bkp" ) == -1 )
    return FALSE;

  fd = fopen( &szFile, "r" );
  if ( fd == NULL )
  {
    log( 1, "[WARNING] Cannot open a file: %s", &szFile );
    return NULL;
  }

  return fd;
}

// LONG dfSetUniqueExtension(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile)
//
// Adds or replaces an extension in the file name with random hexadecimal
// value (three characters long). A new filename is different from that of any
// existing file. 
// Returns the number of characters written into pcBuf, not counting the
// terminating null character, or -1 if more than cbBuf characters were
// requested to be generated. 

LONG dfSetUniqueExtension(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile)
{
  LONG                 cbNewName;
  CHAR                 szExt[4];
  struct stat          stStat;
  CHAR                 szFile[_MAX_PATH];

  if ( strchr( pszFile, '\\' ) == NULL )
  {
    if ( _snprintf( &szFile, sizeof(szFile), "%s\\%s", pConfig->pszDataPath,
                    pszFile ) < 0 )
      return -1;
    pszFile = &szFile;
  }

  do
  {
    sprintf( szExt, "%0.3X", rand() & 0x0FFF );
    cbNewName = utilSetExtension( cbBuf, pcBuf, pszFile, szExt );
    if ( cbNewName == -1 )
      break;
  }
  while( stat( pcBuf, &stStat ) != -1 );

  return cbNewName;
}

// BOOL dfBackupFileReplace(PSZ pszDest, PSZ pszSrc, PSZ pszBakupExt,
//                          BOOL fPostpondAllowed)
//
// 1. Remove the detination file with base name from pszDest and extension
//    pszBakupExt (backup file) if pszBakupExt is NOT null or remove backup
//    file if pszBakupExt is null.
// 2. Rename the existing file pszDest to base name from pszDest and extension
//    pszBakupExt.
// 3. Rename or copy file pszSrc to pszDest.
//
// File names pszDest without a specified path will be complemented
// pConfig->pszDataPath. In the case where file pszSrc cannot be renamed/copied
// to pszDest (destination file was open by another process?) and
// fPostpondAllowed is TRUE, this task will be placed in a queue for later
// execution ( by calling dfExecPostpond() ).
//
// Using in programs for safe writing dynamic files with
// dfSetUniqueExtension():
//
// 1. Get unique filename from dfSetUniqueExtension():
//      D:\dir\MYFILE.EXT -> D:\dir\MYFILE.nnn
// 2. Create file MYFILE.nnn, store data and close file.
// 3. utilBackupFileReplace("D:\dir\MYFILE.EXT","D:\dir\MYFILE.nnn","BKP",?).

BOOL dfBackupFileReplace(PSZ pszDest, PSZ pszSrc, PSZ pszBakupExt,
                         BOOL fPostpondAllowed)
{
  PDFPPTASK            pTask;
  BOOL                 fRes = FALSE;

  xplMutexLock( hmtxPPTasks, XPL_INDEFINITE_WAIT );
  for( pTask = (PDFPPTASK)lnkseqGetFirst( &lsPPTasks ); pTask != NULL;
       pTask = (PDFPPTASK)lnkseqGetNext( pTask ) )
  {
    if ( stricmp( &pTask->szDest, pszDest ) == 0 )
    {
      lnkseqRemove( &lsPPTasks, pTask );
      _taskFree( pTask );
      break;
    }
  }

  switch( _backupFileReplace( pszDest, pszSrc, pszBakupExt ) )
  {
    case 0:            // Done.
      fRes = TRUE;
      break;

    case 2:            // Cannot be renamed/copied right now.
      if ( !fPostpondAllowed )
      {
        unlink( pszSrc );
        break;
      }

      // Put the task to the queue.

      pTask = debugMAlloc( sizeof(DFPPTASK) + strlen( pszDest ) );
      if ( pTask == NULL )
        break;

      pTask->pszSrc = debugStrDup( pszSrc );
      if ( pTask->pszSrc == NULL )
      {
        debugFree( pTask );
        break;
      }
      pTask->pszBakupExt = pszBakupExt == NULL ? NULL : debugStrDup( pszBakupExt );
      strcpy( &pTask->szDest, pszDest );
      lnkseqAdd( &lsPPTasks, pTask );
      fRes = TRUE;
  }

  xplMutexUnlock( hmtxPPTasks );
  return fRes;
}

// ULONG dfExecPostpond(BOOL fRemoveAll)
//
// Attempts to carry out the tasks which are placed in a queue by function
// dfBackupFileReplace(). If the task can not be completed now and fRemoveAll
// is TRUE, it will be removed from the queue (related temporary file will be
// deleted).

ULONG dfExecPostpond(BOOL fRemoveAll)
{
  PDFPPTASK            pTask, pNextTask;
  ULONG                ulRes;

  xplMutexLock( hmtxPPTasks, XPL_INDEFINITE_WAIT );

  pTask = (PDFPPTASK)lnkseqGetFirst( &lsPPTasks );
  while( pTask != NULL )
  {
    pNextTask = (PDFPPTASK)lnkseqGetNext( pTask );

    if ( ( _backupFileReplace( pTask->szDest, pTask->pszSrc,
                               pTask->pszBakupExt ) != 2 ) || fRemoveAll )
    {
      lnkseqRemove( &lsPPTasks, pTask );
      _taskFree( pTask );
    }

    pTask = pNextTask;
  }

  ulRes = lnkseqGetCount( &lsPPTasks );
  xplMutexUnlock( hmtxPPTasks );

  return ulRes;
}
