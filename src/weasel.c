#define INCL_DOSNMPIPES
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#define INCL_DOSMISC
#define INCL_DOSPROCESS
#include <os2.h>
#include <process.h>
#include <string.h>
#include <ctype.h>
#include "debug.h"
#include "config.h"
#include "log.h"
#include "requests.h"
#include "weasel.h"

#define _LOG_PIPE                "\\PIPE\\WeaselTransLog"
#define _PIPE_OPEN_DELAY         19000     // msec.
#define _LOG_BUF_SIZE            32768

static PCHAR           pcLogBuf = NULL;
static ULONG           ulBufPos = 0;
static HFILE           hPipe = NULLHANDLE;
static ULONG           ulOpenTime;
static BOOL            fScreen = FALSE;

BOOL weaselInit(BOOL fScreenOutput)
{
  if ( pcLogBuf != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  pcLogBuf = debugMAlloc( _LOG_BUF_SIZE );
  if ( pcLogBuf == NULL )
  {
    debug( "Not enough memory" );
    return FALSE;
  }
  ulBufPos = 0;
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulOpenTime, sizeof(ULONG) );
  fScreen = fScreenOutput;
  return TRUE;
}

VOID weaselDone()
{
  if ( pcLogBuf == NULL )
    // The module was not initialized.
    return;

  if ( hPipe != NULLHANDLE )
  {
    DosClose( hPipe );
    hPipe = NULLHANDLE;
  }

  debugFree( pcLogBuf );
  pcLogBuf = NULL;
}

VOID weaselListenLog()
{
  ULONG      ulRC;
  static ULONG ulLastRC = NO_ERROR;
  ULONG      ulTime;
  ULONG      ulActual;
  AVAILDATA  stAvail;
  ULONG      ulState;

  PCHAR      pcNextLine, pcEOL, pcBufEnd, pcLine;

  if ( pcLogBuf == NULL )
    // The module was not initialized.
    return;

  if ( hPipe == NULLHANDLE )
  {
    // The pipe was not open.

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    if ( ( (ulOpenTime - ulTime) & 0x80000000 ) == 0 )
      return;

    // Try to open pipe...
    ulRC = DosOpen( _LOG_PIPE, &hPipe, &ulActual, 0, FILE_NORMAL,
                    OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                    OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                    OPEN_FLAGS_NOINHERIT | OPEN_SHARE_DENYNONE |
                    OPEN_ACCESS_READONLY, NULL );
    if ( ulRC != NO_ERROR )
    {
      hPipe = NULLHANDLE;
      ulOpenTime = ulTime + _PIPE_OPEN_DELAY; // Next open try time.

      if ( ulRC == ERROR_PIPE_BUSY )
        log( 5, "[WARNING] Weasel log pipe is busy. Open attempt postponed." );
      else if ( ulLastRC != ulRC ) // Do not repeat this message.
        log( 5, "[WARNING] Weasel log pipe open error %u.", ulRC );

      ulLastRC = ulRC;
      return;
    }
    log( 5, "[INFO] Weasel log pipe is open." );
    ulLastRC = NO_ERROR;
  }

  while( TRUE )
  {
    // Check input data to be available.

    ulRC = DosPeekNPipe( hPipe, &pcEOL, sizeof(pcEOL), &ulActual,
                         &stAvail, &ulState );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosPeekNPipe(), rc = %u", ulRC );
      break;
    }
    if ( ulActual == 0 )
      // No new data in pipe.
      break;

    // Read data from the pipe.

    ulRC = DosRead( hPipe, &pcLogBuf[ulBufPos], _LOG_BUF_SIZE - ulBufPos,
                    &ulActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosRead(), rc = %u", ulRC );
      break;
    }
    ulBufPos += ulActual; // ulPos - next buffer write position;

    // Parse data. Scan all received lines.

    pcBufEnd = &pcLogBuf[ulBufPos];
    pcLine = pcLogBuf;
    while( TRUE )
    {
      ulBufPos = pcBufEnd - pcLine;
      pcNextLine = memchr( pcLine, '\n', ulBufPos );
      if ( pcNextLine == NULL )
      {
        // LF not found.
        if ( ulBufPos == _LOG_BUF_SIZE )
          // Too long line.
          ulBufPos = 0;
        else
          memcpy( pcLogBuf, pcLine, ulBufPos );
        break;
      }
      // We have a line ended with LF.
      pcEOL = pcNextLine;
      pcNextLine++;
      // Removes trailing CR, TABs and spaces.
      while ( ( pcEOL > pcLine ) && isspace( *(pcEOL-1) ) )
        pcEOL--;
      *pcEOL = '\0';

      if ( fScreen )
        puts( pcLine );

      if ( (pcEOL - pcLine) > 20 ) // Enough length of line.
      {
        // Search a string like "2016-01-19 09:36:05 S    57  End of session"

        if ( pcLine[20] == 'S' ) // SMTP log record.
        {
          PCHAR  pcSessId = &pcLine[21];
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
            do { pcPos++; }
            while( isspace( *pcPos ) );

            if ( strcmp( pcPos, "End of session" ) == 0 )
            {
              // We have "End of session" record and session Id.

              log( 5, "[INFO] Weasel log pipe: End of session %s.", pcSessId );
              reqCloseSession( pcSessId );
            }
          }
        }
      } // if ( (pcEOL - pcLogBuf) > 20 )


      // Go to next line in the buffer.
      pcLine = pcNextLine;
    }
  }

  if ( ulRC != NO_ERROR )
  {
    // On error - close the pipe and set timeout for next pipe open trying.
    if ( hPipe != NULLHANDLE )
    {
      DosClose( hPipe );
      hPipe = NULLHANDLE;
    }

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    ulOpenTime = ulTime + _PIPE_OPEN_DELAY;
  }
}
