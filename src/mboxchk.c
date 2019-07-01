#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "xpl.h"
#include "util.h"
#include "sockets.h"
#include "config.h"
#include "hmem.h"
#define MBOXCHK_C
#include "mboxchk.h"
#include "debug.h"     // Must be the last.

PSZ apszMBCResult[10] = {
  "Exist",                                 // MBC_OK
  "Does not exist",                        // MBC_DONE_NOT_EXIST
  "Postmaster does not exist",             // MBC_DONE_NO_POSTMASTER
  "MTA responds OK for any mailbox",       // MBC_DONE_FAKE_CHECK
  "Failed",                                // MBC_FAIL (generic error)
  "Connection failed",                     // MBC_CONN_FAIL
  "Connection timed out",                  // MBC_CONN_TIMEOUT
  "Connection refused",                    // MBC_CONN_REFUSED
  "Network is unreachable",                // MBC_NETUNREACH
  "No buffer space available"              // MBC_NOBUFS
};


typedef struct _DYNBUF {
  ULONG      ulSize;
  ULONG      ulFill;
  PCHAR      pcData;

  ULONG      ulReadPos;
} DYNBUF, *PDYNBUF;

#define _dynbufAvail(pdb) ( (pdb)->ulSize - (pdb)->ulFill )
#define _dynbufWritePtr(pdb) &(pdb)->pcData[ (pdb)->ulFill ]
#define _dynbufMovePtr(pdb,bytes) (pdb)->ulFill += bytes
#define _dynbufRWReset(pdb) do { \
  (pdb)->ulFill = 0; (pdb)->ulReadPos = 0; } while( FALSE )
#define _dynbufRReset(pdb) (pdb)->ulReadPos = 0;

static BOOL _dynbufInit(PDYNBUF pDynBuf, ULONG ulSize)
{
  pDynBuf->ulFill = 0;
  pDynBuf->ulSize = ulSize;
  pDynBuf->pcData = hmalloc( ulSize );
  pDynBuf->ulReadPos = 0;

  return pDynBuf->pcData != NULL;
}

static VOID _dynbufDone(PDYNBUF pDynBuf)
{
  if ( pDynBuf->pcData != NULL )
    hfree( pDynBuf->pcData );
}

static BOOL _dynbufExpand(PDYNBUF pDynBuf, ULONG ulSize)
{
  PCHAR      pcData = hrealloc( pDynBuf->pcData, pDynBuf->ulSize + ulSize );

  if ( pcData == NULL )
    return FALSE;

  pDynBuf->ulSize += ulSize;
  pDynBuf->pcData = pcData;
  return TRUE;
}

static PCHAR _dynbufReadLine(PDYNBUF pDynBuf, PULONG pcbLine)
{
  PCHAR      pcLine = &pDynBuf->pcData[pDynBuf->ulReadPos];
  PCHAR      pcEnd = memchr( pcLine, '\n', pDynBuf->ulFill - pDynBuf->ulReadPos );
  ULONG      cbLine;

  if ( pcEnd == NULL )
    return NULL;

  cbLine = ( pcEnd - pcLine ) + 1;
  pDynBuf->ulReadPos += cbLine;
  *pcbLine = cbLine;
  return pcLine;
}


static ULONG _readSMTPResp(int iSock, PDYNBUF pDynBuf)
{
  int        cBytes;
  ULONG      cbLine;
  PCHAR      pcLine;

  _dynbufRWReset( pDynBuf );

  while( TRUE )
  {
    if ( _dynbufAvail( pDynBuf ) < 64 ) 
    {
      if ( pDynBuf->ulSize >= 65535 )
      {
        debug( "The response is too long" );
        return 0;
      }

      if ( !_dynbufExpand( pDynBuf, 256 ) )
      {
        debug( "Not enough memory" );
        return 0;
      }
    }

    cBytes = recv( iSock, _dynbufWritePtr( pDynBuf ), _dynbufAvail( pDynBuf ), 0 );
    if ( cBytes < 0 )
    {
      debug( "recv() failed, error %u", xplSockError() );
      return 0;
    }
//debug( "Received: \"%s\"", debugBufPSZ( _dynbufWritePtr( pDynBuf ), cBytes ) );
    _dynbufMovePtr( pDynBuf, cBytes );

    while( ( pcLine = _dynbufReadLine( pDynBuf, &cbLine ) ) != NULL )
    {
//debug( "Line: \"%s\"", debugBufPSZ( pcLine, cbLine ) );
      if ( ( cbLine < 3 ) ||
           ( cbLine > 3 && pcLine[3] != ' ' && pcLine[3] != '-' ) ||
           !isdigit( pcLine[0] ) || !isdigit( pcLine[1] ) ||
           !isdigit( pcLine[2] ) ||
           (
             ( pDynBuf->pcData != pcLine ) &&
             ( pcLine[0] != pDynBuf->pcData[0] ||
               pcLine[1] != pDynBuf->pcData[1] ||
               pcLine[2] != pDynBuf->pcData[2] )
           ) )
      {
        debug( "Invalid response line: %s", debugBufPSZ( pcLine, cbLine ) );
        return 0;
      }

      if ( ( cbLine == 3 ) || ( pcLine[3] == ' ' ) )
      {
        ULONG          ulResp;

        _dynbufRReset( pDynBuf );
        return utilStrToULong( 3, pcLine, 100, 999, &ulResp ) ? ulResp : 0;
      }
    }
  }
}

static ULONG _sendSMTPCmd(int iSock, PDYNBUF pDynBuf, PSZ pszMsg)
{
  ULONG      ulRC;

//debug( "Send: %s", pszMsg );
  if ( send( iSock, pszMsg, strlen( pszMsg ), 0 ) == -1 )
  {
    debug( "send() failed" );
    return 0;
  }

  ulRC = _readSMTPResp( iSock, pDynBuf );
/*
  if ( ulRC != 0 )
    debug( "Response: %s", debugBufPSZ( pDynBuf->pcData, pDynBuf->ulFill ) );
*/

  return ulRC;
}

static ULONG _connect(struct in_addr stServer, USHORT usPort, ULONG ulTimeout,
                      int *piSock)
{
  struct sockaddr_in   stSockAddr;
  int                  iRC = 1;
  int                  iSock = socketNew( TRUE );
  int                  iLen = sizeof( iRC );

  if ( iSock == -1 )
  {
    debug( "socketNew() failed" );
    return MBC_FAIL;
  }

  // Set socket to nonblocking I/O mode.
  xplSockIOCtl( iSock, FIONBIO, &iRC );

  stSockAddr.sin_len    = sizeof(stSockAddr);
  stSockAddr.sin_family = AF_INET;
  stSockAddr.sin_port   = htons( usPort );
  stSockAddr.sin_addr   = stServer;
  debug( "Connect to %s:%u", inet_ntoa( stServer ), usPort );

  if ( connect( iSock, (struct sockaddr *)&stSockAddr,
                sizeof(struct sockaddr_in) ) == 0 )
  {
    iRC = 0;
    xplSockIOCtl( iSock, FIONBIO, &iRC );
    debug( "Connected to %s:%u", inet_ntoa( stServer ), usPort );
    *piSock = iSock;
    return MBC_OK;
  }

  iRC = xplSockError();
  if ( iRC != SOCEINPROGRESS )
  {
    debug(, "Connection failed on connect(), error %d", iRC );
    iRC = MBC_CONN_FAIL;
  }
  else
  {
    struct timeval     stTimeVal;
    fd_set             fdsRead, fdsWrite;

    FD_ZERO( &fdsRead );
    FD_ZERO( &fdsWrite );
    FD_SET( iSock, &fdsRead );
    FD_SET( iSock, &fdsWrite );

    // Set timeout for connecting.
    stTimeVal.tv_sec  = ulTimeout;         // Seconds.
    stTimeVal.tv_usec = 0;

    iRC = select( iSock + 1, &fdsRead, &fdsWrite, NULL, &stTimeVal );
    if ( iRC < 0 )
    {    
      debug( "Connection failed on select(), error %d", xplSockError() );
      iRC = MBC_CONN_FAIL;
    }
    else if ( ( iRC == 0 ) ||
              ( !FD_ISSET(iSock, &fdsRead) && !FD_ISSET(iSock, &fdsWrite) ) )
    {
      debug( "Connection to %s:%u timed out", inet_ntoa( stServer ), usPort );
      iRC = MBC_CONN_TIMEOUT;
    }
    else if ( getsockopt( iSock, SOL_SOCKET, SO_ERROR, (PCHAR)&iRC, &iLen ) < 0 )
    {
      debug( "Connection failed on getsockopt(), error %d", xplSockError() );
      iRC = MBC_CONN_FAIL;
    }
    else if ( iRC != 0 )
    {
      debug( "Cannot connect to %s:%u, error %d", inet_ntoa( stServer ),
             usPort, iRC );

      switch( iRC )
      {
        case SOCECONNREFUSED:
          iRC = MBC_CONN_REFUSED;
          break;

        case SOCENETUNREACH:
          iRC = MBC_NETUNREACH;
          break;

        case SOCENOBUFS:
          iRC = MBC_NOBUFS;
          break;

        default:
          iRC = MBC_CONN_FAIL;
      }
    }
    else     // iRC == 0
    {
      debug( "Connected to %s:%u", inet_ntoa( stServer ), usPort );
      *piSock = iSock;
      iRC = MBC_OK;
    }
  }

  // Set socket to blocking I/O mode.
  iLen = 0;
  xplSockIOCtl( iSock, FIONBIO, &iLen );

  if ( iRC != MBC_OK )
    socketDestroy( iSock );

  return iRC;
}


// ULONG MailBoxCheck(struct in_addr stServer, PSZ pszMailAddr)
//
// Check mail box pszMailAddr on the SMTP server stServer.
// Returns MBC_xxxxx error code.

ULONG MailBoxCheck(struct in_addr stServer, USHORT usPort, PSZ pszMailAddr,
                   BOOL fFullCheck)
{
  int                  iSock;
  CHAR                 acBuf[264];
  struct timeval       stTimeVal;
  ULONG                ulRC = _connect( stServer, (usPort == 0 ? 25 : usPort),
                                        3, &iSock );
  DYNBUF               stDynBuf;

  if ( ulRC != MBC_OK )
    return ulRC;

  debug( "Connected to %s:25", inet_ntoa( stServer ) );

  // Set timeout for recv().
  stTimeVal.tv_sec  = 15;        // Seconds.
  stTimeVal.tv_usec = 0;
  if ( setsockopt( iSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&stTimeVal,
                   sizeof(struct timeval) ) < 0 )
  {
    debug( "setsockopt() failed, error: %u", sock_errno() );
  }

  if ( !_dynbufInit( &stDynBuf, 128 ) )
  {
    socketDestroy( iSock );
    return MBC_FAIL;
  }

  _bprintf( &acBuf, sizeof(acBuf), "HELO %s\r\n", pConfig->pszMailServerName );
  if ( _readSMTPResp( iSock, &stDynBuf ) != 220 ||
       _sendSMTPCmd( iSock, &stDynBuf, &acBuf ) != 250 ||
       _sendSMTPCmd( iSock, &stDynBuf, "MAIL FROM:<>\r\n" ) != 250 )
  {
    ulRC = MBC_FAIL;
  }
  else
  {
    _bprintf( &acBuf, sizeof(acBuf), "RCPT TO:<%s>\r\n", pszMailAddr );
    ulRC = _sendSMTPCmd( iSock, &stDynBuf, &acBuf );

    if ( ulRC != 250 )
      ulRC = MBC_DONE_NOT_EXIST;
    else if ( !fFullCheck )
      ulRC = MBC_OK;
    else
    {
      PCHAR            pcAt = strchr( pszMailAddr, '@' );

      if ( pcAt == NULL )
      {
        debug( "Invalid e-mail address: %s", pszMailAddr );
        ulRC = MBC_FAIL;
      }
      else 
      {
        _bprintf( &acBuf[9], sizeof(acBuf) - 9, "postmaster%s>\r\n", pcAt );
        if ( ( memcmp( pszMailAddr, "postmaster@", 11 ) != 0 ) &&
             ( _sendSMTPCmd( iSock, &stDynBuf, &acBuf ) != 250 ) )
          ulRC = MBC_DONE_NO_POSTMASTER;
        else
        {
          _bprintf( &acBuf[9], sizeof(acBuf) - 9, "%x%x%s>\r\n",
                    pszMailAddr, iSock, pcAt );
          debug( "Check fake mailbox, %s", &acBuf );
          ulRC = _sendSMTPCmd( iSock, &stDynBuf, &acBuf ) == 250
                  ? MBC_DONE_FAKE_CHECK : MBC_OK;
        }
      }
    }
  }

  _dynbufDone( &stDynBuf );
  socketDestroy( iSock );
  return ulRC;
}
