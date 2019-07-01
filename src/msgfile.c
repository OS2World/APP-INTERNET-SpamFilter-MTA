#include <ctype.h>
#include <string.h>
#include "util.h"
#include "dns.h"
#include "log.h"
#include "mcodec.h"
#include "config.h"
#include "hmem.h"
#include "msgfile.h"
#include "debug.h"     // Must be the last.

#define _MF_FILE_END             0
#define _MF_PART_DIV             1
#define _MF_PART_END             2
#define _MF_LINE                 3

#define _MF_LINE_BUF_SIZE        2048


typedef struct _MFFIELD {
  SEQOBJ     seqObj;
  ULONG      cbValue;
  PSZ        pszValue;
  CHAR       acName[1];
} MFFIELD, *PMFFIELD;

struct _MFSCAN {
  PADDRLIST  pAddrList;
  FILE       *fd;
  CHAR       acBuf[_MF_LINE_BUF_SIZE];
};


static VOID _fieldFree(PMFFIELD pField)
{
  if ( pField->pszValue != NULL )
    hfree( pField->pszValue );

  hfree( pField );
}

static VOID _hdrFree(PLINKSEQ plsFields)
{
  lnkseqFree( plsFields, PMFFIELD, _fieldFree );
}

static BOOL _hdrRead(FILE *fd, PLINKSEQ plsFields)
{
  CHAR       acBuf[2048];
  PMFFIELD   pField = NULL;
  PCHAR      pcValue;
  ULONG      cbValue;
  PSZ        pszValue;
  BOOL       fEndOfHeader;

  acBuf[ sizeof(acBuf) - 1 ] = '\0';
  while( TRUE )
  {
    fEndOfHeader = ( fgets( &acBuf, sizeof(acBuf) - 1, fd ) == NULL ) ||
                   ( acBuf[0] == '\n' );
    if ( fEndOfHeader )
      break;

    if ( isspace( acBuf[0] ) )
    {
      if ( pField == NULL )
      {
        debug( "Invalid message file format" );
        break;
      }

      pcValue = &acBuf;
    }
    else
    {
      PCHAR            pcNameEnd;

      pcValue = strchr( &acBuf, ':' );
      if ( pcValue == NULL )
      {
        debug( "Column not found: \"%s\"", &acBuf );
        break;
      }

      pcNameEnd = pcValue;
      while( ( pcNameEnd > &acBuf ) && isspace( *(pcNameEnd - 1) ) )
        pcNameEnd--;
      pcValue++;

      if ( pcNameEnd == &acBuf )
      {
        debug( "Empty field name: \"%s\"", &acBuf );
        break;
      }
      *pcNameEnd = '\0';

      pField = hmalloc( sizeof(MFFIELD) + strlen( &acBuf ) );
      if ( pField == NULL )
      {
        debug( "Not enough memory" );
        break;
      }

      pField->pszValue = NULL;
      pField->cbValue = 0;
      strcpy( &pField->acName, &acBuf );
      lnkseqAdd( plsFields, pField );
    }

    cbValue = strlen( pcValue );
    pszValue = hrealloc( pField->pszValue, pField->cbValue + cbValue + 1 );
    if ( pszValue == NULL )
    {
      debug( "Not enough memory" );
      break;
    }
    pField->pszValue = pszValue;
    strcpy( &pszValue[pField->cbValue], pcValue );
    pField->cbValue += cbValue;
  }

  if ( !fEndOfHeader )
  {
    _hdrFree( plsFields );
    return FALSE;
  }

  return TRUE;
}

static PMFFIELD _hdrFind(PLINKSEQ plsFields, PSZ pszField)
{
  PMFFIELD   pField;

  for( pField = (PMFFIELD)lnkseqGetFirst( plsFields );
       pField != NULL; pField = (PMFFIELD)lnkseqGetNext( pField ) )
  {
    if ( stricmp( &pField->acName, pszField ) == 0 )
      break;
  }

  return pField;
}

static ULONG _readLine(struct _MFSCAN *pScan, ULONG cbBoundary,
                       PCHAR pcBoundary)
{
  if ( ( fgets( &pScan->acBuf, _MF_LINE_BUF_SIZE - 1, pScan->fd ) == NULL ) ||
       ( ftell( pScan->fd ) > pConfig->ulMaxMessage ) )
    return _MF_FILE_END;

  if ( ( pcBoundary != NULL ) && ( *((PUSHORT)pScan->acBuf) == (USHORT)'--' ) &&
       ( memcmp( &pScan->acBuf[2], pcBoundary, cbBoundary ) == 0 ) )
  {
    if ( *((PUSHORT)&pScan->acBuf[cbBoundary+2]) == (USHORT)'\0\n' )
      return _MF_PART_DIV;

    else if ( *((PULONG)&pScan->acBuf[cbBoundary+2]) == (ULONG)'\0\n--' )
      return _MF_PART_END;
  }

  return _MF_LINE;
}

static BOOL _fnHostStore(ULONG cbAddr, PCHAR pcAddr, PVOID pData)
{
  CHAR       acBuf[256];
  ULONG      cbBuf;
  PCHAR      pcEnd = &pcAddr[cbAddr];
  
  pcAddr = memchr( pcAddr, '/', cbAddr );
  if ( ( pcAddr == NULL ) || ( (pcEnd - pcAddr) < 2 ) || ( pcAddr[1] != '/' ) )
  {
    debug( "Prefix ???:// not found" );
    return TRUE;
  }
  pcAddr += 2;
  cbAddr = pcEnd - pcAddr;

  if ( cfgIsMatchPtrnList( pConfig->cbLocalDomains, pConfig->pcLocalDomains,
                           cbAddr, pcAddr ) ||
       cfgIsMatchPtrnList( pConfig->cbURIBLNotSpam, pConfig->pcURIBLNotSpam,
                           cbAddr, pcAddr ) )
  {
    debug( "Ignore: %s", debugBufPSZ( pcAddr, cbAddr ) );
    return TRUE;
  }

  cbBuf = min( sizeof(acBuf) - 1, cbAddr );
  memcpy( &acBuf, pcAddr, cbBuf );
  acBuf[cbBuf] = '\0';

  debug( "Name found: %s", &acBuf );
  return pData == NULL
           ? TRUE
           : addrlstAdd( (PADDRLIST)pData, &acBuf, pConfig->ulSpamURIHostTTL );
}

static ULONG _scanPart(struct _MFSCAN *pScan, PLINKSEQ plsFields,
                       ULONG cbBoundary, PCHAR pcBoundary)
{
  ULONG      ulRC;
  PMFFIELD   pField = _hdrFind( plsFields, "Content-Type" );
  PSZ        pszValue;
  BOOL       fScan = FALSE;

  if ( pField != NULL )
  {
    pszValue = pField->pszValue;

    STR_SKIP_SPACES( pszValue );
    if ( memicmp( pszValue, "multipart/", 10 ) == 0 )
    {
      // Multipart message.

      LINKSEQ          lsFields;
      PCHAR            pcLocBndr = utilStrNewGetOption( strlen( pszValue ),
                                                        pszValue, "boundary" );

      if ( pcLocBndr != NULL )
      {
        ULONG          cbLocBndr = strlen( pcLocBndr );

        do {
          ulRC = _readLine( pScan, cbLocBndr, pcLocBndr );
        } while( ulRC == _MF_LINE );

        lnkseqInit( &lsFields );
        while( ulRC == _MF_PART_DIV )
        {
          if ( !_hdrRead( pScan->fd, &lsFields ) )
            break;

          ulRC = _scanPart( pScan, &lsFields, cbLocBndr, pcLocBndr );
          _hdrFree( &lsFields );
        }

        hfree( pcLocBndr );
        if ( ulRC != _MF_PART_END )
          return ulRC; // EOF

      } // if ( pcLocBndr != NULL )
    } // multipart/...
    else if ( memicmp( pszValue, "message/rfc822", 14 ) == 0 )
    {
      // Attached message.

      LINKSEQ          lsFields;

      // After the part's header follows the header of the attached message.
      lnkseqInit( &lsFields );
      if ( _hdrRead( pScan->fd, &lsFields ) )
      {
        ulRC = _scanPart( pScan, &lsFields, cbBoundary, pcBoundary );
        _hdrFree( &lsFields );
      }
    }
    else
      fScan = memcmp( pszValue, "text/", 5 ) == 0;

  } // if ( pField != NULL )

  if ( fScan && ( pConfig->ulMaxBodyPart > 8 ) )
  {
    // Scan part content (Content-Type: text/...).

    CODEC    stCodec;

    pField = _hdrFind( plsFields, "Content-Transfer-Encoding" );
    pszValue = pField == NULL ? "" : pField->pszValue;
    STR_SKIP_SPACES( pszValue );

    if ( codecInit( &stCodec,
                    stricmp( pszValue, "base64\n" ) == 0
                      ? CODEC_DEC_BASE64
                      : stricmp( pszValue, "quoted-printable\n" ) == 0
                        ? CODEC_DEC_QUOTED_PRINTABLE : CODEC_ENC_DEC_8BIT ) )
    {
      // Read and decode part body.

      PCHAR  pcTDecBuf = hmalloc( pConfig->ulMaxBodyPart );
             // ^^^ Memory block for the decoded content.
      PCHAR  pcTDecPos;
      ULONG  ulTDecLeft;
      ULONG  ulBufLeft;
      PCHAR  pcBufPos;

      if ( pcTDecBuf == NULL )
        log( 1, "[ERROR] Cannot allocate memory to check the message." );

      ulTDecLeft = pConfig->ulMaxBodyPart - 1;
      pcTDecPos = pcTDecBuf;
      while( TRUE )
      {
        ulRC = _readLine( pScan, cbBoundary, pcBoundary );
        if ( ulRC != _MF_LINE )
          break;

        ulBufLeft = strlen( &pScan->acBuf );
        if ( ( ulTDecLeft > 0 ) && ( pcTDecBuf != NULL ) )
        {
          pcBufPos = &pScan->acBuf;
          codecConv( &stCodec, &pcTDecPos, &ulTDecLeft, &pcBufPos, &ulBufLeft );
        }
      }

      if ( pcTDecBuf != NULL )
      {
        // Search host addresses in the decoded content.

        utilStrFindURIHosts( pcTDecPos - pcTDecBuf, pcTDecBuf,
                             _fnHostStore, (PVOID)pScan->pAddrList );
        hfree( pcTDecBuf );
      }

      // Part is readed.
    }
    else
    {
      debug( "codecInit(,\"%s\") failed", pszValue );
      // Cannot decode the part - skip it.
      fScan = FALSE;
    }
  }

  // Read message up to the next boundary or EOF.
  if ( !fScan )
    do {
      ulRC = _readLine( pScan, cbBoundary, pcBoundary );
    } while( ulRC == _MF_LINE );

  return ulRC;
}


PMSGFILE mfOpen(PSZ pszFile)
{
  PMSGFILE   pFile = hmalloc( sizeof(MSGFILE) );

  if ( pFile == NULL )
  {
    debug( "Not enough memory" );
    return NULL;
  }

  pFile->fd = fopen( pszFile, "r" );
  if ( pFile->fd == NULL )
  {
    hfree( pFile );
    debug( "Cannot open file: %s", pszFile );
    return NULL;
  } 

  lnkseqInit( &pFile->lsFields );
  if ( !_hdrRead( pFile->fd, &pFile->lsFields ) )
  {
    fclose( pFile->fd );
    hfree( pFile );
    return NULL;
  } 
  pFile->ulBodyStart = ftell( pFile->fd );

  return pFile;
}

VOID mfClose(PMSGFILE pFile)
{
  fclose( pFile->fd );
  _hdrFree( &pFile->lsFields );
  hfree( pFile );
}

VOID mfSetHeader(PMSGFILE pFile, PSZ pszField, PSZ pszValue)
{
#define _MAX_LINE      77
  ULONG                cbField = strlen( pszField );
  PMFFIELD             pField = hmalloc( sizeof(MFFIELD) + cbField );
  ULONG                ulLineLeft = _MAX_LINE - cbField - 1; // -1 - ':'
  ULONG                cbItem, ulAddLen;
  PCHAR                pcItemEnd;
  BOOL                 fNeedSemcol = FALSE, fNeedLF = FALSE;
  PSZ                  pszNewVal;

  pField->cbValue = 0;
  pField->pszValue = NULL;
  strcpy( &pField->acName, pszField );
  lnkseqAdd( &pFile->lsFields, pField );

  while( TRUE )
  {
    STR_SKIP_SPACES( pszValue );
    if ( *pszValue == '\0' )
      break;

    pcItemEnd = strchr( pszValue, ';' );
    if ( pcItemEnd == NULL )
      pcItemEnd = strchr( pszValue, '\0' );
    cbItem = pcItemEnd - pszValue;

    ulAddLen = cbItem + 1;       // +1 - SPACE
    if ( pField->cbValue != 0 )  // Not first item.
    {
      fNeedSemcol = TRUE;        // Need leading ';'.
      ulAddLen++;                
      fNeedLF = ulAddLen >= ulLineLeft;    // LF after leading ';'.
      if ( fNeedLF )
      {
        ulAddLen++;
        ulLineLeft = _MAX_LINE - ( cbItem + 1 );
      }
    }

    pszNewVal = hrealloc( pField->pszValue, pField->cbValue + ulAddLen + 1 );
    if ( pszNewVal == NULL )
    {
      debug( "Not enough memory" );
      break;
    }
    pField->pszValue = pszNewVal;
    pszNewVal = &pszNewVal[pField->cbValue];

    if ( fNeedSemcol )
    {
      *pszNewVal = ';';
      pszNewVal++;
    }
    if ( fNeedLF )
    {
      *pszNewVal = '\n';
      pszNewVal++;
    }
    else
      ulLineLeft -= ( cbItem + 2 );
    *pszNewVal = ' ';
    pszNewVal++;
    memcpy( pszNewVal, pszValue, cbItem );
    pszNewVal[cbItem] = '\0';
    pField->cbValue += ulAddLen;

    pszValue += cbItem;
    if ( *pszValue == ';' )
      pszValue++;
  }
}

VOID mfScanBody(PMSGFILE pFile, PADDRLIST pList)
{
  struct _MFSCAN       stScan;

  stScan.pAddrList = pList;
  stScan.fd = pFile->fd;
  stScan.acBuf[_MF_LINE_BUF_SIZE - 1] = '\0';

  fseek( pFile->fd, pFile->ulBodyStart, SEEK_SET ); 
  _scanPart( &stScan, &pFile->lsFields, 0, NULL );
}

BOOL mfStore(PMSGFILE pFile, PSZ pszFile)
{
  FILE                 *fd = fopen( pszFile, "wt" );
  PMFFIELD             pField;
  CHAR                 acBuf[2048];

  if ( fd == NULL )
  {
    log( 1, "[ERROR] File create failed: %s\n", pszFile );
    return FALSE;
  }

  // Write header to the new file.

  for( pField = (PMFFIELD)lnkseqGetFirst( &pFile->lsFields );
       pField != NULL; pField = (PMFFIELD)lnkseqGetNext( pField ) )
  {
    fputs( &pField->acName, fd );
    fputc( ':', fd );
    fputs( pField->pszValue, fd );
    if ( ( pField->cbValue > 1 ) &&
         ( pField->pszValue[pField->cbValue - 1] != '\n' ) )
      fputs( "\n", fd );
  }
  fputs( "\n", fd );

  // Copy message body.

  fseek( pFile->fd, pFile->ulBodyStart, SEEK_SET ); 
  while( fgets( &acBuf, sizeof(acBuf) - 1, pFile->fd ) != NULL )
  {
    if ( fputs( &acBuf, fd ) == EOF ) // Write line to the new file.
    {
      fclose( fd );
      unlink( pszFile );
      log( 1, "[ERROR] File write error: %s\n", pszFile );
      return FALSE;
    }
  }

  fclose( fd );
  return TRUE;
}


// BOOL mfGetOutsideHost(PMSGFILE pFile, struct in_addr *pInAddr)
//
// Scans fields "Received" up to first host after all relay hosts listed in the
// configuration. Found host IP-address will be stored in pInAddr.
// Returns FALSE if host behind our relays not found.

/*
received    =  "Received"    ":"            ; one per relay
                       ["from" domain]           ; sending host
                       ["by"   domain]           ; receiving host
                       ["via"  atom]             ; physical path
                      *("with" atom)             ; link/mail protocol
                       ["id"   msg-id]           ; receiver msg id
                       ["for"  addr-spec]        ; initial form

Received: by srv.bla-bla123.ru; Mon, 04 Dec 2016 02:47:12 +1100
Received: from some.dom.ru (bla-bla [192.168.1.2]) by hst.dom.ru with SMTP;
          Mon, 04 Dec 2016 02:46:26 +1100
Received: from unknown (HELO myhost) (192.168.103.44) by some.dom.ru with SMTP;
*/

static BOOL _isNotRelay(ULONG cbHost, PCHAR pcHost, struct in_addr *pInAddr)
{
  ULONG                cNSRes;
  CHAR                 acBuf[512];
  ULONG                ulRC;
  CHAR                 szAddr[256];

  if ( ( cbHost == 0 ) || ( pcHost == NULL ) )
    return FALSE;

  if ( pcHost[0] == '[' && pcHost[cbHost - 1] == ']' )
  {
    pcHost++;
    cbHost -= 2;
  }

  if ( BUF_STR_IEQ( cbHost, pcHost, pConfig->pszMailServerName ) ||
       cfgHostListCheckName( &pConfig->lsHostListRelays, cbHost, pcHost,
                             NULL ) )
    return FALSE;

  if ( utilStrToInAddr( cbHost, pcHost, pInAddr ) )
    return TRUE;

  // Given name is a host name, not ip-address.

  if ( cbHost >= sizeof(szAddr) )
    return FALSE;
  memcpy( &szAddr, pcHost, cbHost );
  szAddr[cbHost] = '\0';

  // Request to the DNS server.
  ulRC = dnsRequest( DNSREC_TYPE_A, &szAddr, sizeof(acBuf), &acBuf, &cNSRes );
  if ( ( ulRC != DNS_NOERROR ) || ( cNSRes == 0 ) ||
       cfgHostListCheckIP( &pConfig->lsHostListRelays,
                           *(struct in_addr *)&acBuf, NULL ) )
    return FALSE;

  *pInAddr = *(struct in_addr *)&acBuf;
  return TRUE;
}

BOOL mfGetOutsideHost(PMSGFILE pFile, struct in_addr *pInAddr,
                      ULONG cbHostName, PCHAR pcHostName)
{
  PMFFIELD             pField;
  ULONG                cbText, cbWord, cbFromHost, cbByHost;
  PCHAR                pcText, pcWord, pcFromHost, pcByHost;

  for( pField = (PMFFIELD)lnkseqGetFirst( &pFile->lsFields );
       pField != NULL; pField = (PMFFIELD)lnkseqGetNext( pField ) )
  {
    if ( stricmp( &pField->acName, "Received" ) != 0 )
      continue;

    // Parse field value.

    cbText = pField->cbValue;
    pcText = pField->pszValue;

    cbFromHost = 0;
    pcFromHost = NULL;
    cbByHost = 0;
    pcByHost = NULL;

    while( utilStrCutWord( &cbText, &pcText, &cbWord, &pcWord ) )
    {
      if (
           ( ( cbFromHost == 0 ) &&
             ( cbWord == 4 ) && ( *((PULONG)pcWord) == (ULONG)'morf' ) &&
             !utilStrCutWord( &cbText, &pcText, &cbFromHost, &pcFromHost ) )
         ||
           ( ( cbByHost == 0 ) &&
             ( cbWord == 2 ) && ( *((PUSHORT)pcWord) == (USHORT)'yb' ) &&
             !utilStrCutWord( &cbText, &pcText, &cbByHost, &pcByHost ) )
         ||
           ( ( cbFromHost != 0 ) && ( cbByHost != 0 ) )
         )
        break;
    }

    if ( _isNotRelay( cbByHost, pcByHost, pInAddr ) )
    {
      cbFromHost = cbByHost;
      pcFromHost = pcByHost;
    }
    else if ( !_isNotRelay( cbFromHost, pcFromHost, pInAddr ) )
      continue;

    if ( !utilStrToInAddr( cbFromHost, pcFromHost, NULL ) &&
         ( cbFromHost < cbHostName ) )
      // We have found host symbolic name.
      memcpy( pcHostName, pcFromHost, cbFromHost );
    else
      // We have found host ip-address - do not return name as IP to user.
      cbFromHost = 0;

    pcHostName[cbFromHost] = '\0';
    return TRUE;
  }

  return FALSE;
}


// BOOL mfGetMessageId(PMSGFILE pFile, PULONG pcbMsgId, PSZ *ppszMsgId)
//
// Searches the field "Message-ID:".
// Returns TRUE and field's value at pcbMsgId/ppszMsgId if field is found.
// The a pointer in ppszMsgId is valid until the file is not closed by
// mfClose().

BOOL mfGetMessageId(PMSGFILE pFile, PULONG pcbMsgId, PSZ *ppszMsgId)
{
  PMFFIELD             pField;

  for( pField = (PMFFIELD)lnkseqGetFirst( &pFile->lsFields );
       pField != NULL; pField = (PMFFIELD)lnkseqGetNext( pField ) )
  {
    if ( stricmp( &pField->acName, "Message-ID" ) == 0 )
    {
      *pcbMsgId = pField->cbValue;
      *ppszMsgId = pField->pszValue;
      return TRUE;
    }
  }

  return FALSE;
}

// BOOL mfGetFirstReceivedByHost(PMSGFILE pFile, PULONG pcbHost,
//                                PCHAR *ppcHost)
//
// Searches in the fields "Received:" first host received the message.
// Returns TRUE and host address at pcbHost/ppcHost if host is found.
// The a pointer in ppcHost is valid until the file is not closed by mfClose().

BOOL mfGetFirstReceivedByHost(PMSGFILE pFile, PULONG pcbHost, PCHAR *ppcHost)
{
  PMFFIELD             pField;
  ULONG                cbText, cbWord;
  PCHAR                pcText, pcWord;

  // Look for last "Received" by fields order.
  for( pField = (PMFFIELD)lnkseqGetFirst( &pFile->lsFields );
       pField != NULL; pField = (PMFFIELD)lnkseqGetNext( pField ) )
  {
    if ( stricmp( &pField->acName, "Received" ) == 0 )
      break;
  }

  if ( pField == NULL )
  {
    debug( "Field \"Received\" not found." );
    return FALSE;
  }

  // Look for word "by" in the field's value and return to user first word
  // after "by".

  cbText = pField->cbValue;
  pcText = pField->pszValue;

  while( utilStrCutWord( &cbText, &pcText, &cbWord, &pcWord ) )
  {
    if ( ( cbWord == 2 ) && ( *((PUSHORT)pcWord) == (USHORT)'yb' ) ) // "by"
      return utilStrCutWord( &cbText, &pcText, pcbHost, ppcHost );
  }

  debug( "Word \"by\" not found: %s", pField->pszValue );
  return FALSE;
}
