#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys\types.h>
#include <sys\stat.h>
#include <fcntl.h>
#include <io.h>
#include <ctype.h>
#include <iconv.h>
#include <debug.h>
#include "mcodec.h"

#define FILE_IN_BUF_SIZE	65535
#define FILE_OUT_BUF_SIZE	65535

#define MAX_QP_CHAR_PERCENTAGE	45

typedef ULONG CODECFN(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                     PCHAR *ppcSrc, PULONG pcbSrc);
typedef CODECFN *PCODECFN;

static const CHAR acBase64Table[65] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0";
static const CHAR acHex[16] = "0123456789ABCDEF";

#define HEX2BITS(c) (( c >= '0' && c <= '9' ) ? ( c - '0' ) : ( c - 'A' + 10 ))


static ULONG _encBase64(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                       PCHAR *ppcSrc, PULONG pcbSrc)
{
  BOOL		fEnd = ( ppcSrc == NULL ) || ( pcbSrc == NULL ) || ( *pcbSrc == 0 );
  ULONG		cbBuf;
  PCHAR		pcDst = *ppcDst;
  ULONG		cbDst = *pcbDst;
  PCHAR		pcSrc;
  ULONG		cbSrc;
  int		b64byte[4];

  if ( !fEnd )
  {
    pcSrc = *ppcSrc;
    cbSrc = *pcbSrc;
  }

  while( TRUE )
  {
    cbBuf = min( pCodec->cbOutBuf, cbDst );
    memcpy( pcDst, &pCodec->acOutBuf, cbBuf );
    pcDst += cbBuf;
    cbDst -= cbBuf;
    pCodec->cbOutBuf -= cbBuf;
    memcpy( &pCodec->acOutBuf, &pCodec->acOutBuf[cbBuf], pCodec->cbOutBuf );
    if ( cbDst == 0 )
      break;

    if ( !fEnd )
    {
      cbBuf = min( 3 - pCodec->cbInBuf, cbSrc );
      memcpy( &pCodec->acInBuf[pCodec->cbInBuf], pcSrc, cbBuf );
      pCodec->cbInBuf += cbBuf;
      pcSrc += cbBuf;
      cbSrc -= cbBuf;

      if ( pCodec->cbInBuf < 3 )
        break;
    }
    else if ( pCodec->cbInBuf == 0 )
      break;

    b64byte[0] = pCodec->acInBuf[0] >> 2;
    b64byte[1] = (pCodec->acInBuf[0] & 3) << 4;
    if ( pCodec->cbInBuf > 1 )
    {
      b64byte[1] |= pCodec->acInBuf[1] >> 4;
      b64byte[2] = (pCodec->acInBuf[1] & 0x0F) << 2;
      if ( pCodec->cbInBuf > 2 )
      {
        b64byte[2] |= pCodec->acInBuf[2] >> 6;
        b64byte[3] = pCodec->acInBuf[2] & 0x3F;
      }
      else
        b64byte[3] = -1;
    }
    else
    {
      b64byte[2] = -1;
      b64byte[3] = -1;
    }
    pCodec->cbInBuf = 0;

    if ( pCodec->ulOutCnt == 19 )
    {
      *((PUSHORT)&pCodec->acOutBuf) = '\n\r';
      pCodec->cbOutBuf = 2;
      pCodec->ulOutCnt = 0;
    }
    else
      pCodec->cbOutBuf = 0;

#if 1
    *((PULONG)&pCodec->acOutBuf[pCodec->cbOutBuf]) =
      ( (ULONG)acBase64Table[b64byte[0]] ) |
      ( (ULONG)acBase64Table[b64byte[1]] << 8 ) |
      ( (ULONG)( b64byte[2] == -1 ? '=' : acBase64Table[b64byte[2]] ) << 16 ) |
      ( (ULONG)( b64byte[3] == -1 ? '=' : acBase64Table[b64byte[3]] ) << 24 );
    pCodec->cbOutBuf += 4;
#else
    pCodec->acOutBuf[pCodec->cbOutBuf++] = acBase64Table[b64byte[0]];
    pCodec->acOutBuf[pCodec->cbOutBuf++] = acBase64Table[b64byte[1]];
    pCodec->acOutBuf[pCodec->cbOutBuf++] = b64byte[2] == -1 ? '=' : acBase64Table[b64byte[2]];
    pCodec->acOutBuf[pCodec->cbOutBuf++] = b64byte[3] == -1 ? '=' : acBase64Table[b64byte[3]];
    pCodec->ulOutCnt++;
#endif
  }

  *ppcDst = pcDst;
  *pcbDst = cbDst;
  if ( !fEnd )
  {
    *ppcSrc = pcSrc;
    *pcbSrc = cbSrc;
  }

  return pCodec->cbOutBuf + pCodec->cbInBuf;
}

static ULONG _decBase64(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                       PCHAR *ppcSrc, PULONG pcbSrc)
{
  BOOL		fEnd = ( ppcSrc == NULL ) || ( pcbSrc == NULL ) || ( *pcbSrc == 0 );
  ULONG		cbBuf;
  PCHAR		pcDst = *ppcDst;
  ULONG		cbDst = *pcbDst;
  PCHAR		pcSrc;
  ULONG		cbSrc;
  PCHAR		pcPtr;

  if ( !fEnd )
  {
    pcSrc = *ppcSrc;
    cbSrc = *pcbSrc;
  }

  while( TRUE )
  {
    if ( pCodec->cbOutBuf != 0 )
    {
      cbBuf = min( pCodec->cbOutBuf, cbDst );
      memcpy( pcDst, &pCodec->acOutBuf, cbBuf );
      pCodec->cbOutBuf -= cbBuf;
      memcpy( &pCodec->acOutBuf, &pCodec->acOutBuf[cbBuf], pCodec->cbOutBuf );
      pcDst += cbBuf;
      cbDst -= cbBuf;

      if ( pCodec->cbOutBuf != 0 )
        break;
    }

    if ( !fEnd )
    {
      while( ( cbSrc > 0 ) && ( pCodec->cbInBuf < 4 ) )
      {
        if ( *pcSrc == '=' )
        {
          fEnd = TRUE;
          *ppcSrc = ( pcSrc + cbSrc );
          *pcbSrc = 0;
          bzero( &pCodec->acInBuf[pCodec->cbInBuf],
                 sizeof(pCodec->acInBuf) - pCodec->cbInBuf );
          break;
        }

        pcPtr = strchr( &acBase64Table, *pcSrc );
        if ( pcPtr != NULL )
          pCodec->acInBuf[pCodec->cbInBuf++] = pcPtr - &acBase64Table;

        pcSrc++;
        cbSrc--;
      }

      if ( !fEnd && ( pCodec->cbInBuf < 4 ) )
        break;
    }
    else if ( pCodec->cbInBuf == 0 )
      break;

#if 1
    pCodec->acOutBuf[0] = ( pCodec->acInBuf[0] << 2 ) |
                          ( pCodec->acInBuf[1] >> 4 );
    pCodec->acOutBuf[1] = ( pCodec->acInBuf[1] << 4 ) |
                          ( pCodec->acInBuf[2] >> 2 );
    pCodec->acOutBuf[2] = ( (pCodec->acInBuf[2] & 0x03 ) << 6 ) |
                          ( pCodec->acInBuf[3] & 0x3f );
    pCodec->cbOutBuf = pCodec->cbInBuf - 1;
    pCodec->cbInBuf = 0;
    if ( pCodec->cbOutBuf != 3 )
      break;
#else
    pCodec->acOutBuf[0] = pCodec->acInBuf[0] << 2;
    if ( pCodec->cbInBuf > 1 )
    {
      pCodec->acOutBuf[0] |= pCodec->acInBuf[1] >> 4;
      pCodec->acOutBuf[1] = pCodec->acInBuf[1] << 4;
      if ( pCodec->cbInBuf > 2 )
      {
        pCodec->acOutBuf[1] |= pCodec->acInBuf[2] >> 2;
        pCodec->acOutBuf[2] = (pCodec->acInBuf[2] & 0x03 ) << 6;
        if ( pCodec->cbInBuf > 3 )
        {
          pCodec->acOutBuf[2] |= pCodec->acInBuf[3] & 0x3f;
          pCodec->cbOutBuf = 3;
          pCodec->cbInBuf = 0;
          continue;
        }
        else
          pCodec->cbOutBuf = 2;
      }
      else
        pCodec->cbOutBuf = 1;
    }
    else
      pCodec->cbOutBuf = 0;

    pCodec->cbInBuf = 0;
    break;
#endif
  }

  *ppcDst = pcDst;
  *pcbDst = cbDst;
  if ( !fEnd )
  {
    *ppcSrc = pcSrc;
    *pcbSrc = cbSrc;
  }

  return pCodec->cbOutBuf;
}

static ULONG _encQuotedPrintable(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                                PCHAR *ppcSrc, PULONG pcbSrc, BOOL fNoSpaces)
{
  BOOL		fEnd = ( ppcSrc == NULL ) || ( pcbSrc == NULL ) || ( *pcbSrc == 0 );
  ULONG		cbBuf;
  PCHAR		pcDst = *ppcDst;
  ULONG		cbDst = *pcbDst;
  PCHAR		pcSrc;
  ULONG		cbSrc;
  CHAR		chIn;
  ULONG		ulOutputFlag;
#define QP_OF_CHAR	0
#define QP_OF_ENCCHAR	1
#define QP_OF_CRLF	2
#define QP_OF_WAITMORE	3
  ULONG		ulOutBufLeft;

  if ( !fEnd )
  {
    pcSrc = *ppcSrc;
    cbSrc = *pcbSrc;
  }

  while( TRUE )
  {
    if ( !fEnd )
    {
      cbBuf = min( sizeof( pCodec->acInBuf ) - pCodec->cbInBuf, cbSrc );
      memcpy( &pCodec->acInBuf[pCodec->cbInBuf], pcSrc, cbBuf );
      pCodec->cbInBuf += cbBuf;
      pcSrc += cbBuf;
      cbSrc -= cbBuf;
    }

    if ( pCodec->cbInBuf > 0 )
    do
    {
      chIn = pCodec->acInBuf[0];

      if ( ( ( chIn >= 37 && chIn <= 60 ) || ( chIn >= 62 && chIn <= 63 ) ||
             ( chIn >= 65 && chIn <= 90 ) || ( chIn == 95 ) ||
             ( chIn >= 97 && chIn <= 122 ) )
           &&
           ( !fNoSpaces || ( strchr( "(),./:;<>?", chIn ) == NULL ) ) )

      {
        ulOutputFlag = QP_OF_CHAR;
      }
      else if ( !fNoSpaces && ( chIn == 9 || chIn == 32 ) )	// TAB / SP
      {
        if ( pCodec->cbInBuf > 1 )
        {
          ulOutputFlag = pCodec->acInBuf[1] == 13 ? QP_OF_ENCCHAR : QP_OF_CHAR;
        }
        else if ( fEnd )
          ulOutputFlag = QP_OF_ENCCHAR;
        else
        {
          ulOutputFlag = QP_OF_WAITMORE;
          break;
        }
      }
      else if ( !fNoSpaces && ( chIn == 13 ) )		// CR
      {
        if ( pCodec->cbInBuf > 2 )
        {
          ulOutputFlag = pCodec->acInBuf[1] == 10 ? QP_OF_CRLF : QP_OF_ENCCHAR;
        }
        else if ( fEnd )
          ulOutputFlag = QP_OF_ENCCHAR;
        else
        {
          ulOutputFlag = QP_OF_WAITMORE;
          break;
        }
      }
      else				// must be encoded
      {
        ulOutputFlag = QP_OF_ENCCHAR;
      }

      ulOutBufLeft = sizeof(pCodec->acOutBuf) - pCodec->cbOutBuf;
      if ( ( ( ulOutputFlag == QP_OF_CHAR ) && ( pCodec->ulOutCnt >= 74 ) ) ||
           ( ( ulOutputFlag == QP_OF_ENCCHAR ) && ( pCodec->ulOutCnt >= 72 ) ) )
      {
        if ( ulOutBufLeft < 3 )
          break;

        pCodec->acOutBuf[pCodec->cbOutBuf++] = '=';
        pCodec->acOutBuf[pCodec->cbOutBuf++] = '\r';
        pCodec->acOutBuf[pCodec->cbOutBuf++] = '\n';
        ulOutBufLeft -= 3;
        pCodec->ulOutCnt = 0;
      }

      switch( ulOutputFlag )
      {
        case QP_OF_CHAR:
          if ( ulOutBufLeft == 0 )
            break;

          pCodec->acOutBuf[pCodec->cbOutBuf++] = chIn;
          pCodec->ulOutCnt++;
          pCodec->cbInBuf--;
          *((PULONG)&pCodec->acInBuf) >>= 8;
          break;

        case QP_OF_ENCCHAR:
          if ( ulOutBufLeft < 3 )
            break;

          pCodec->acOutBuf[pCodec->cbOutBuf++] = '=';
          pCodec->acOutBuf[pCodec->cbOutBuf++] = acHex[chIn >> 4];
          pCodec->acOutBuf[pCodec->cbOutBuf++] = acHex[chIn & 0x0F];
          pCodec->ulOutCnt += 3;
          pCodec->cbInBuf--;
          *((PULONG)&pCodec->acInBuf) >>= 8;
          break;

        case QP_OF_CRLF:
          if ( ulOutBufLeft < 2 )
            break;

          pCodec->ulOutCnt = 0;
          pCodec->acOutBuf[pCodec->cbOutBuf++] = '\r';
          pCodec->acOutBuf[pCodec->cbOutBuf++] = '\n';
          pCodec->ulOutCnt += 2;
          pCodec->cbInBuf -= 2;
          *((PULONG)&pCodec->acInBuf) >>= 16;
          break;
      }
    }
    while( FALSE );

    cbBuf = min( pCodec->cbOutBuf, cbDst );
    memcpy( pcDst, &pCodec->acOutBuf, cbBuf );
    pCodec->cbOutBuf -= cbBuf;
    memcpy( &pCodec->acOutBuf, &pCodec->acOutBuf[cbBuf], pCodec->cbOutBuf );
    pcDst += cbBuf;
    cbDst -= cbBuf;

    if ( ( ulOutputFlag == QP_OF_WAITMORE ) || ( cbDst == 0 ) ||
         ( ( pCodec->cbInBuf == 0 ) && ( fEnd || cbSrc == 0 ) ) )
      break;
  }

  *ppcDst = pcDst;
  *pcbDst = cbDst;
  if ( !fEnd )
  {
    *ppcSrc = pcSrc;
    *pcbSrc = cbSrc;
  }

  return pCodec->cbInBuf + pCodec->cbOutBuf;
}

static ULONG _encQuotedPrintableSp(PCODEC pCodec, PCHAR *ppcDst,
                                  PULONG pcbDst, PCHAR *ppcSrc, PULONG pcbSrc)
{
  return _encQuotedPrintable( pCodec, ppcDst, pcbDst, ppcSrc, pcbSrc, FALSE );
}

static ULONG _encQuotedPrintableNoSp(PCODEC pCodec, PCHAR *ppcDst,
                                    PULONG pcbDst, PCHAR *ppcSrc, PULONG pcbSrc)
{
  return _encQuotedPrintable( pCodec, ppcDst, pcbDst, ppcSrc, pcbSrc, TRUE );
}

static ULONG _decQuotedPrintable(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                                 PCHAR *ppcSrc, PULONG pcbSrc)
{
  BOOL		fEnd = ( ppcSrc == NULL ) || ( pcbSrc == NULL ) || ( *pcbSrc == 0 );
  ULONG		cbBuf;
  PCHAR		pcDst = *ppcDst;
  ULONG		cbDst = *pcbDst;
  PCHAR		pcSrc;
  ULONG		cbSrc;
  CHAR		chIn;

  if ( !fEnd )
  {
    pcSrc = *ppcSrc;
    cbSrc = *pcbSrc;
  }

  while( cbDst != 0 )
  {
    if ( !fEnd )
    {
      cbBuf = min( 3 - pCodec->cbInBuf, cbSrc );
      memcpy( &pCodec->acInBuf[pCodec->cbInBuf], pcSrc, cbBuf );
      pCodec->cbInBuf += cbBuf;
      pcSrc += cbBuf;
      cbSrc -= cbBuf;
    }

    if ( pCodec->cbInBuf == 0 )
      break;

    chIn = pCodec->acInBuf[0];
    if ( chIn == '=' )
    {
      if ( pCodec->cbInBuf > 1 && pCodec->acInBuf[1] == 10 )
      {
        // soft CRLF (line ended with 0x0A)
        pCodec->cbInBuf -= 2;
        continue;
      }
     

      if ( pCodec->cbInBuf == 3 )
      {   
        pCodec->cbInBuf = 0;

        if ( pCodec->acInBuf[1] == 13 ) // soft CRLF
          continue;

        // encoded byte
        chIn = ( HEX2BITS( pCodec->acInBuf[1] ) << 4 ) |
               HEX2BITS( pCodec->acInBuf[2] );
      }
      else
      {
        if ( fEnd )
          pCodec->cbInBuf = 0;
        break;
      }
    }
    else	// not encoded byte
    {
      pCodec->cbInBuf--;
      *((PULONG)&pCodec->acInBuf) >>= 8;
    }

    *pcDst = chIn;
    pcDst++;
    cbDst--;
  }

  *ppcDst = pcDst;
  *pcbDst = cbDst;
  if ( !fEnd )
  {
    *ppcSrc = pcSrc;
    *pcbSrc = cbSrc;
  }

  return pCodec->cbInBuf;
}

static ULONG _encdec8Bit(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst,
                         PCHAR *ppcSrc, PULONG pcbSrc)
{
  ULONG		cbCopy = min( *pcbDst, *pcbSrc );

  memcpy( *ppcDst, *ppcSrc, cbCopy );
  *ppcDst += cbCopy;
  *ppcSrc += cbCopy;
  *pcbDst -= cbCopy;
  *pcbSrc -= cbCopy;
  return 0;
}

BOOL codecInit(PCODEC pCodec, ULONG ulType)
{
  switch( ulType )
  {
    case CODEC_ENC_BASE64:
      pCodec->pFunc = (PVOID)_encBase64;
      break;

    case CODEC_DEC_BASE64:
      pCodec->pFunc = (PVOID)_decBase64;
      break;

    case CODEC_ENC_QUOTED_PRINTABLE_SP:
      pCodec->pFunc = (PVOID)_encQuotedPrintableSp;
      break;

    case CODEC_ENC_QUOTED_PRINTABLE:
      pCodec->pFunc = (PVOID)_encQuotedPrintableNoSp;
      break;

    case CODEC_DEC_QUOTED_PRINTABLE:
      pCodec->pFunc = (PVOID)_decQuotedPrintable;
      break;

    case CODEC_ENC_DEC_8BIT:
      pCodec->pFunc = (PVOID)_encdec8Bit;
      break;

    default:
      return FALSE;
  }

  pCodec->cbInBuf = 0;
  pCodec->cbOutBuf = 0;
  pCodec->ulOutCnt = 0;

  return TRUE;
}

ULONG codecConv(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst, PCHAR *ppcSrc,
                PULONG pcbSrc)
{
  PCODECFN	pFunc = (PCODECFN)pCodec->pFunc;

  return pFunc( pCodec, ppcDst, pcbDst, ppcSrc, pcbSrc );
}

LONG codecConvBuf(ULONG ulType, PCHAR pcDst, ULONG cbDst,
                  PCHAR pcSrc, ULONG cbSrc)
{
  CODEC		sCodec;
  ULONG		ulRC;
  ULONG		cbDstLeft = cbDst;

  if ( !codecInit( &sCodec, ulType ) )
    return -1;

  ulRC = codecConv( &sCodec, &pcDst, &cbDstLeft, &pcSrc, &cbSrc );
  if ( ulRC != 0 && cbDstLeft > 0 )
    ulRC = codecConv( &sCodec, &pcDst, &cbDstLeft, NULL, NULL );

  return ( ulRC != 0 ) || ( cbSrc != 0 ) ? -2 : ( cbDst - cbDstLeft );
}

ULONG codecFile(PCODEC pCodec, PSZ pszFOut, PSZ pszFIn)
{
  int		hfOut;
  int		hfIn;
  PCHAR		pcIn, pcInPos;
  PCHAR		pcOut, pcOutPos;
  ULONG		cbIn = 0;
  ULONG		cbOut;
  int		cbRead;
  ULONG		ulRes = CODEC_OK;

  hfIn = open( pszFIn, O_RDONLY | O_BINARY ); 
  if ( hfIn == -1 )
    return CODEC_OPEN_FILE_ERROR;

  hfOut = open( pszFOut, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY,
                S_IREAD | S_IWRITE ); 
  if ( hfOut == -1 )
  {
    close( hfIn );
    return CODEC_CREATE_FILE_ERROR;
  }

  pcIn = debugMAlloc( FILE_IN_BUF_SIZE );
  if ( pcIn == NULL )
  {
    close( hfIn );
    close( hfOut );
    return CODEC_NOT_ENOUGH_MEMORY;
  }

  pcOut = debugMAlloc( FILE_OUT_BUF_SIZE );
  if ( pcOut == NULL )
  {
    debugFree( pcIn );
    close( hfIn );
    close( hfOut );
    return CODEC_NOT_ENOUGH_MEMORY;
  }

  do
  {
    cbRead = read( hfIn, pcIn, FILE_IN_BUF_SIZE ); 
    if ( cbRead == -1 )
    {
      ulRes = CODEC_IO_ERROR;
      break;
    }

    cbIn = cbRead;
    pcInPos = pcIn;

    do
    {
      pcOutPos = pcOut;
      cbOut = FILE_OUT_BUF_SIZE;

      codecConv( pCodec, &pcOutPos, &cbOut, &pcInPos, &cbIn );
      cbOut = pcOutPos - pcOut;
      if ( ( cbOut != 0 ) && ( write( hfOut, pcOut, cbOut ) <= 0 ) )
      {
        ulRes = CODEC_IO_ERROR;
        break;
      }
    }
    while( cbIn != 0 );
  }
  while( ( cbRead != 0 ) && ( ulRes == CODEC_OK ) );

  debugFree( pcIn );
  debugFree( pcOut );
  close( hfIn );
  close( hfOut );

  return ulRes;
}


static ULONG _codecCopyWords(PCHAR pcDst, ULONG cbDst, PSZ *ppszSrc)
{
  PCHAR		pcNextWord;
  ULONG		cbWord;
  PSZ		pszSrc = *ppszSrc;
  ULONG		cbResult = 0;

  while( isspace( *pszSrc ) )
    pszSrc++;

  while( TRUE )
  {
    pcNextWord = strchr( pszSrc, ' ' );
    if ( pcNextWord == NULL )
      pcNextWord = strchr( pszSrc, '\0' );
    else
      while( isspace( *pcNextWord ) )
        pcNextWord++;

    cbWord = pcNextWord - pszSrc;
    if ( cbWord == 0 || cbWord > cbDst )
      break;

    memcpy( pcDst, pszSrc, cbWord );
    pszSrc += cbWord;
    pcDst += cbWord;
    cbDst -= cbWord;
    cbResult += cbWord;
  }

  *ppszSrc = pszSrc;
  return cbResult;
}

PSZ codecEncodedWordNew(ULONG ulType, PSZ pszCharset, ULONG ulFirstLineSpace,
                        PSZ pszData)
{
  CHAR		acPref[32];
  LONG		cbPref;
  ULONG		ulEncType;
  PSZ		pszEW = NULL, pszEWNew;
  ULONG		cbEW = 0;
  ULONG		ulEWPos = 0;
  CODEC		sCodec;
  ULONG		cbData = strlen( pszData );
  ULONG		cbDataPart;
  PCHAR		pcDst, pcSrc;
  ULONG		cbDst, cbSrc;
  ULONG		ulRC;
  BOOL		fPlainText = TRUE;
  BOOL		fHTTPMode = ( ulType & CODEC_EW_MODE_HTTP ) != 0;

  ulType &= 0x000000FF;

  if ( ulType != CODEC_EW_PLAIN )
  {
    for( pcSrc = pszData; *pcSrc != '\0'; pcSrc++ )
    {
      if ( !isalnum( *pcSrc ) &&
           ( strchr( "\r\n!?;#$%^~*{}/\\.,- \t", *pcSrc ) != NULL ) )
      {
        fPlainText = FALSE;
        break;
      }
    }

    if ( fPlainText )
      ulType = CODEC_EW_PLAIN;
  }

  switch( ulType )
  {
    case CODEC_EW_BASE64:			// 0
      ulEncType = CODEC_ENC_BASE64;
      break;

    case CODEC_EW_AUTO:				// 1
      pcSrc = pszData;
      ulRC = 0;
      while( *pcSrc != '\0' )
      {
        if ( *pcSrc < 32 || *pcSrc > 127 )
          ulRC++;
        pcSrc++;
      }

      if ( ( ( ulRC * 100 ) / strlen( pszData ) ) > MAX_QP_CHAR_PERCENTAGE )
      {
        ulEncType = CODEC_ENC_BASE64;
        break;
      }

    default: // CODEC_EW_QUOTED_PRINTABLE (2), CODEC_EW_PLAIN (5)
      ulEncType = CODEC_ENC_QUOTED_PRINTABLE;
  }

  if ( pszCharset == NULL )
  {
    if ( ulType != CODEC_EW_PLAIN )
      return NULL;

    cbPref = 0;
  }
  else
  {
    cbPref = _snprintf( &acPref, sizeof(acPref), "=?%s?%c?", pszCharset,
                        ulEncType == CODEC_ENC_BASE64 ? 'B' : 'Q' );
    if ( cbPref < 0 )
      return FALSE;
  }


  if ( fHTTPMode )
  {
    LONG	cbBytes;

    if ( fPlainText )
      pszEW = debugStrDup( pszData );
    else
    {
      cbBytes = cbData * 3;			// "body" max. size
      pcDst = debugMAlloc( cbBytes + cbPref + 4 );	// 4: "?=", ZERO, ZERO

      memcpy( pcDst, &acPref, cbPref );
      cbBytes = codecConvBuf( ulEncType, &pcDst[cbPref], cbBytes,
                              pszData, cbData );
      if ( cbBytes < 0 )
        pszEW = NULL;
      else
      {
        *((PULONG)&pcDst[cbPref + cbBytes]) = '\0\0=?';
        pszEW = debugStrDup( pcDst );
      }
      debugFree( pcDst );
    }

    return pszEW;
  }


  while( cbData != 0 )
  {
    // Allocate memory for next line.
    cbEW = ( ulEWPos == 0 ? ( 76 - ulFirstLineSpace ) : ulEWPos + 78 );
    pszEWNew = debugReAlloc( pszEW, cbEW );
    if ( pszEWNew == NULL )
    {
      if ( pszEW != NULL )
        debugFree( pszEW );
      return NULL;
    }
    pszEW = pszEWNew;

    // CRLF to prev. line, SP
    if ( ulEWPos != 0 )
    {
      pszEW[ulEWPos++] = '\r';
      pszEW[ulEWPos++] = '\n';
      pszEW[ulEWPos++] = ' ';
    }

    if ( fPlainText )
    {
      pcDst = &pszEW[ulEWPos];
      cbDst = ( cbEW - ulEWPos ) - 1;
      pcSrc = pszData;

      ulRC = _codecCopyWords( pcDst, cbDst, &pcSrc );
      if ( ulRC != 0 )
      {
        cbData -= pcSrc - pszData;
        pszData = pcSrc;
        ulEWPos += ulRC;
        pszEW[ulEWPos] = '\0';
        continue;
      }

      if ( cbPref == 0 ) // pszCharset == NULL : do "dirty" line break
      {
        memcpy( pcDst, pszData, cbDst );
        pszData += cbDst;
        cbData -= cbDst;
        ulEWPos += cbDst;
        continue;
      }

      fPlainText = FALSE;
    }

    if ( !fPlainText )
    {
      // Encoding-word "prefix"
      memcpy( &pszEW[ulEWPos], &acPref, cbPref );
      ulEWPos += cbPref;
      cbDataPart = cbData;

      // Encoded-word "body"
      while( TRUE )
      {
        pcDst = &pszEW[ulEWPos];
        cbDst = ( cbEW - ulEWPos ) - 3; // Reserve 3 bytes for '?=' + ZERO.
        pcSrc = pszData;
        cbSrc = cbDataPart;

        codecInit( &sCodec, ulEncType );
        ulRC = codecConv( &sCodec, &pcDst, &cbDst, &pcSrc, &cbSrc );
        if ( ulRC != 0 && cbDst > 0 )
          ulRC = codecConv( &sCodec, &pcDst, &cbDst, NULL, NULL );

        if ( ulRC == 0 && cbDst > 0 )
        {
          cbData -= cbDataPart;
          pszData += cbDataPart;
          ulEWPos += pcDst - &pszEW[ulEWPos];
          pszEW[ulEWPos++] = '?';
          pszEW[ulEWPos++] = '=';
          pszEW[ulEWPos] = '\0';
          break;
        }

        cbDataPart = pcSrc - pszData - 1;
      }
    }
  }

  return pszEW;
}

PSZ codecDecodeWordNew(PSZ pszCharset, PCHAR pcData, ULONG cbData)
{
  PCHAR		pcSrc;
  BOOL		fDecoded;
  PCHAR		pcWord;
  ULONG		cbWord;
  BOOL		fSpaceBefore;
  PSZ		pszResNew;
  PSZ		pszRes = NULL;
  ULONG		ulResPos = 0;
  PCHAR		pcDataEnd = &pcData[cbData];

  while( pcData < pcDataEnd )
  {
    fDecoded = FALSE;

    // Try decode encoded-word

    for( pcSrc = pcData; isspace( *pcSrc ) && pcSrc < pcDataEnd; pcSrc++ ) { }
    if ( ( pcSrc < pcDataEnd ) && ( *((PUSHORT)pcSrc) == '?=' ) )
    do
    {
      PCHAR	pcCharset;
      ULONG	cbCharset;
      ULONG	ulEncType;
      PCHAR	pcEW;
      ULONG	cbEW;
      CODEC	sCodec;
      CHAR	acDec[80];
      PCHAR	pcDec;
      ULONG	cbDec;
      CHAR	acCharset[24];
      iconv_t	icEW;
      CHAR	acConv[80];
      size_t	sizeIC;

      pcSrc += 2;
      pcCharset = pcSrc;
      while( ( pcSrc < pcDataEnd ) && ( *pcSrc != '\0' ) && !isspace( *pcSrc )
             && ( *pcSrc != '?' ) && ( *pcSrc != '=' ) )
        pcSrc++;

      if ( ( pcSrc == pcDataEnd ) || ( *pcSrc != '?') ||
           ( pcSrc[1] != 'b' && pcSrc[1] != 'B' &&
             pcSrc[1] != 'q' && pcSrc[1] != 'Q' ) || ( pcSrc[2] != '?' ) )
        break;

      cbCharset = pcSrc - pcCharset;
      if ( cbCharset >= sizeof(acCharset) )
        break;

      ulEncType = pcSrc[1] == 'b' || pcSrc[1] == 'B' ?
                    CODEC_DEC_BASE64 : CODEC_DEC_QUOTED_PRINTABLE;
      pcSrc += 3;
      pcEW = pcSrc;
      while( ( pcSrc < pcDataEnd ) && !isspace( *pcSrc ) && ( *pcSrc != '?' ) )
        pcSrc++;

      if ( ( pcSrc == pcDataEnd ) || ( *pcSrc != '?' ) || ( pcSrc[1] != '=' ) )
        break;

      cbEW = pcSrc - pcEW;
      // pcCharset:cbCharset - charset, ulEncType - decode type, pcEW:cbEW - data

      pcDec = &acDec;
      cbDec = sizeof(acDec);
      codecInit( &sCodec, ulEncType );
      if ( codecConv( &sCodec, &pcDec, &cbDec, &pcEW, &cbEW ) != 0 )
        codecConv( &sCodec, &pcDec, &cbDec, NULL, NULL );
      if ( cbEW != 0 )
        break;

      memcpy( &acCharset, pcCharset, cbCharset );
      acCharset[cbCharset] = '\0';

      icEW = iconv_open( pszCharset, &acCharset );
      if ( icEW == ((iconv_t)(-1)) )
        break;

      pcDec = &acDec;
      cbDec = sizeof(acDec) - cbDec;
      pcWord = &acConv;
      cbWord = sizeof(acConv);
      sizeIC = iconv( icEW, &pcDec, (size_t *)&cbDec, &pcWord, (size_t *)&cbWord );
      iconv_close( icEW );

      if ( sizeIC == ((size_t)(-1)) )
        break;

      cbWord = sizeof(acConv) - cbWord;
      pcWord = &acConv;

      pcData = pcSrc + 2;
      fSpaceBefore = FALSE;
      fDecoded = TRUE;
    }
    while( FALSE );

    // Search "real" (not encoded-) word

    if ( !fDecoded )
    {
      if ( *pcData == '\r' || *pcData == '\n' )
      {
        // Skip spaces from begin of line.
        while( ( pcData < pcDataEnd ) && isspace( *pcData ) )
          pcData++;
        fSpaceBefore = TRUE;
      }
      else
        fSpaceBefore = FALSE;

      for( pcWord = pcData;
           ( pcData < pcDataEnd ) && ( *pcData == ' ' || *pcData == '\t' );
           pcData++ ) { }

      if ( ( pcData < pcDataEnd ) && ( *pcData != '\r' && *pcData != '\n' ) )
      {
        while( ( pcData < pcDataEnd ) && !isspace( *pcData ) )
          pcData++;

        cbWord = pcData - pcWord;
        while( ( pcData < pcDataEnd ) &&
               *pcData == ' ' || *pcData == '\t' )
          pcData++;

        if ( pcData < pcDataEnd )
          cbWord = pcData - pcWord;
      }
      else
        cbWord = pcData - pcWord;
    }

    // pcWord:cbWord - decoded encoded-word or "real" word
    // Allocate memory, copy word to result.

    pszResNew = debugReAlloc( pszRes, ulResPos + cbWord + 2 );
    if ( pszResNew == NULL )
    {
      if ( pszRes != NULL )
        debugFree( pszRes );
      return NULL;
    }
    pszRes = pszResNew;

    memcpy( &pszRes[ulResPos], pcWord, cbWord );
    ulResPos += cbWord;
  }

  pszRes[ulResPos] = '\0';
  return pszRes;
}

VOID codecEncodedWordFree(PSZ pszEncodedWord)
{
  if ( pszEncodedWord )
    debugFree( pszEncodedWord );
}

LONG codecIConvBuf(PSZ pszDstCode, PCHAR pcDst, ULONG cbDst,
                   PSZ pszSrcCode, PCHAR pcSrc, ULONG cbSrc)
{
  iconv_t	ic;
  size_t	sizeIC;

  ic = iconv_open( pszDstCode, pszSrcCode );
  if ( ic == ((iconv_t)(-1)) )
    return -1;

  sizeIC = iconv( ic, &pcDst, (size_t *)&cbDst, &pcSrc, (size_t *)&cbSrc );
  iconv_close( ic );

  if ( sizeIC == ((size_t)(-1)) )
    return -1;

  return cbSrc != 0 ? -2 : sizeIC;
}
