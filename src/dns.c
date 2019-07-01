// https://tools.ietf.org/html/rfc2929#page-2
// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

#include <stdlib.h>
#include <string.h>
#include <types.h>
#include <stdio.h>
#include "xpl.h"
#include "linkseq.h"
#include "sockets.h"
#include "dns.h"
#include "hmem.h"
#include "debug.h"     // Must be the last.

#define MAX_SIMULTANEOUS_REQ    32
#define NEGATIVE_ANSWER_TTL     60

#define DNSPKT_FL_QR            0x0001     // 0 - request, 1 - answer.
#define DNSPKT_FL_OPCODE        0x001E
#define DNSPKT_FL_AA            0x0020
#define DNSPKT_FL_TC            0x0040     // Truncated.
#define DNSPKT_FL_RD            0x0080     // Recursion desired.
#define DNSPKT_FL_RA            0x8000     // Recursion available.
#define DNSPKT_FL_RCODE         0x0F00

#define DNSREC_CLASS_INET       0x0100     // Internet address.

// Cache record.

#define cri_stAddr _dns_id.stAddr
#define cri_pszName _dns_id.pszName
#define cri_pMXName _dns_id.pMXName

typedef struct _MXNAME {
  USHORT               usLevel;
  CHAR                 acName[1];
} MXNAME, *PMXNAME;

typedef struct _CRECITEM {
  time_t               timeExpire;
  union {
    struct in_addr     stAddr;
    PSZ                pszName;
    PMXNAME            pMXName;
  } _dns_id;                               // cri_xxxxxx
} CRECITEM, *PCRECITEM;

typedef struct _DNSCACHEREC {
  SEQOBJ               seqObj;

  USHORT               usType;
  PSZ                  pszName;
  time_t               timeExpire;
  ULONG                ulRCode;            // DNS_xxxxx
  ULONG                cItems;
  CRECITEM             aItems[1];
} DNSCACHEREC, *PDNSCACHEREC;

// DNS request/answer packet.

#pragma pack(1)
typedef struct _DNSPKT {
  USHORT               usId;
  USHORT               usFlags;
  USHORT               cQueries;           // Questions.
  USHORT               cAnswers;           // Answers.
  USHORT               cRights;            // Authoritative Servers.
  USHORT               cAdditions;         // Additional records.
  CHAR                 acData[1];
} DNSPKT, *PDNSPKT;
#pragma pack()

static struct in_addr  stNSAddr;
static USHORT          usNSPort;

static LINKSEQ         stCache;
static HMTX            hmtxCache;

static ULONG           ulNSTimeouts[] = { 3, 6, 15 };
#define REQ_MAX_ATTEMPTS         ( sizeof(ulNSTimeouts) / sizeof(ULONG) )


//           Answers cache
//           -------------

#define _cacheInit() do { \
  lnkseqInit( &stCache ); xplMutexCreate( &hmtxCache, FALSE ); \
} while( FALSE )
#define _cacheDone() do { \
  if ( hmtxCache != NULLHANDLE ) { \
    lnkseqFree( &stCache, PDNSCACHEREC, _cacheRecFree ); \
    xplMutexDestroy( hmtxCache ); hmtxCache = NULLHANDLE; } \
} while( FALSE )
#define _cacheLock() xplMutexLock( hmtxCache, XPL_INDEFINITE_WAIT )
#define _cacheUnlock() xplMutexUnlock( hmtxCache )

// _cacheRecNew(USHORT usType, PSZ pszName, ULONG ulRCode, ULONG cItems)
//
// Allocates object DNSCACHEREC with given type, name and array for cItems
// items. Inserts new object to the cache.
// Cache must be locked with _cacheLock().
// Returns pointer to the created object or NULL when an error occurs.

static PDNSCACHEREC _cacheRecNew(USHORT usType, PSZ pszName, ULONG ulRCode,
                                 ULONG cItems)
{
  PDNSCACHEREC         pRec;

  pRec = hcalloc( 1, sizeof(DNSCACHEREC) + (sizeof(CRECITEM)*(cItems-1)) );
  if ( pRec == NULL )
  {
    debug( "Not enough memory" );
    return NULL;
  }

  pRec->usType = usType;
  pRec->pszName = hstrdup( pszName );
  pRec->ulRCode = ulRCode;
  pRec->cItems = cItems;
  lnkseqAdd( &stCache, pRec );
  return pRec;
}

// _cacheRecFree(PDNSCACHEREC pRec)
//
// Remove record from cache and destroy it.
// Cache must be locked with _cacheLock().

static VOID _cacheRecFree(PDNSCACHEREC pRec)
{
  ULONG      ulIdx;

  lnkseqRemove( &stCache, pRec );

  if ( pRec->usType != DNSREC_TYPE_A )
  {
    for( ulIdx = 0; ulIdx < pRec->cItems; ulIdx++ )
      if ( pRec->aItems[ulIdx]._dns_id.pszName != NULL )
        hfree( pRec->aItems[ulIdx]._dns_id.pszName );
  }
  
  if ( pRec->pszName != NULL )
    hfree( pRec->pszName );
  hfree( pRec );
}

// PDNSCACHEREC _cacheFind(USHORT usType, PSZ pszName)
//
// Returns cached object DNSCACHEREC for given type and name or NULL if record
// not found. Also, this function will remove all expired records and objects
// from the cache.
// Cache must be locked with _cacheLock().

static PDNSCACHEREC _cacheFind(USHORT usType, PSZ pszName)
{
  PDNSCACHEREC         pRec = (PDNSCACHEREC)lnkseqGetFirst( &stCache );
  PDNSCACHEREC         pNextRec;
  time_t               timeCurrent;
  ULONG                ulIdx;

  time( &timeCurrent );

  while( pRec != NULL )
  {
    // Remove expired items from the record.

    for( ulIdx = 0; ulIdx < pRec->cItems; )
    {
      if ( timeCurrent > pRec->aItems[ulIdx].timeExpire )
      {
        pRec->cItems--;
        if ( pRec->usType != DNSREC_TYPE_A )
          hfree( pRec->aItems[ulIdx]._dns_id.pszName );
        pRec->aItems[ulIdx] = pRec->aItems[pRec->cItems];
      }
      else
        ulIdx++;
    }

    pNextRec = (PDNSCACHEREC)lnkseqGetNext( pRec );

    if ( timeCurrent > pRec->timeExpire )
    {
      // Record expired - remove it from cache and destroy.
      _cacheRecFree( pRec );
    }
    else if ( ( pRec->usType == usType ) &&
              ( stricmp( pRec->pszName, pszName ) == 0 ) )
      // Record found.
      break;

    pRec = pNextRec;
  }

  return pRec;
}

// ULONG _cacheRecRead(PDNSCACHEREC pRec, ULONG cbBuf, PCHAR pcBuf,
//                    PULONG pulItems)
//
// Fills user buffer pointed by pcBuf with data items from object pRec:
//   for DNSREC_TYPE_A - record <struct in_addr>, ...,
//   for DNSREC_TYPE_MX - MX level (2 bytes), MX name (ASCIIZ), ...,
//   for others - ASCIIZ strings.
// Number of readed items will be stored in pulItems.
// Returns DNS_xxxxx code (RCODE or private DNS module code).

static ULONG _cacheRecRead(PDNSCACHEREC pRec, ULONG cbBuf, PCHAR pcBuf,
                           PULONG pulItems)
{
  ULONG      ulIdx;
  ULONG      cItems = 0;
  BOOL       fOverflow = FALSE;

  for( ulIdx = 0; ulIdx < pRec->cItems; ulIdx++ )
  {
    switch( pRec->usType )
    {
      case DNSREC_TYPE_A:
        if ( cbBuf < sizeof(struct in_addr) )
        {
          fOverflow = TRUE;
          break;
        }
        *((struct in_addr *)pcBuf) = pRec->aItems[ulIdx].cri_stAddr;
        pcBuf += sizeof(struct in_addr);
        cbBuf -= sizeof(struct in_addr);
        break;

      case DNSREC_TYPE_MX:
        if ( cbBuf < sizeof(USHORT) )
        {
          fOverflow = TRUE;
          break;
        }
        *((PUSHORT)pcBuf) = pRec->aItems[ulIdx].cri_pMXName->usLevel;
        pcBuf += sizeof(USHORT);
        cbBuf -= sizeof(USHORT);

      default:
      {
        PSZ            pszText = pRec->usType == DNSREC_TYPE_MX
                                 ? &pRec->aItems[ulIdx].cri_pMXName->acName
                                 : pRec->aItems[ulIdx].cri_pszName;
        ULONG          cbText = strlen( pszText ) + 1;

        if ( cbBuf <= cbText )
        {
          fOverflow = TRUE;
          break;
        }

        memcpy( pcBuf, pszText, cbText );
        pcBuf += cbText;
        cbBuf -= cbText;
      }
    }

    if ( fOverflow )
      break;
    cItems++;
  }

  *pulItems = cItems;
  return fOverflow ? DNS_OVERFLOW : pRec->ulRCode;
}


//           Encode request / decode answer utils
//           ------------------------------------

static ULONG _encName(PSZ pszName, ULONG cbBuf, PCHAR pcBuf)
{
  PCHAR      pcDstStart = pcBuf;
  PCHAR      pcDot;
  ULONG      cbChunk;

  do
  {
    pcDot = strchr( pszName, '.' );
    if ( pcDot == NULL )
      pcDot = strchr( pszName, '\0' );

    cbChunk = pcDot - pszName;          // Name part length.

    if ( ( cbChunk > 63 ) || ( cbBuf <= cbChunk ) )
      // Too long part of name or not enough buffer space.
      return 0;

    *pcBuf = (CHAR)cbChunk;             // Store part length.
    pcBuf++;
    memcpy( pcBuf, pszName, cbChunk );
    pcBuf += cbChunk;

    pszName += cbChunk;
    if ( *pszName == '.' )
      pszName++;
  }
  while( *pszName != '\0' );

  return pcBuf - pcDstStart;
}

static PCHAR _decName(ULONG cbDnsPkt, PDNSPKT pDnsPkt, PCHAR pcSrc,
                      ULONG cbBuf, PCHAR pcBuf)
{
  ULONG      cbChunk = *pcSrc;
  PCHAR      pcRet = NULL;
  PCHAR      pcEnd = (PCHAR)pDnsPkt + cbDnsPkt; 

  if ( cbChunk == 0 )
    return NULL;

  while( cbChunk != 0 )
  {
    if ( (cbChunk & 0xC0) != 0 )
    {
      // Offset mark - jump to the new place in the packet.

      if ( pcRet == NULL )  // We'll return pointer to the next byte in
        pcRet = pcSrc + 2;  // the _first_ source byte sequence - store it.

      // Set new read position in the packet.
      pcSrc = (PCHAR)pDnsPkt + ( ntohs( *((PUSHORT)pcSrc) ) & 0x1FFF );
      cbChunk = *pcSrc;
      continue;
    }

    if ( ( (cbChunk + 1) >= cbBuf ) || ( &pcSrc[cbChunk] >= pcEnd ) )
      return NULL;

    pcSrc++;
    memcpy( pcBuf, pcSrc, cbChunk );
    pcBuf += cbChunk;
    cbBuf -= cbChunk;
    pcSrc += cbChunk;
    cbChunk = *pcSrc;
    *(pcBuf++) = cbChunk == 0 ? '\0' : '.';
  }

  return pcRet != NULL ? pcRet : ( pcSrc + 1 );
}

// PDNSCACHEREC _parseAnswer(ULONG cbDnsPkt, PDNSPKT pDnsPkt)
//
// Creates object DNSCACHEREC from DNS packet and stores it in cache.
// Cache must be locked with _cacheLock().
// Returns NULL if packet is invalid.

static PDNSCACHEREC _parseAnswer(ULONG cbDnsPkt, PDNSPKT pDnsPkt)
{
  PCHAR                pcScan;
  PCHAR                pcEnd = (PCHAR)pDnsPkt + cbDnsPkt;
  ULONG                ulIdx;
  CHAR                 acBuf[320];
  USHORT               usType;
  ULONG                ulAnswerType;
  ULONG                ulDataLength;
  PDNSCACHEREC         pRec;
  time_t               timeCurrent, timeExpire;
  ULONG                ulItemIdx;
  PCHAR                pcData;

  if ( cbDnsPkt < 13 )
  {
    debug( "Too short answer" );
    return NULL;
  }

  if ( ( pDnsPkt->usFlags & DNSPKT_FL_QR ) == 0 )
  {
    debug( "Not answer packet" );
    return NULL;
  }

/*  if ( pDnsPkt->cAnswers == 0 )
  {
    debug( "Name not exist" );
    return pRec;
  }*/

  // Read requested names from the answer.

  pcScan = &pDnsPkt->acData[0];
  for( ulIdx = 0; ulIdx < ntohs( pDnsPkt->cQueries ); ulIdx++ )
  {
    pcScan = _decName( cbDnsPkt, pDnsPkt, pcScan, sizeof(acBuf), &acBuf );
    if ( pcScan == NULL )
    {
      debug( "Cannot decode requested name in answer" );
      return NULL;
    }
  }

  usType = *((PUSHORT)pcScan);
  switch( usType )
  {
    case DNSREC_TYPE_A:
    case DNSREC_TYPE_NS:
    case DNSREC_TYPE_SOA:
    case DNSREC_TYPE_PTR:
    case DNSREC_TYPE_MX:
    case DNSREC_TYPE_TXT:
      break;

    default:
      debug( "Unknown answer type: 0x%X", usType );
      return NULL;
  }

  pcScan += 2 * sizeof(USHORT); // Skip query type and query class.
  if ( pcScan > pcEnd )
  {
    debug( "Not full answer" );
    return NULL;
  }

  // Create a new cache record.
  pRec = _cacheRecNew( usType, &acBuf,
                       (pDnsPkt->usFlags & DNSPKT_FL_RCODE) >> 8,   // RCODE
                       ntohs( pDnsPkt->cAnswers ) );
  if ( pRec == NULL )
    return NULL;

  // Fill record's items.

  time( &timeCurrent );
  if ( pRec->cItems == 0 )
  {
    pRec->timeExpire = timeCurrent + NEGATIVE_ANSWER_TTL;
    return pRec;
  }

  pRec->timeExpire = 0;
  ulItemIdx = 0;
  for( ulIdx = 0; ulIdx < pRec->cItems; ulIdx++ )
  {
    // Read name from answer.
    pcScan = _decName( cbDnsPkt, pDnsPkt, pcScan, sizeof(acBuf), &acBuf );
    if ( pcScan == NULL )
    {
      debug( "Cannot decode name in answer" );
      _cacheRecFree( pRec );
      return NULL;
    }

    // Answer type.
    ulAnswerType = *((PUSHORT)pcScan);
    pcScan += 2 * sizeof(USHORT); // Skip record type and record class.

    // TTL.

    timeExpire = timeCurrent + ntohl( *((PULONG)pcScan) );
    pRec->aItems[ulItemIdx].timeExpire = timeExpire;
    // Record expire time = max. answers expite rime.
    if ( pRec->timeExpire < timeExpire )
      pRec->timeExpire = timeExpire;

    pcScan += sizeof(ULONG); // Skip TTL.

    ulDataLength = ntohs( *((PUSHORT)pcScan) );
    pcScan += sizeof(USHORT); // Skip data bytes couter.

    pcData = pcScan;

    pcScan += ulDataLength; // Skip data.
    if ( pcScan > pcEnd )
    {
      debug( "Not full answer" );
      return NULL;
    }

    if ( ulAnswerType != usType )
    {
      debug( "Answer type (0x%X) is not equal requested type (0x%X)",
             ulAnswerType, usType );
      continue;
    }

    switch( usType )
    {
      case DNSREC_TYPE_A:
        if ( ulDataLength != 4 )
        {
          debug( "Invalid length of data for IP-address: %u", ulDataLength );
          continue;
        }

        *((u_long *)&pRec->aItems[ulItemIdx].cri_stAddr) = *((u_long *)pcData);
        break;

      case DNSREC_TYPE_NS:
      case DNSREC_TYPE_SOA:
      case DNSREC_TYPE_PTR:
        if ( _decName( cbDnsPkt, pDnsPkt, pcData, sizeof(acBuf), &acBuf ) == NULL )
        {
          debug( "Cannot decode name in answer" );
          continue;
        }

        pRec->aItems[ulItemIdx].cri_pszName = hstrdup( &acBuf );
        if ( pRec->aItems[ulItemIdx].cri_pszName == NULL )
        {
          debug( "Not enough memory" );
          _cacheRecFree( pRec );
          return NULL;
        }
        break;

      case DNSREC_TYPE_TXT:
        pRec->aItems[ulItemIdx].cri_pszName = hmalloc( *pcData + 1 );
        if ( pRec->aItems[ulItemIdx].cri_pszName == NULL )
        {
          debug( "Not enough memory" );
          _cacheRecFree( pRec );
          return NULL;
        }

        memcpy( pRec->aItems[ulItemIdx].cri_pszName, &pcData[1], *pcData );
        pRec->aItems[ulItemIdx].cri_pszName[*pcData] = '\0';
        break;

      case DNSREC_TYPE_MX:
        if ( _decName( cbDnsPkt, pDnsPkt, &pcData[2], sizeof(acBuf), &acBuf )
               == NULL )
        {
          debug( "Cannot decode name in answer" );
          return FALSE;
        }

        pRec->aItems[ulItemIdx].cri_pMXName =
          hmalloc( sizeof(MXNAME) + strlen( &acBuf ) );
        if ( pRec->aItems[ulItemIdx].cri_pMXName == NULL )
        {
          debug( "Not enough memory" );
          _cacheRecFree( pRec );
          return NULL;
        }

        strcpy( &pRec->aItems[ulItemIdx].cri_pMXName->acName, &acBuf );
        pRec->aItems[ulItemIdx].cri_pMXName->usLevel =
          ntohs( *((PUSHORT)pcData) );
        break;

      default:
        debug( "Answer type not implemented: 0x%X", usType );
    }

    ulItemIdx++;
  }

  // Correct items counter.
  pRec->cItems = ulItemIdx;

  return pRec;
}


//           Public routines
//           ---------------

BOOL dnsInit()
{
  if ( hmtxCache != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  _cacheInit();
  if ( hmtxCache == NULLHANDLE )
    return FALSE;

  return TRUE;
}

VOID dnsDone()
{
  if ( hmtxCache == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  _cacheDone();
}

// BOOL dnsSetServer(struct in_addr *pAddr, USHORT usPort)
//
// Set new DNS server address. If given port is 0, default DNS port 53 will
// be used. ulTimeout - answers waiting timeout in seconds.

BOOL dnsSetServer(struct in_addr *pAddr, USHORT usPort)
{
  stNSAddr = *pAddr;
  usNSPort = usPort == 0 ? 53 : usPort;
  return TRUE;
}

// ULONG dnsRequest(USHORT usType, PSZ pszName, ULONG cbBuf, PCHAR pcBuf,
//                  PULONG pulItems)
//
// usType: type of the request to the NS-server (DNSREC_TYPE_xxxxx)
// pszName: requested name.
// Results (ASCIIZ string / struct in_addr / 2 bytes MX level, ASCIIZ MX name)
// stores to the buffer pcBuf up to cbBuf bytes.
// Number of stored results stores in *pulItems.
// Returns DNS_xxxxx code.

ULONG dnsRequest(USHORT usType, PSZ pszName, ULONG cbBuf, PCHAR pcBuf,
                 PULONG pulItems)
{
  static ULONG         ulReqId = 24815162342; // Station 3. The Swan. ;-)
  CHAR                 acDnsPkt[1024];
  PDNSPKT              pDnsPkt = (PDNSPKT)&acDnsPkt;
  ULONG                cbName = 0;
  struct sockaddr_in   stSockAddr = { 0 };
  int                  iSock;
  int                  cbSockAddr;
  int                  cbDnsPkt;
  PDNSCACHEREC         pRec;
  ULONG                ulRes;
  ULONG                ulTry;
  struct timeval       stTimeVal;

  // Search in cache.

  _cacheLock();
  pRec = _cacheFind( usType, pszName );
  if ( pRec != NULL )
    goto readCacheRecord;
  _cacheUnlock();

  // Fill packet.

  pDnsPkt->usId       = (ulReqId++);       // Request id.
  pDnsPkt->usFlags    = DNSPKT_FL_QR;      // Request flag.
  pDnsPkt->cQueries   = 0x0100;            // One question (net byte order).
  pDnsPkt->cAnswers   = 0;
  pDnsPkt->cRights    = 0;
  pDnsPkt->cAdditions = 0;

  cbName = _encName( pszName, sizeof(acDnsPkt) - sizeof(DNSPKT) - 2,
                     &pDnsPkt->acData );
  if ( cbName == 0 )
  {
    *pulItems = 0;
    return DNS_INVALID_NAME;
  }
  pDnsPkt->acData[cbName++] = '\0'; // Mark end of host name.

  *(PUSHORT)&pDnsPkt->acData[cbName] = usType;
  cbName += 2;
  *(PUSHORT)&pDnsPkt->acData[cbName] = DNSREC_CLASS_INET;
  cbName += 2 + ( sizeof(DNSPKT) - 1 );
    // cbName - length of packet.

  // Fill the server's address.
  stSockAddr.sin_family = AF_INET;
  stSockAddr.sin_port   = htons( usNSPort );
  stSockAddr.sin_addr   = stNSAddr;
  // Create the socket.
  iSock = socketNew( FALSE );
  if ( iSock == -1 )
  {
    debug( "Does socketInit() called?" );
    *pulItems = 0;
    return DNS_SEND_FAILED;
  }

  // We will try to send the packet REQ_MAX_ATTEMPTS times with timeouts listed
  // in ulNSTimeouts[].
  for( ulTry = 0; ulTry < REQ_MAX_ATTEMPTS; ulTry++ )
  {
    // Send request to the NS.
    if ( sendto( iSock, &acDnsPkt, cbName, 0, 
                 (struct sockaddr *)&stSockAddr, sizeof(stSockAddr) ) != cbName )
    {
      debug( "sendto() failed" );
      socketDestroy( iSock );
      *pulItems = 0;
      return DNS_SEND_FAILED;
    }

    // Set receive timeout.
    stTimeVal.tv_sec  = ulNSTimeouts[ulTry];
    stTimeVal.tv_usec = 0;
    if ( setsockopt( iSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&stTimeVal,
                     sizeof(struct timeval) ) < 0 )
    {
      debug( "setsockopt() failed, error: %u", sock_errno() );
      socketDestroy( iSock );
      *pulItems = 0;
      return DNS_RECV_FAILED;
    }

    // Receive (wait for) answer.
    cbSockAddr = sizeof(struct sockaddr_in);
    cbDnsPkt = recvfrom( iSock, &acDnsPkt, sizeof(acDnsPkt), 0,
                         (struct sockaddr *)&stSockAddr, &cbSockAddr );
    if ( cbDnsPkt > 0 )
      break;

    if ( cbDnsPkt == -1 )
    {
      int      iErr = sock_errno();

      if ( iErr != SOCEAGAIN )   // SOCEAGAIN - wait timed out.
      {
        debug( "recvfrom() failed, error: %u", iErr );
        socketDestroy( iSock );
        *pulItems = 0;
        return iErr == SOCEINTR ? DNS_CANCEL : DNS_RECV_FAILED;
      }
    }

    debug( "Try %u failed", ulTry );
  }
  socketDestroy( iSock );

  if ( cbDnsPkt == -1 )
  {
    debug( "Answer wait timeout" );
    *pulItems = 0;
    return DNS_TIMEOUT;
  }

  _cacheLock();
  // Parse answer and store (on success) it in cache.
  pRec = _parseAnswer( cbDnsPkt, pDnsPkt );
  if ( pRec == NULL )
  {
    // Name not found or invalid answer.
    *pulItems = 0;
    ulRes = DNS_INVALID_FORMAT;
  }
  else if ( pRec->usType != usType )
  {
    // Theoretically possible situation - type of answer is not same as the
    // type of the query.
    debug( "Request type: 0x%X, answer type: 0x%X", usType, pRec->usType );
    *pulItems = 0;
    ulRes = DNS_UNREQ_ANSWER_TYPE;
  }
  else
  {
readCacheRecord:
    // Have answer - parse data from the cached object to the user's buffer.
    ulRes = _cacheRecRead( pRec, cbBuf, pcBuf, pulItems );
  }
  _cacheUnlock();

  return ulRes;
}

ULONG dnsPTRRequest(struct in_addr stInAddr, ULONG cbBuf, PCHAR pcBuf,
                    PULONG pulItems)
{
  CHAR       acName[64];

  sprintf( &acName, "%u.%u.%u.%u.in-addr.arpa",
           ((PCHAR)&stInAddr)[3], ((PCHAR)&stInAddr)[2],
           ((PCHAR)&stInAddr)[1], ((PCHAR)&stInAddr)[0] );

  return dnsRequest( DNSREC_TYPE_PTR, &acName, cbBuf, pcBuf, pulItems );
}

// ULONG dnsValidateDomainNames(struct in_addr stIP, PULONG pulMaxReq,
//                              ULONG cbBuf, PCHAR pcBuf, PULONG pulItems)
//
// Looking for validated domain names for an ip-address stIP. All validated
// domain names has A-record for given ip-address.
// pulMaxReq: In: limit for requests to NS-server, Out: left requests counter.
//            May be a NULL.
// The resulting ASCIIZ names stores in the buffer pcBuf up to cbBuf bytes.
// Number of stored names stores in *pulItems.
// Returns DNS_xxxxx code.

ULONG dnsValidateDomainNames(struct in_addr stIP, PULONG pulMaxReq, ULONG cbBuf,
                             PCHAR pcBuf, PULONG pulItems)
{
  ULONG                ulRC;
  CHAR                 acPTRRes[512];
  ULONG                cPTRRes;
  PCHAR                pPTRRes = &acPTRRes;
  CHAR                 acARes[512];
  ULONG                cARes;
  struct in_addr       *pIP;
  ULONG                ulLen;
  ULONG                ulItems = 0;

  *pulItems = 0;
  if ( ( pulMaxReq != NULL ) && ( *pulMaxReq == 0 ) )
    return DNS_NOERROR;

  ulRC = dnsPTRRequest( stIP, sizeof(acPTRRes), &acPTRRes, &cPTRRes );
  if ( pulMaxReq != NULL )
    (*pulMaxReq)--;
  if ( ulRC != DNS_NOERROR )
    return ulRC;

  for( ; cPTRRes > 0; cPTRRes--, pPTRRes = strchr( pPTRRes, '\0' ) + 1 )
  {
    if ( ( pulMaxReq != NULL ) && ( *pulMaxReq == 0 ) )
      return DNS_NOERROR;

    ulRC = dnsRequest( DNSREC_TYPE_A, pPTRRes, sizeof(acARes), &acARes,
                       &cARes );
    if ( pulMaxReq != NULL )
      (*pulMaxReq)--;
    if ( ( ulRC != DNS_NOERROR ) || ( cARes == 0 ) )
      continue;

    for( pIP = (struct in_addr *)&acARes;
         ( cARes > 0 ) && ( pIP->s_addr != stIP.s_addr ); cARes--, pIP++ );
    if ( cARes == 0 )
      continue;

    ulLen = strlen( pPTRRes );
    if ( ulLen < cbBuf )
    {
      strcpy( pcBuf, pPTRRes );
      pcBuf += ulLen;
      cbBuf -= ulLen;
      ulItems++;
    }
  }

  *pulItems = ulItems;
  return DNS_NOERROR;
}

ULONG dnsGetCacheCount()
{
  ULONG      ulCount;

  _cacheLock();
  ulCount = lnkseqGetCount( &stCache );
  _cacheUnlock();

  return ulCount;
}
