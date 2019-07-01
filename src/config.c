#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include "xpl.h"
#include "rwmutex.h"
#include "sf.h"
#include "log.h"
#include "xmlutil.h"
#define CONFIG_C
#include "hmem.h"
#include "config.h"
#include "debug.h"     // Must be the last.

#define _CFG_MAX_THREADS         100
#define _CFG_DEF_THREADS         5
#define _CFG_DEF_WEASEL_LOG_PIPE "WeaselTransLog"
#define _CFG_MAX_PIPES           100
#define _CFG_DEF_PIPES           5
#define _CFG_MIN_COMMAND_TIMEOUT 1
#define _CFG_MAX_COMMAND_TIMEOUT (60*60)
#define _CFG_DEF_COMMAND_TIMEOUT (60*3)
#define _CFG_DEF_GLMASK          0x00FFFFFF          // 255.255.255.0
#define _CFG_DEF_CFNUM           95
#define _CFG_DEF_CFDEN           100
#define _CFG_DEF_CFTTL           (60 * 60 * 24 * 14)
#define _CFG_DEF_MAX_MESSAGE     104857600
#define _CFG_DEF_MAX_BODY_PART   (300 * 1024)

#define _CFG_SW_ON               "1 YES Y ON"

PCONFIG                pConfig = NULL;

static RWMTX           rwmtxConfig = { 0 };
static PSZ             pszCfgFile = NULL;


//           Host lists
//           ----------

typedef struct _HOSTREC {
  SEQOBJ               seqObj;

  LONG                 lScore;
  ULONG                cbName;             // If 0 - acName is two ULONG.
  CHAR                 acName[1];
} HOSTREC, *PHOSTREC;

BOOL cfgHostListAdd(PLINKSEQ plsList, LONG lScore, ULONG cbHost, PCHAR pcHost)
{
  struct in_addr       stInAddrFirst, stInAddrLast;
  PHOSTREC             pHost;

  if ( utilStrToInAddrRange( cbHost, pcHost, &stInAddrFirst, &stInAddrLast ) )
  {
    pHost = hmalloc( ( sizeof(HOSTREC) - 1 ) +
                         ( 2 * sizeof(struct in_addr) ) );
    if ( pHost != NULL )
    {
      pHost->cbName = 0;
      ((PULONG)&pHost->acName)[0] = ntohl( stInAddrFirst.s_addr );
      ((PULONG)&pHost->acName)[1] = ntohl( stInAddrLast.s_addr );
    }
  }
  else
  {
    pHost = hmalloc( sizeof(HOSTREC) + cbHost );
    if ( pHost != NULL )
    {
      pHost->cbName = cbHost;
      memcpy( &pHost->acName, pcHost, cbHost );
      pHost->acName[cbHost] = '\0';
    }
  }

  if ( pHost == NULL )
  {
    debug( "Not enough memory" );
    return FALSE;
  }
  pHost->lScore = lScore;

  lnkseqAdd( plsList, pHost );
  return TRUE;
}

BOOL cfgHostListAddList(PLINKSEQ plsList, LONG lScore, ULONG cbHosts,
                        PCHAR pcHosts)
{
  ULONG      cbHost;
  PCHAR      pcHost;

  while( utilStrCutWord( &cbHosts, &pcHosts, &cbHost, &pcHost ) )
  {
    if ( !cfgHostListAdd( plsList, lScore, cbHost, pcHost ) )
      return FALSE;
  }

  return TRUE;
}

BOOL cfgHostListCheck(PLINKSEQ plsList, struct in_addr stInAddr,
                      ULONG cbName, PCHAR pcName, PLONG plScore)
{
  ULONG                ulAddr = ntohl( stInAddr.s_addr );
  PHOSTREC             pHost;

  for( pHost = (PHOSTREC)lnkseqGetFirst( plsList );
       pHost != NULL; pHost = (PHOSTREC)lnkseqGetNext( pHost ) )
  {
    if ( pHost->cbName == 0 )
    {
      if ( ulAddr >= ((PULONG)&pHost->acName)[0] &&
           ulAddr <= ((PULONG)&pHost->acName)[1] )
        break;
    }
    else if ( utilIsMatch( cbName, pcName, pHost->cbName, &pHost->acName ) )
      break;
  }

  if ( pHost == NULL )
    return FALSE;

  if ( plScore != NULL )
    *plScore = pHost->lScore;

  return TRUE;
}

BOOL cfgHostListCheckIP(PLINKSEQ plsList, struct in_addr stInAddr,
                        PLONG plScore)
{
  PCHAR                pcAddr = inet_ntoa( stInAddr );

  return cfgHostListCheck( plsList, stInAddr, strlen( pcAddr ), pcAddr,
                           plScore );
}

BOOL cfgHostListCheckName(PLINKSEQ plsList, ULONG cbHost, PCHAR pcHost,
                          PLONG plScore)
{
  CHAR                 acAddr[24];
  struct in_addr       stInAddr;

  if ( cbHost < sizeof(acAddr) )
  {
    memcpy( &acAddr, pcHost, cbHost );
    acAddr[cbHost] = '\0';
    stInAddr.s_addr = inet_addr( &acAddr );
  }
  else
    stInAddr.s_addr = (u_long)(-1);

  return cfgHostListCheck( plsList, stInAddr, cbHost, pcHost, plScore );
}


//           Configuration XML tree
//           ----------------------

// Utils
// -----


static VOID _cfgAddWeaselLogPipe(PCONFIG pConfig, ULONG cbName, PCHAR pcName)
{
  ULONG      cbWeaselLogPipes;
  PSZ        pszNew;

  if ( ( cbName != 0 ) && ( pcName != NULL ) )
  {
    if ( pConfig->pcWeaselLogPipes == NULL )
      cbWeaselLogPipes = 0;
    else
      cbWeaselLogPipes = strlen( pConfig->pcWeaselLogPipes ) + 1;

    pszNew = hrealloc( pConfig->pcWeaselLogPipes,
                       cbWeaselLogPipes + cbName + 2 );

    if ( pszNew != NULL )
    {
      memcpy( &pszNew[cbWeaselLogPipes], pcName, cbName );
      cbWeaselLogPipes += cbName;
      pszNew[cbWeaselLogPipes++] = '\0';  // End of pipe name.
      pszNew[cbWeaselLogPipes]   = '\0';  // Double zero - end of list.

      pConfig->pcWeaselLogPipes = pszNew;
    }
  }
}

// BOOL _cfgStrToScore(ULONG cbValue, PCHAR pcValue, PLONG plScore)
//
// Converts string cbValue/pcValue to the score value. Returns FALSE on error.

static BOOL _cfgStrToScore(ULONG cbValue, PCHAR pcValue, PLONG plScore)
{
  if ( utilStrToLong( cbValue, pcValue, 0, 0, plScore ) )
    return TRUE;

  switch( utilStrWordIndex( "SPAM NOT_SPAM NOT-SPAM NOTSPAM NONE NEUTRAL",
                            cbValue, pcValue ) )
  {
    case -1:
      return FALSE;

    case 0:
      *plScore = SF_SCORE_SPAM;
      break;

    case 1:
    case 2:
    case 3:
      *plScore = SF_SCORE_NOT_SPAM;
      break;

    case 4:
    case 5:
      *plScore = SF_SCORE_NONE;
      break;
  }

  return TRUE;
}

// BOOL __cfgAttrSwitch(xmlNodePtr pNode, PSZ pszAttribute)
//
// Returns TRUE when attribute's value is one of listed in _CFG_SW_ON values
// ("1", "YES", "Y", "ON").

static BOOL __cfgAttrSwitch(xmlNodePtr pNode, PSZ pszAttribute)
{
  PSZ        pszAttr = xmlGetNoNsProp( pNode, pszAttribute );

  return ( pszAttr != NULL ) &&
         ( utilStrWordIndex( _CFG_SW_ON, strlen( pszAttr ), pszAttr ) != -1 );
}

// BOOL __cfgFillHostListScore(PLINKSEQ plsHostList, xmlNodePtr pNode,
//                             BOOL fSplitOnWords)
//
// Makes list of hosts from XML-tree:
// <pNode><addr score="?">str</addr>...</pNode>
// If fSplitOnWords is TRUE - content of <addr> will be splited on words
// (substrings separated by SPACE).

static BOOL __cfgFillHostListScore(PLINKSEQ plsHostList, xmlNodePtr pNode,
                                   BOOL fSplitOnWords)
{
  ULONG      cbHosts;
  PSZ        pszHosts;
  PSZ        pszScore;
  LONG       lScore;

  for( pNode = pNode->children; pNode != NULL; pNode = pNode->next )
  {
    if ( xmlIsBlankNode( pNode ) || ( pNode->name == NULL ) ||
         ( ( stricmp( pNode->name, "addr" ) != 0 ) &&
           ( stricmp( pNode->name, "pattern" ) != 0 ) ) )
      continue;

    pszHosts = xmluGetNodeTextSZ( pNode );
    pszScore = xmlGetNoNsProp( pNode, "score" );
    if ( pszScore == NULL )
      lScore = SF_SCORE_NONE;
    else if ( !_cfgStrToScore( strlen( pszScore ), pszScore, &lScore ) )
    {
      xmluLog( pNode, "Invalid score value: \"%s\".", pszScore );
      return FALSE;
    }

    cbHosts = strlen( pszHosts );

    if ( fSplitOnWords )
      cfgHostListAddList( plsHostList, lScore, cbHosts, pszHosts );
    else
      cfgHostListAdd( plsHostList, lScore, cbHosts, pszHosts );
  }

  return TRUE;
}


// Parse XML trees.
// ----------------


// BOOL __cfgReadURIBL(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <uribl> XML-tree.

static BOOL __cfgReadURIBL(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  lRC = xmluBeginScan( pNode, &pScan,
          "provider:rm hits score-positive:r score-neutral:r not-spam:em" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // provider
        fNoError = utilStrAddWords( &pConfig->cbURIBLProviders,
                                    &pConfig->pcURIBLProviders,
                                    pScan->cbValue, pScan->pcValue,
                                    utilVerifyDomainName );
        break;

      case 1: // hits
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 0, ~0,
                                   &pConfig->ulURIBLHits );
        break;

      case 2: // score-positive
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreURIBLPositive );
        break;

      case 3: // score-neutral
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreURIBLNeutral );
        break;

      case 4: // not-spam
        utilStrAddWords( &pConfig->cbURIBLNotSpam, &pConfig->pcURIBLNotSpam,
                         pScan->cbValue, pScan->pcValue, NULL );
        break;
    }

    if ( !fNoError )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadFrequency(PCONFIG pConfig, xmlNodePtr pNode,
//                         PULONG pulMaxEvents, PULONG pulDuration,
//                         PULONG pulExpiration, PLINKSEQ plsIgnore)
//
// Parse <ip-frequency> XML-tree.

static BOOL __cfgReadFrequency(PCONFIG pConfig, xmlNodePtr pNode,
                               PULONG pulMaxEvents, PULONG pulDuration,
                               PULONG pulExpiration, PLINKSEQ plsIgnore)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  lRC = xmluBeginScan( pNode, &pScan, "max-ataccept max-events duration:r "
                                      "expiration ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // max-ataccept (old syntax)
        xmluScanLog( pScan, "<max-ataccept> is an obsolete parameter, "
                            "please use <max-events>" );
      case 1: // max-events
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 1, ~0,
                                   pulMaxEvents );
        break;

      case 2: // duration
        fNoError = utilStrTimeToSec( pScan->cbValue, pScan->pcValue,
                                     pulDuration ) &&
                   ( *pulDuration >= 10 ) && ( *pulDuration <= 86400 );
        break;

      case 3: // expiration
        fNoError = utilStrTimeToSec( pScan->cbValue, pScan->pcValue,
                                     pulExpiration ) &&
                   ( *pulExpiration <= 86400 );
        break;

      case 4: // ignore
        if ( plsIgnore != NULL )
          cfgHostListAddList( plsIgnore, 0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC != 0 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  if ( *pulMaxEvents > (*pulDuration * 100) )
  {
    xmluLog( pNode, "Invalid <duration> / <max-events> values." );
    return FALSE;
  }

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadRWL(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <rwl> XML-tree.

static BOOL __cfgReadRWL(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;

  lRC = xmluBeginScan( pNode, &pScan, "provider:rm score:rm ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // provider
        fNoError = utilStrAddWords( &pConfig->cbRWLProviders,
                                    &pConfig->pcRWLProviders,
                                    pScan->cbValue, pScan->pcValue,
                                    utilVerifyDomainName );
        break;

      case 1: // score
        {
          ULONG      ulLevel;

          pszAttr = xmlGetNoNsProp( pScan->xmlNode, "level" );
          if ( ( pszAttr == NULL ) ||
               !utilStrToULong( strlen( pszAttr ), pszAttr, 1, 3, &ulLevel ) )
          {
            fNoError = FALSE;
            break;
          }

          fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                     &pConfig->alScoreRWL[ulLevel - 1] );
        }
        break;

      case 2: // ignore
        cfgHostListAddList( &pConfig->lsHostListRWLIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadAutoWhitelist(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <autowhitelist> XML-tree.

static BOOL __cfgReadAutoWhitelist(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr = xmlGetNoNsProp( pNode, "ttl" );

  if ( ( pszAttr != NULL ) &&
       !utilStrTimeToSec( strlen(pszAttr), pszAttr,
                          &pConfig->ulTTLAutoWhiteListed ) )
  {
    xmluLog( pNode, "Invalid time-to-live value: \"%s\".", pszAttr );
    return FALSE;
  }

  lRC = xmluBeginScan( pNode, &pScan, "ignore-senders:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // ignore-senders
        utilStrAddWords( &pConfig->cbAutoWhitelistIgnoreSenders,
                         &pConfig->pcAutoWhitelistIgnoreSenders,
                         pScan->cbValue, pScan->pcValue, NULL );
        break;
    }

    if ( !fNoError )
      break;

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadSpamTrap(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <spamtrap> XML-tree.

static BOOL __cfgReadSpamTrap(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;

  lRC = xmluBeginScan( pNode, &pScan, "address:rm score-client" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // address
        fNoError = utilStrAddWords( &pConfig->cbSpamTrap, &pConfig->pcSpamTrap,
                                     pScan->cbValue, pScan->pcValue,
                                     NULL );
        break;

      case 1: // score-client
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "ttl" );
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                    &pConfig->lScoreSpamTrapClient );

        if ( fNoError && ( pszAttr != NULL ) )
          fNoError = utilStrTimeToSec( strlen( pszAttr ), pszAttr,
                                       &pConfig->ulSpamTrapClientTTL );
        break;
    }

    if ( !fNoError )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL _cfgReadExtClntLocSenderLocRcpt( pConfig, pScan->xmlNode )
//
// Parse <extclnt-locsender-locrcpt> XML-tree.

static BOOL __cfgReadNonexistentLocSender(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;

  lRC = xmluBeginScan( pNode, &pScan, "score:r score-client" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // score
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreNonexistentLocSndr );
        break;

      case 1: // score-client
        pszAttr = xmlGetNoNsProp( pNode, "expiration" );

        if ( ( pszAttr != NULL ) &&
             !utilStrTimeToSec( strlen(pszAttr), pszAttr,
                             &pConfig->ulExpirationClientNonexistentLocSndr ) )
        {
          xmluLog( pNode, "Invalid expiration value: \"%s\".", pszAttr );
          return FALSE;
        }

        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreClientNonexistentLocSndr );
        break;
    }

    if ( !fNoError )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

static BOOL _cfgReadExtClntLocSenderLocRcpt(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  lRC = xmluBeginScan( pNode, &pScan, "nonexistent-locsender:e score:r" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // nonexistent-locsender
        fNoError = __cfgReadNonexistentLocSender( pConfig, pScan->xmlNode );
        break;

      case 1: // score
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                       &pConfig->lScoreExtClntLocSndrLocRcpt );
        break;
    }

    if ( !fNoError )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadGreylist(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <greylist> XML-tree.

static BOOL __cfgReadGreylist(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr = xmlGetNoNsProp( pNode, "ttl" );

  if ( ( pszAttr != NULL ) &&
       !utilStrTimeToSec( strlen(pszAttr), pszAttr, &pConfig->ulGreylistTTL ) )
  {
    xmluLog( pNode, "Invalid time-to-live value: \"%s\".", pszAttr );
    return FALSE;
  }

  lRC = xmluBeginScan( pNode, &pScan, "coefficient mask ignore-senders:m "
                                      "ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // coefficient
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "num" );
        pConfig->ulGreylistCfNum = pszAttr == NULL ? 0 : atol( pszAttr );
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "den" );
        pConfig->ulGreylistCfDen = pszAttr == NULL ? 0 : atol( pszAttr );
        if ( ( pConfig->ulGreylistCfDen ) == 0 ||
             ( pConfig->ulGreylistCfNum > pConfig->ulGreylistCfDen ) )
        {
          xmluScanLog( pScan, "Invalid num/den value." );
          fNoError = FALSE;
        }
        else if ( !utilStrTimeToSec( pScan->cbValue, pScan->pcValue,
                                     &pConfig->ulGreylistCfTTL ) )
        {
          xmluScanLog( pScan, "Invalid time value." );
          fNoError = FALSE;
        }
        break;

      case 1:
        if ( !utilStrToMask( pScan->cbValue, pScan->pcValue,
                             &pConfig->stGreylistMask ) )
        {
          xmluScanLog( pScan, "Invalid mask value." );
          fNoError = FALSE;
        }
        break;

      case 2: // ignore-senders
        utilStrAddWords( &pConfig->cbGreylistIgnoreSenders,
                         &pConfig->pcGreylistIgnoreSenders,
                         pScan->cbValue, pScan->pcValue, NULL );
        break;

      case 3: // ignore
        cfgHostListAddList( &pConfig->lsHostListGreylistIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
      break;

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadDNSBL(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <dnsbl> XML-tree.

static BOOL __cfgReadDNSBL(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;
  ULONG                cDNSBL;
  PDNSBL               pDNSBL;

  cDNSBL = xmluChildElementCount( pNode, "provider" );
  if ( cDNSBL != 0 )
  {
    pDNSBL = hcalloc( cDNSBL, sizeof(DNSBL) );
    if ( pDNSBL == NULL )
    {
      debug( "Not enough memory" );
      return FALSE;
    }
    pConfig->paDNSBL = pDNSBL;
  }

  lRC = xmluBeginScan( pNode, &pScan, "provider:rem hits:r ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // provider
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "name" );

        if ( ( pszAttr == NULL ) || ( strlen( pszAttr ) > 112 ) ||
             !utilVerifyDomainName( strlen( pszAttr ), pszAttr ) )
        {
          xmluScanLog( pScan, "Invalid or not specified attribute \"name\"." );
        }
        else
        {
          lnkseqInit( &pDNSBL->lsHostListAnswers );
         
          if ( __cfgFillHostListScore( &pDNSBL->lsHostListAnswers,
                                       pScan->xmlNode, TRUE ) )
          {
            pDNSBL->pszName = hstrdup( pszAttr );
            pDNSBL++;
            pConfig->cDNSBL++;
            break;
          }

          lnkseqFree( &pDNSBL->lsHostListAnswers, PHOSTREC, hfree );
        }

        fNoError = FALSE;
        break;

      case 1: // hits
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 0, ~0,
                                   &pConfig->ulDNSBLMaxHits );
        break;

      case 2: // ignore
        cfgHostListAddList( &pConfig->lsHostListDNSBLIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC != 1 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadMBoxCheck(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <sender-mailbox-check> XML-tree.

static BOOL __cfgReadMBoxCheck(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC, lResult;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;

  lRC = xmluBeginScan( pNode, &pScan, "score:m ignore-senders:m ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // score
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "result" );
        if ( pszAttr == NULL )
        {
          xmluLog( pScan->xmlNode, "Attribute \"result\" is not specified." );
          fNoError = FALSE;
          break;
        }

        lResult = utilStrWordIndex( "EXIST NOT-EXIST NO-POSTMASTER ANY-EXIST "
                                    "FAILED CONNECTION-FAILED TIME-OUT REFUSED "
                                    "NET-UNREACHABLE NO-BUFFER-AVAILABLE",
                                    strlen( pszAttr ), pszAttr );
        if ( lResult == -1 )
        {
          xmluLog( pScan->xmlNode, "Invalid result name." );
          fNoError = FALSE;
          break;
        }

        if ( !_cfgStrToScore( pScan->cbValue, pScan->pcValue,
                              &pConfig->alScoreMailBoxCheck[lResult] ) )
        {
          xmluLog( pScan->xmlNode, "Invalid score value." );
          fNoError = FALSE;
          break;
        }
        if ( pConfig->alScoreMailBoxCheck[lResult] != SF_SCORE_NONE )
          pConfig->fMailBoxCheck = TRUE;

        break;

      case 1: // ignore-senders
        utilStrAddWords( &pConfig->cbMailBoxCheckIgnoreSenders,
                         &pConfig->pcMailBoxCheckIgnoreSenders,
                         pScan->cbValue, pScan->pcValue, NULL );
        break;

      case 2: // ignore
        cfgHostListAddList( &pConfig->lsMailBoxCheckIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        if ( !fNoError )
          xmluScanLog( pScan, "Invalid value." );
        break;

    }

    if ( !fNoError )
      break;

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadSPF(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <spf> XML-tree.

static BOOL __cfgReadSPF(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC, lLevel;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;

  lRC = xmluBeginScan( pNode, &pScan, "score:m ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // score
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "level" );
        if ( pszAttr == NULL )
        {
          xmluLog( pScan->xmlNode, "Attribute \"level\" is not specified." );
          fNoError = FALSE;
          break;
        }

        lLevel = utilStrWordIndex( "none neutral pass fail SoftFail TempError "
                                   "PermError", strlen( pszAttr ), pszAttr );
        if ( lLevel == -1 )
        {
          xmluLog( pScan->xmlNode, "Invalid level value." );
          fNoError = FALSE;
          break;
        }

        if ( !_cfgStrToScore( pScan->cbValue, pScan->pcValue,
                              &pConfig->alScoreSPF[lLevel] ) )
        {
          xmluLog( pScan->xmlNode, "Invalid score value." );
          fNoError = FALSE;
          break;
        }
        break;

      case 1: // ignore
        cfgHostListAddList( &pConfig->lsHostListSPFIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        if ( !fNoError )
          xmluScanLog( pScan, "Invalid value." );
        break;
    }

    if ( !fNoError )
      break;

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

// BOOL __cfgReadMessageId(PCONFIG pConfig, xmlNodePtr pNode)
//
// Parse <message-id> XML-tree.

static BOOL __cfgReadMessageId(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  // Read patterns for message-id.
  if ( !__cfgFillHostListScore( &pConfig->lsHostListMsgId, pNode, FALSE ) )
    return FALSE;

  lRC = xmluBeginScan( pNode, &pScan, "score-suspicious pattern:m ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // score-suspicious
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreSuspiciousMsgId );
        break;

      case 1: // pattern
        // All patterns already readed.
        break;

      case 2: // ignore
        cfgHostListAddList( &pConfig->lsHostListMsgIdIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC != 0 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}


// BOOL __cfgReadCmdAttributes(PCONFIG pConfig, ULONG ulCommandNo,
//                             xmlNodePtr pNode)
//
// Read attibutes "score-limit" and "ttl" of nodes <command-XXXXX>.

static BOOL __cfgReadCmdAttributes(PCONFIG pConfig, ULONG ulCommandNo,
                                   xmlNodePtr pNode)
{
  PSZ                  pszAttr = xmlGetNoNsProp( pNode, "score-limit" );

  if ( ( pszAttr != NULL ) &&
       !utilStrToULong( -1, pszAttr, 1, ~0,
                      (PULONG)&pConfig->aCmdParam[ulCommandNo].lScoreLimit ) )
  {
    xmluLog( pNode, "Invalid score limit value: \"%s\".", pszAttr );
    return FALSE;
  }

  pszAttr = xmlGetNoNsProp( pNode, "ttl" );
  if ( ( pszAttr != NULL ) &&
       !utilStrTimeToSec( strlen( pszAttr ), pszAttr,
                          &pConfig->aCmdParam[ulCommandNo].ulTTL ) )
  {
    xmluLog( pNode, "Invalid time-to-live value: \"%s\".", pszAttr );
    return FALSE;
  }

  return TRUE;  
}

static BOOL __cfgReadCmdWeaselLogPipe(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  ULONG                cbValue;
  PCHAR                pcValue;
  PSZ                  pszAttr;
  BOOL                 fNotEmpty = xmluGetNodeText( pNode, &cbValue, &pcValue );

  pConfig->fWeaselLogToScreen = __cfgAttrSwitch( pNode, "screen" );

  if ( !fNotEmpty )
  {
    // Old syntax.

    pConfig->fWeaselLogPipe = utilStrWordIndex( _CFG_SW_ON, cbValue, pcValue )
                                != -1;
    if ( pConfig->fWeaselLogPipe ||
         ( utilStrWordIndex( "0 NO N OFF", cbValue, pcValue ) != -1 ) )
    return TRUE;       // Old syntax
  }

  lRC = xmluBeginScan( pNode, &pScan, "alternative-pipe:m server-pipe "
                                      "auth-failed-frequency:e" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // alternative-pipe
        _cfgAddWeaselLogPipe( pConfig, pScan->cbValue, pScan->pcValue );
        break;

      case 1: // server-pipe
        pConfig->pszServerLogPipe = utilStrNewSZ( pScan->cbValue,
                                                  pScan->pcValue );
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "number" );
        if ( pszAttr == NULL )
          pConfig->ulServerLogPipes = 1;
        else
          fNoError = utilStrToULong( -1, pszAttr, 1, _CFG_MAX_PIPES,
                                     &pConfig->ulServerLogPipes );
        break;

      case 2: // auth-failed-frequency
        fNoError = __cfgReadFrequency( pConfig, pScan->xmlNode,
                                       &pConfig->ulAuthFailFreqMax,
                                       &pConfig->ulAuthFailFreqDuration,
                                       &pConfig->ulAuthFailFreqExpiration,
                                       NULL );
    }

    if ( !fNoError )
    {
/*      switch( lRC )
      {
        case ?:
          xmluScanLog( pScan, "Invalid value." );
      }*/
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  pConfig->fWeaselLogPipe = TRUE;

  return lRC == XMLU_SCAN_END;
}

// XML trees <command-XXXXX>.

static BOOL __cfgReadCmdAtAccept(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  if ( !__cfgReadCmdAttributes( pConfig, 0, pNode ) )
    return FALSE;

  lRC = xmluBeginScan( pNode, &pScan, "relay:e local:rm ip-frequency:e "
                                      "score-host:e score-no-ptr" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // relay
        fNoError = __cfgFillHostListScore( &pConfig->lsHostListRelays,
                                           pScan->xmlNode, TRUE );
        break;

      case 1: // local
        cfgHostListAddList( &pConfig->lsHostListLocal, 0,
                            pScan->cbValue, pScan->pcValue );
        break;

      case 2: // ip-frequency
        fNoError = __cfgReadFrequency( pConfig, pScan->xmlNode,
                                       &pConfig->ulIPFreqMaxAtAcceptNum,
                                       &pConfig->ulIPFreqDuration,
                                       &pConfig->ulIPFreqExpiration,
                                       &pConfig->lsHostListIPFreqIgnore );
        break;

      case 3: // score-host
        fNoError = __cfgFillHostListScore( &pConfig->lsHostListScore,
                                           pScan->xmlNode, TRUE );
        break;

      case 4: // score-no-ptr
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreNoPTR );
        break;
    }

    if ( !fNoError )
    {
      switch( lRC )
      {
        case 1:
        case 4:
          xmluScanLog( pScan, "Invalid value." );
      }
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

static BOOL __cfgReadCmdEHLO(PCONFIG pConfig, xmlNodePtr pNode)
{
  return __cfgReadCmdAttributes( pConfig, 1, pNode );
}

static BOOL __cfgReadCmdRSET(PCONFIG pConfig, xmlNodePtr pNode)
{
  return __cfgReadCmdAttributes( pConfig, 2, pNode );
}

static BOOL __cfgReadCmdMAIL(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  if ( !__cfgReadCmdAttributes( pConfig, 3, pNode ) )
    return FALSE;

  lRC = xmluBeginScan( pNode, &pScan, "score-mailfrom:e rwl:e score-ehlo:e "
                       "ehlo-on-rwl score-invalid-ehlo ehlo-uribl-ignore:m" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // score-mailfrom
        fNoError = __cfgFillHostListScore( &pConfig->lsHostListMailFrom,
                                           pScan->xmlNode, FALSE );
        break;

      case 1: // rwl
        fNoError = __cfgReadRWL( pConfig, pScan->xmlNode );
        break;

      case 2: // score-ehlo
        fNoError = __cfgFillHostListScore( &pConfig->lsHostListEHLO,
                                           pScan->xmlNode, TRUE );
        break;

      case 3: // ehlo-on-rwl
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 1, 4,
                                   &pConfig->ulCheckEHLOOnRWL );
        break;

      case 4: // score-invalid-ehlo
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreInvalidEHLO );
        break;

      case 5: // ehlo-uribl-ignore
        cfgHostListAddList( &pConfig->lsHostListEHLOURIBLIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC > 2 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

static BOOL __cfgReadCmdRCPT(PCONFIG pConfig, xmlNodePtr pNode)
{
  return __cfgReadCmdAttributes( pConfig, 4, pNode );
}

static BOOL __cfgReadCmdDATA(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE, fNoErrLog = TRUE;

  if ( !__cfgReadCmdAttributes( pConfig, 5, pNode ) )
    return FALSE;

  lRC = xmluBeginScan( pNode, &pScan,
                       "autowhitelist:e spamtrap:e "
                       "score-extclnt-locsender-locrcpt "
                       "extclnt-locsender-locrcpt:e "
                       "mailfrom-on-rwl "
                       "greylist:e dnsbl:e mailfrom-uribl-ignore:m "
                       "sender-mailbox-check:e spf:e" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // autowhitelist
        fNoError = __cfgReadAutoWhitelist( pConfig, pScan->xmlNode );
        break;

      case 1: // spamtrap
        fNoError = __cfgReadSpamTrap( pConfig, pScan->xmlNode );
        break;

      case 2: // score-extclnt-locsender-locrcpt (deprecated)
        fNoErrLog = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                    &pConfig->lScoreExtClntLocSndrLocRcpt );
        break;

      case 3: // extclnt-locsender-locrcpt
        fNoError = _cfgReadExtClntLocSenderLocRcpt( pConfig, pScan->xmlNode );
        break;

      case 4: // mailfrom-on-rwl
        fNoErrLog = utilStrToULong( pScan->cbValue, pScan->pcValue, 1, 4,
                                    &pConfig->ulCheckMailFromOnRWL );
        break;

      case 5: // greylist
        fNoError = __cfgReadGreylist( pConfig, pScan->xmlNode );
        break;

      case 6: // dnsbl
        fNoError = __cfgReadDNSBL( pConfig, pScan->xmlNode );
        break;

      case 7: // mailfrom-uribl-ignore
        cfgHostListAddList( &pConfig->lsHostListMailFromURIBLIgnore,
                            0, pScan->cbValue, pScan->pcValue );
        break;

      case 8: // sender-mailbox-check
        fNoError = __cfgReadMBoxCheck( pConfig, pScan->xmlNode );
        break;

      case 9: // spf
        fNoError = __cfgReadSPF( pConfig, pScan->xmlNode );
        break;
    }

    if ( !fNoErrLog )
    {
      xmluScanLog( pScan, "Invalid value." );
      break;
    }

    if ( !fNoError )
      break;

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

static BOOL __cfgReadCmdAtContent(PCONFIG pConfig, xmlNodePtr pNode)
{
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;

  if ( !__cfgReadCmdAttributes( pConfig, 6, pNode ) )
    return FALSE;

  lRC = xmluBeginScan( pNode, &pScan,
                       "message-id:e body-on-rwl max-message max-bodypart "
                       "spam-urihost-ttl score-spam-urihost" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // message-id
        fNoError = __cfgReadMessageId( pConfig, pScan->xmlNode );
        break;

      case 1: // body-on-rwl
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 1, 4,
                                   &pConfig->ulCheckMsgBodyOnRWL );
        break;

      case 2: // max-message
        fNoError = utilStrToBytes( pScan->cbValue, pScan->pcValue,
                                   &pConfig->ulMaxMessage );
        break;

      case 3: // max-bodypart
        fNoError = utilStrToBytes( pScan->cbValue, pScan->pcValue,
                                   &pConfig->ulMaxBodyPart );
        break;

      case 4: // spam-urihost-ttl
        fNoError = utilStrTimeToSec( pScan->cbValue, pScan->pcValue,
                                     &pConfig->ulSpamURIHostTTL );
        break;

      case 5: // score-spam-urihost
        fNoError = _cfgStrToScore( pScan->cbValue, pScan->pcValue,
                                   &pConfig->lScoreSpamURIHost );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC > 0 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );

  return lRC == XMLU_SCAN_END;
}

static BOOL __cfgReadCmdQUIT(PCONFIG pConfig, xmlNodePtr pNode)
{
  return __cfgReadCmdAttributes( pConfig, 7, pNode );
}


static VOID _cfgFree(PCONFIG pConfig)
{
  ULONG    ulIdx;

  if ( pConfig->pszDataPath != NULL )
    hfree( pConfig->pszDataPath );

  if ( pConfig->pszLogPath != NULL )
    hfree( pConfig->pszLogPath );

  if ( pConfig->pszSocket != NULL )
    hfree( pConfig->pszSocket );

  if ( pConfig->pszPipe != NULL )
    hfree( pConfig->pszPipe );

  if ( pConfig->pcWeaselLogPipes != NULL )
    hfree( pConfig->pcWeaselLogPipes );

  if ( pConfig->pszServerLogPipe != NULL )
    hfree( pConfig->pszServerLogPipe );

  if ( pConfig->pszMailServerName != NULL )
    hfree( pConfig->pszMailServerName );

  if ( pConfig->pcLocalDomains != NULL )
    hfree( pConfig->pcLocalDomains );

  if ( pConfig->pszSpamStore != NULL )
    hfree( pConfig->pszSpamStore );

  if ( pConfig->pcURIBLProviders != NULL )
    hfree( pConfig->pcURIBLProviders );

  if ( pConfig->pcURIBLNotSpam != NULL )
    hfree( pConfig->pcURIBLNotSpam );

  lnkseqFree( &pConfig->lsHostListLocal, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListRelays, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListIPFreqIgnore, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListScore, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListRWLIgnore, PHOSTREC, hfree );

  if ( pConfig->pcRWLProviders != NULL )
    hfree( pConfig->pcRWLProviders );

  lnkseqFree( &pConfig->lsHostListMailFrom, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListEHLO, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListEHLOURIBLIgnore, PHOSTREC, hfree );

  if ( pConfig->pcAutoWhitelistIgnoreSenders != NULL )
    hfree( pConfig->pcAutoWhitelistIgnoreSenders );

  if ( pConfig->pcSpamTrap != NULL )
    hfree( pConfig->pcSpamTrap );

  if ( pConfig->pcGreylistIgnoreSenders != NULL )
    hfree( pConfig->pcGreylistIgnoreSenders );

  lnkseqFree( &pConfig->lsHostListGreylistIgnore, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListDNSBLIgnore, PHOSTREC, hfree );

  if ( pConfig->paDNSBL != NULL )
  {
    PDNSBL   pDNSBL = pConfig->paDNSBL;

    for( ulIdx = 0; ulIdx < pConfig->cDNSBL; ulIdx++, pDNSBL++ )
    {
      if ( pDNSBL->pszName != NULL )
        hfree( pDNSBL->pszName );

      lnkseqFree( &pDNSBL->lsHostListAnswers, PHOSTREC, hfree );
    }

    hfree( pConfig->paDNSBL );
  }

  lnkseqFree( &pConfig->lsHostListMailFromURIBLIgnore, PHOSTREC, hfree );

  if ( pConfig->pcMailBoxCheckIgnoreSenders != NULL )
    hfree( pConfig->pcMailBoxCheckIgnoreSenders );

  lnkseqFree( &pConfig->lsMailBoxCheckIgnore, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListSPFIgnore, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListMsgId, PHOSTREC, hfree );
  lnkseqFree( &pConfig->lsHostListMsgIdIgnore, PHOSTREC, hfree );

  hfree( pConfig );
}

static PCONFIG _cfgNew(PSZ pszFile)
{
  PCONFIG              pConfig = hcalloc( 1, sizeof(CONFIG) );
  xmlDocPtr            pDoc;
  xmlNodePtr           pNode;
  PXMLUSCAN            pScan;
  LONG                 lRC;
  BOOL                 fNoError = TRUE;
  PSZ                  pszAttr;
  ULONG                ulIdx;

  if ( pConfig == NULL )
  {
    debug( "Not enough memory" );
    return NULL;
  }

  // Load XML tree from the file.

  pDoc = xmlReadFile( pszFile, "UTF-8", XML_PARSE_NOERROR+XML_PARSE_NOWARNING );
  if ( pDoc == NULL )
  {
    CHAR               acBuf[512];
    PCHAR              pcBuf =
          &acBuf[ sprintf( &acBuf, "Configuration read error: %s", pszFile ) ];
    xmlErrorPtr        pError = xmlGetLastError();

    if ( pError != NULL )
    {
      if ( pError->line != 0 )
        pcBuf += sprintf( pcBuf, ":%d", pError->line );

      acBuf[sizeof(acBuf) - 1] = '\0';
      pcBuf += _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 1, ", %s",
                          pError->message );
      
      while( (pcBuf > &acBuf) && isspace( *(pcBuf - 1) ) ) pcBuf--;
      *pcBuf = '\0';
    }

    logWrite( &acBuf );
    hfree( pConfig );
    return NULL;
  }

  // Read configuration.

  pNode = xmlDocGetRootElement( pDoc );
  if ( pNode == NULL || ( xmlStrcmp( pNode->name, "config" ) != 0 ) )
  {
    logWrite( "Unknown root node <%s>", pNode->name );
    xmlFreeDoc( pDoc );
    hfree( pConfig );
    return FALSE;
  }

  pConfig->ulThreads = _CFG_DEF_THREADS;
  _cfgAddWeaselLogPipe( pConfig, strlen( _CFG_DEF_WEASEL_LOG_PIPE ),
                        _CFG_DEF_WEASEL_LOG_PIPE );
  pConfig->ulURIBLHits = 1;
  pConfig->ulPipes = _CFG_DEF_PIPES;
  pConfig->ulCommandTimeout = _CFG_DEF_COMMAND_TIMEOUT;
  pConfig->stGreylistMask.s_addr = _CFG_DEF_GLMASK;
  pConfig->ulGreylistCfNum = _CFG_DEF_CFNUM;
  pConfig->ulGreylistCfDen = _CFG_DEF_CFDEN;
  pConfig->ulGreylistCfTTL = _CFG_DEF_CFTTL;
  pConfig->ulMaxMessage    = _CFG_DEF_MAX_MESSAGE;
  pConfig->ulMaxBodyPart   = _CFG_DEF_MAX_BODY_PART;
  lnkseqInit( &pConfig->lsHostListRelays );
  lnkseqInit( &pConfig->lsHostListLocal );
  lnkseqInit( &pConfig->lsHostListIPFreqIgnore );
  lnkseqInit( &pConfig->lsHostListScore );
  lnkseqInit( &pConfig->lsHostListRWLIgnore );
  lnkseqInit( &pConfig->lsHostListMailFrom );
  lnkseqInit( &pConfig->lsHostListEHLO );
  lnkseqInit( &pConfig->lsHostListEHLOURIBLIgnore );
  lnkseqInit( &pConfig->lsHostListGreylistIgnore );
  lnkseqInit( &pConfig->lsHostListDNSBLIgnore );
  lnkseqInit( &pConfig->lsHostListMailFromURIBLIgnore );
  lnkseqInit( &pConfig->lsMailBoxCheckIgnore );
  lnkseqInit( &pConfig->lsHostListSPFIgnore );
  lnkseqInit( &pConfig->lsHostListMsgIdIgnore );
  lnkseqInit( &pConfig->lsHostListMsgId );

  lRC = xmluBeginScan( pNode, &pScan,
          "path-data:pr path-log:pr log-level log-size log-history socket:r "
          "pipe threads weasel-log-pipe:e name-server:r mail-server "
          "mail-server-name:r "
          "local-domain:rm spam-store update-header command-timeout uribl:e "
          "command-ataccept:re command-ehlo:re command-rset:re command-mail:re "
          "command-rcpt:re command-data:re command-atcontent:re "
          "command-quit:re" );
  while( lRC >= 0 )
  {
    switch( lRC )
    {
      case 0: // path-data
      case 1: // path-log
        *(lRC == 0 ? &pConfig->pszDataPath : &pConfig->pszLogPath) =
           utilStrNewSZ( pScan->cbValue, pScan->pcValue );
        break;

      case 2: // log-level
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 0, 5,
                                   &pConfig->ulLogLevel );
        break;

      case 3: // log-size
        fNoError = utilStrToBytes( pScan->cbValue, pScan->pcValue,
                                   &pConfig->ulLogSize );
        break;

      case 4: // log-history
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 0, 365,
                                   &pConfig->ulLogHistory );
        break;

      case 5: // socket
        if ( pScan->cbValue > 99 )
        {
          fNoError = FALSE;
          break;
        }

        pConfig->pszSocket = utilStrNewSZ( pScan->cbValue, pScan->pcValue );
        break;

      case 6: // pipe
        if ( pScan->cbValue > (CCHMAXPATH - 7 /* \PIPE\ and ZERO */) )
        {
          fNoError = FALSE;
          break;
        }

        pConfig->pszPipe = utilStrNewSZ( pScan->cbValue, pScan->pcValue );
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "number" );
        if ( pszAttr != NULL )
          fNoError = utilStrToULong( -1, pszAttr, 1, _CFG_MAX_PIPES,
                                     &pConfig->ulPipes );
        break;

      case 7: // threads
        fNoError = utilStrToULong( pScan->cbValue, pScan->pcValue, 1,
                                   _CFG_MAX_THREADS, &pConfig->ulThreads );
        break;

      case 8: // weasel-log-pipe
        fNoError = __cfgReadCmdWeaselLogPipe( pConfig, pScan->xmlNode );
        break;

      case 9: // name-server
        fNoError = utilStrToInAddrPort( pScan->cbValue, pScan->pcValue,
                     &pConfig->stNSAddr, &pConfig->usNSPort, FALSE, 53 );
        break;

      case 10: // mail-server
        fNoError = utilStrToInAddrPort( pScan->cbValue, pScan->pcValue,
                     &pConfig->stMXAddr, &pConfig->usMXPort, FALSE, 25 );
        break;

      case 11: // mail-server-name
        fNoError = utilVerifyDomainName( pScan->cbValue, pScan->pcValue );
        if ( fNoError )
          pConfig->pszMailServerName = utilStrNewSZ( pScan->cbValue,
                                                     pScan->pcValue );
        break;

      case 12: // local-domain
        fNoError = utilStrAddWords( &pConfig->cbLocalDomains,
                                    &pConfig->pcLocalDomains,
                                    pScan->cbValue, pScan->pcValue,
                                    NULL );
        break;

      case 13: // spam-store
        pConfig->pszSpamStore = utilStrNewSZ( pScan->cbValue, pScan->pcValue );
        pConfig->fSpamTrapStore = __cfgAttrSwitch( pScan->xmlNode, "to-trap" );
        break;

      case 14: // update-header
        pConfig->fUpdateHeader = utilStrWordIndex( _CFG_SW_ON, pScan->cbValue,
                                                   pScan->pcValue ) != -1;
        pszAttr = xmlGetNoNsProp( pScan->xmlNode, "from-local" );
        pConfig->fUpdateHeaderLocal = ( pszAttr != NULL ) &&
          ( utilStrWordIndex( _CFG_SW_ON, strlen( pszAttr ), pszAttr ) != -1 );
        break;

      case 15: // command-timeout
        fNoError = utilStrTimeToSec( pScan->cbValue, pScan->pcValue,
                                     &pConfig->ulCommandTimeout ) &&
                   ( pConfig->ulCommandTimeout >= _CFG_MIN_COMMAND_TIMEOUT ) &&
                   ( pConfig->ulCommandTimeout <= _CFG_MAX_COMMAND_TIMEOUT );
        break;

      case 16: // uribl
        fNoError = __cfgReadURIBL( pConfig, pScan->xmlNode );
        break;

      case 17: // command-ataccept
        fNoError = __cfgReadCmdAtAccept( pConfig, pScan->xmlNode );
        break;

      case 18: // command-ehlo
        fNoError = __cfgReadCmdEHLO( pConfig, pScan->xmlNode );
        break;

      case 19: // command-rset
        fNoError = __cfgReadCmdRSET( pConfig, pScan->xmlNode );
        break;

      case 20: // command-mail
        fNoError = __cfgReadCmdMAIL( pConfig, pScan->xmlNode );
        break;

      case 21: // command-rcpt
        fNoError = __cfgReadCmdRCPT( pConfig, pScan->xmlNode );
        break;

      case 22: // command-data
        fNoError = __cfgReadCmdDATA( pConfig, pScan->xmlNode );
        break;

      case 23: // command-atcontent
        fNoError = __cfgReadCmdAtContent( pConfig, pScan->xmlNode );
        break;

      case 24: // command-quit
        fNoError = __cfgReadCmdQUIT( pConfig, pScan->xmlNode );
        break;
    }

    if ( !fNoError )
    {
      if ( lRC <= 14 )
        xmluScanLog( pScan, "Invalid value." );
      break;
    }

    lRC = xmluScan( pScan );
  }

  xmluEndScan( pScan );
  xmlFreeDoc( pDoc );

  if ( lRC != XMLU_SCAN_END )
  {
    _cfgFree( pConfig );
    return NULL;
  }

  // Check score limmits and TTLs for commands. The score limmit value should
  // not be less than previous one.

  for( ulIdx = 1; ulIdx < ARRAY_SIZE( pConfig->aCmdParam ); ulIdx++ )
  {
    // Default TTL.
    if ( pConfig->aCmdParam[ulIdx].ulTTL == 0 )
      pConfig->aCmdParam[ulIdx].ulTTL = ( 24 * 60 * 60 * 1000 );

    if ( pConfig->aCmdParam[ulIdx].lScoreLimit <
         pConfig->aCmdParam[ulIdx-1].lScoreLimit )
    {
      pConfig->aCmdParam[ulIdx].lScoreLimit =
        pConfig->aCmdParam[ulIdx-1].lScoreLimit;
/*      log( 1, "[WARNING] Set score limit for stage %u to %u",
           ulIdx, pConfig->lStageScoringLimit[ulIdx] );*/
    }
  }

  return pConfig;
}


//           Public routines
//           ---------------

BOOL cfgInit(PSZ pszFile)
{
  if ( pConfig != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  if ( !rwmtxInit( &rwmtxConfig ) )
  {
    debug( "rwmtxInit() failed" );
    return FALSE;
  }

  pConfig = _cfgNew( pszFile );
  if ( pConfig == NULL )
  {
    rwmtxDone( &rwmtxConfig );
    return FALSE;
  }

  pszCfgFile = hstrdup( pszFile );

  return TRUE;
}

VOID cfgDone()
{
  if ( pConfig == NULL )
  {
    debug( "Was not initialized" );
    return;
  }

  rwmtxDone( &rwmtxConfig );

  _cfgFree( pConfig );
  pConfig = NULL;
  if ( pszCfgFile != NULL )
  {
    hfree( pszCfgFile );
    pszCfgFile = NULL;
  }
}

// BOOL cfgReconfigure()
//
// Read configuration file and set new configuration.
// Returns FALSE on error (error message will be logged).
// Configuration should not be locked with cfgReadLock() !

BOOL cfgReconfigure()
{
  PCONFIG    pNewConfig;
  PCONFIG    pOldConfig;

  pNewConfig = _cfgNew( pszCfgFile );
  if ( pNewConfig == NULL )
    return FALSE;

  rwmtxLockWrite( &rwmtxConfig );
  pOldConfig = pConfig;
  pConfig = pNewConfig;
  rwmtxUnlockWrite( &rwmtxConfig );

  _cfgFree( pOldConfig );
  log( 1, "[INFO] Configuration been read from the file %s", pszCfgFile );
  return TRUE;
}

BOOL cfgReadLock()
{
  return rwmtxLockRead( &rwmtxConfig );
}

VOID cfgReadUnlock()
{
  rwmtxUnlockRead( &rwmtxConfig );
}

// BOOL cfgIsMatchPtrnList(ULONG cbPtrnList, PCHAR pcPtrnList,
//                         ULONG cbWord, PCHAR pcWord)
//
// Matches cbWord/pcWord list of patterns cbPtrnList/pcPtrnList separated by
// spaces.

BOOL cfgIsMatchPtrnList(ULONG cbPtrnList, PCHAR pcPtrnList,
                        ULONG cbWord, PCHAR pcWord)
{
  ULONG      cbPtrn;
  PCHAR      pcPtrn;

  if ( ( cbPtrnList != 0 ) && ( pcPtrnList != NULL ) && ( cbWord != 0 ) )
  {
    while( utilStrCutWord( &cbPtrnList, &pcPtrnList, &cbPtrn, &pcPtrn ) )
    {
      if ( utilIsMatch( cbWord, pcWord, cbPtrn, pcPtrn ) )
        return TRUE;
    }
  }

  return FALSE;
}

BOOL cfgIsLocalEMailDomain(ULONG cbDomain, PCHAR pcDomain)
{
  if ( ( *pcDomain == '[' ) && ( pcDomain[cbDomain-1] == ']' ) )
  {
    pcDomain++;
    cbDomain -= 2;
    // Future: Compare IP address with resolved our host name, local IPs here.
  }

  return cfgIsMatchPtrnList( pConfig->cbLocalDomains, pConfig->pcLocalDomains,
                             cbDomain, pcDomain );
}
