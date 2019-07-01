#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include <time.h>
#include "xpl.h"
#include "util.h"
#include "xmlutil.h"
#include "dns.h"
#include "sessions.h"
#include "greylist.h"
#include "requests.h"
#include "log.h"
#include "datafile.h"
#include "hmem.h"
#include "stat.h"
#include "debug.h"     // Must be the last.

#define STAT_FILE      "stat.xml"
#define ROOT_NODE      "sf-statistics"

extern ADDRLIST        stSpamURIHostList;

typedef struct _STATITEM {
  PSZ        pszName;
  LONG       lValue;
} STATITEM, *PSTATITEM;

// static BOOL            fChanged = FALSE;
static HMTX            hmtxStat = NULLHANDLE;
static STATITEM        aItems[] =
{
  { "sessions", 0 },             // 0 STAT_SESSIONS
  { "spam", 0 },                 // 1 STAT_SPAM
  { "not-spam", 0 },             // 2 STAT_NOT_SPAM
  { "delayed", 0 },              // 3 STAT_DELAYED
  { "sess-timedout", 0 },        // 4 STAT_SESS_TIMEDOUT
  { "spam-trap", 0 },            // 5 STAT_SPAM_TRAP
  { "ip-freq-limit", 0 },        // 6 STAT_IP_FREQ_LIMIT
  { "spam-urihosts-found", 0 },  // 7 STAT_SPAM_URIHOSTS_FOUND
  { "command-timeout", 0 },      // 8 STAT_COMMAND_TIMEOUT
  { "auth-fail-block", 0 }       // 9 STAT_AUTHFAIL_BLOCK
};
static PSZ             pszGeneralStart = NULL;


static PSZ _statGetTimeStr(ULONG cbBuf, PCHAR pcBuf)
{
  time_t     timeCur;
  struct tm  stTime;

  time( &timeCur );
  _localtime( &timeCur, &stTime );

  return strftime( pcBuf, cbBuf, "%a, %e %b %Y %T %z", &stTime ) == 0 ?
           NULL : pcBuf;
}


BOOL statInit()
{
  xmlDocPtr            pxmlDoc;
  xmlNodePtr           pxmlRoot, pxmlNode;
  ULONG                ulIdx;
  xmlChar              *pxcValue;
  CHAR                 acBuf[_MAX_PATH];

  if ( hmtxStat != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxStat, FALSE );
  if ( hmtxStat == NULLHANDLE )
    return FALSE;

  if ( pszGeneralStart == NULL )
    pszGeneralStart = hstrdup( _statGetTimeStr( sizeof(acBuf), &acBuf ) );

  // Load general statistics.

  if ( dfBackupGetName( sizeof(acBuf), &acBuf, STAT_FILE, "bkp" ) == -1 )
    return TRUE;

  pxmlDoc = xmlReadFile( &acBuf, "UTF-8",
                         XML_PARSE_NOERROR + XML_PARSE_NOWARNING );
  if ( pxmlDoc == NULL )
  {
    debug( "xmlReadFile() failed" );
  }
  else
  {

    pxmlRoot = xmlDocGetRootElement( pxmlDoc );
    if ( pxmlRoot == NULL || ( xmlStrcmp( pxmlRoot->name, ROOT_NODE ) != 0 ) )
    {
      debug( "Cannot read root node %s", ROOT_NODE );
    }
    else
    {
      // Search node "general".

      for( pxmlNode = pxmlRoot->children; pxmlNode != NULL; pxmlNode = pxmlNode->next )
      {
        if ( !xmlIsBlankNode( pxmlNode ) && ( pxmlNode->name != NULL ) &&
             ( stricmp( pxmlNode->name, "general" ) == 0 ) )
          break;
      }

      if ( pxmlNode != NULL )
      {
        // Read values from the tree "general".

        pxcValue = xmlGetNoNsProp( pxmlNode, "date-start" );
        if ( pxcValue != NULL )
        {
          if ( pszGeneralStart != NULL )
            hfree( pszGeneralStart );
          pszGeneralStart = hstrdup( pxcValue );
         }

        for( pxmlNode = pxmlNode->children; pxmlNode != NULL; pxmlNode = pxmlNode->next )
        {
          if ( xmlIsBlankNode( pxmlNode ) || ( pxmlNode->name == NULL ) )
            continue;

          for( ulIdx = 0; ulIdx < ARRAY_SIZE( aItems ); ulIdx++ )
          {
            if ( stricmp( pxmlNode->name, aItems[ulIdx].pszName ) == 0 )
            {
              pxcValue = xmluGetNodeTextSZ( pxmlNode );
              if ( pxcValue != NULL )
                aItems[ulIdx].lValue = atol( pxcValue );
              break;
            }
          }
        }
      }
    }

  } // pxmlDoc != NULL

  xmlFreeDoc( pxmlDoc );
  return TRUE;
}

VOID statDone()
{
  if ( hmtxStat == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  if ( pszGeneralStart != NULL )
  {
    hfree( pszGeneralStart );
    pszGeneralStart = NULL;
  }

  xplMutexDestroy( hmtxStat );
  hmtxStat = NULLHANDLE;
}

BOOL statSaveChanges()
{
  xmlDocPtr            pxmlDoc;
  xmlNodePtr           pxmlRoot, pxmlNode;
  ULONG                ulIdx;
  PSTATITEM            pItem = &aItems[0];
  CHAR                 acBuf[_MAX_PATH];
  BOOL                 fSaved;
  ULONG                ulGlIPSender, ulGlIPCf;

  xplMutexLock( hmtxStat, XPL_INDEFINITE_WAIT );

  pxmlDoc = xmlNewDoc( "1.0" );
  if ( pxmlDoc == NULL )
  {
    xplMutexUnlock( hmtxStat );
    return FALSE;
  }

  pxmlRoot = xmlNewNode( NULL, ROOT_NODE );
  if ( pxmlRoot == NULL )
  {
    xplMutexUnlock( hmtxStat );
    debug( "xmlNewNode() fail" );
    xmlFreeDoc( pxmlDoc );
    return FALSE;
  }
  xmlDocSetRootElement( pxmlDoc, pxmlRoot );
  xmlNewProp( pxmlRoot, "date", _statGetTimeStr( sizeof(acBuf), &acBuf ) );

  pxmlNode = xmlNewChild( pxmlRoot, NULL, "general", NULL );
  xmlNewProp( pxmlNode, "date-start", pszGeneralStart );

  for( ulIdx = 0; ulIdx < ARRAY_SIZE( aItems ); ulIdx++, pItem++ )
  {
    xmlNewChild( pxmlNode, NULL, pItem->pszName,
                 ltoa( pItem->lValue, &acBuf, 10 ) );
  }

  pxmlNode = xmlNewChild( pxmlRoot, NULL, "snapshot", NULL );
  xmlNewChild( pxmlNode, NULL, "dns-cache",
               ltoa( dnsGetCacheCount(), &acBuf, 10 ) );
  xmlNewChild( pxmlNode, NULL, "sessions", ltoa( sessCount(), &acBuf, 10 ) );

  glGetCounters( &ulGlIPSender, &ulGlIPCf );
  xmlNewChild( pxmlNode, NULL, "greylist-sender-records",
               ltoa( ulGlIPSender, &acBuf, 10 ) );
  xmlNewChild( pxmlNode, NULL, "greylist-ip-coefficients",
               ltoa( ulGlIPCf, &acBuf, 10 ) );

  xmlNewChild( pxmlNode, NULL, "requests", ltoa( reqGetCount(), &acBuf, 10 ) );
  xmlNewChild( pxmlNode, NULL, "dynamic-ip",
               ltoa( reqDynIPGetCount(), &acBuf, 10 ) );
  xmlNewChild( pxmlNode, NULL, "spam-urihosts",
               ltoa( addrlstGetCount( &stSpamURIHostList ), &acBuf, 10 ) );
  xmlNewChild( pxmlNode, NULL, "auto-whitelist",
               ltoa( addrlstGetCount( &stWhiteAddrList ), &acBuf, 10 ) );

  xplMutexUnlock( hmtxStat );

  fSaved = ( dfSetUniqueExtension( sizeof(acBuf), &acBuf, STAT_FILE ) > 0 ) &&
           ( xmlSaveFormatFileEnc( &acBuf, pxmlDoc, "UTF-8", 1 ) != -1 ) &&
           dfBackupFileReplace( STAT_FILE, &acBuf, "bkp", TRUE );

  xmlFreeDoc( pxmlDoc );

  if ( !fSaved )
    log( 1, "[ERROR] Cannot save statistics" );

  return fSaved;
}

VOID statChange(ULONG ulItem, LONG lValue)
{
  if ( ulItem >= ARRAY_SIZE( aItems ) )
    return;

  xplMutexLock( hmtxStat, XPL_INDEFINITE_WAIT );
  aItems[ulItem].lValue += lValue;
  xplMutexUnlock( hmtxStat );
}
