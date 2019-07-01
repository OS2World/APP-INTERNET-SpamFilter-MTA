#include <libxml/parser.h>
#include <libxml/tree.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <log.h>
#include "xmlutil.h"
#include "util.h"
#include "hmem.h"
#include "debug.h"     // Must be the last.

#define _SI_FL_MULTIPLE          1
#define _SI_FL_REQUIRED          2
#define _SI_FL_EMPTYALLOWED      4
#define _SI_FL_PATH              8


static VOID _xmluVLog(xmlNodePtr xmlNode, PSZ pszFormat, va_list arglist)
{
  CHAR       acBuf[1024];
  PCHAR      pcBuf = &acBuf;

  if ( xmlNode != NULL )
  {
    LONG     lLine = xmlGetLineNo( xmlNode );

    if ( ( xmlNode->doc != NULL ) && ( xmlNode->doc->URL != NULL ) )
      pcBuf += _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 3,
                          "%s", xmlNode->doc->URL );

    if ( lLine > 0 )
      pcBuf += _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 3,
                          ":%u", lLine );

    if ( xmlNode->name != NULL )
      pcBuf += _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 3,
                          " <%s>", xmlNode->name );

    *pcBuf = ',';
    pcBuf++;
    *pcBuf = ' ';
    pcBuf++;
  }

  acBuf[sizeof(acBuf) - 1] = '\0';
  vsnprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 1, pszFormat, arglist );
  logWrite( "%s", &acBuf );
}

static LONG _xmluScan(PXMLUSCAN pScan)
{
  ULONG                ulIdx;
  PXMLUSCANNODE        pScanNode;

  while( TRUE )
  {
    if ( pScan->xmlNode == NULL )
    {
      // No more nodes in the tree.

      // Checking required nodes.
      for( ulIdx = 0, pScanNode = &pScan->aNodes; ulIdx < pScan->cNodes;
           ulIdx++, pScanNode++ )
      {
        if ( ( (pScanNode->ulFlags & _SI_FL_REQUIRED) != 0 ) &&
             ( pScanNode->cFound == 0 ) )
        {
          CHAR         acBuf[64];
          ULONG        cbBuf = min( pScanNode->cbName, sizeof(acBuf) - 1 );

          pScan->cbValue = pScanNode->cbName;
          pScan->pcValue = pScanNode->pcName;
          memcpy( &acBuf, pScanNode->pcName, cbBuf );
          acBuf[cbBuf] = '\0';
          xmluScanLog( pScan, "Node <%s> not found.", &acBuf );
          return XMLU_SCAN_NOT_FOUND;
        }
      }

      return XMLU_SCAN_END;
    }

    if ( !xmlIsBlankNode( pScan->xmlNode ) && ( pScan->xmlNode->name != NULL ) )
    {
      // Found current XML node in the user's node list.

      for( ulIdx = 0, pScanNode = &pScan->aNodes; ulIdx < pScan->cNodes;
           ulIdx++, pScanNode++ )
      {
        if ( ( pScanNode->cbName == strlen( pScan->xmlNode->name ) ) &&
             ( memicmp( pScanNode->pcName, pScan->xmlNode->name,
                        pScanNode->cbName ) == 0 ) )
        {
          // Current XML node present in user's node list.

          BOOL         fNotEmpty
                         = xmluGetNodeText( pScan->xmlNode, &pScan->cbValue,
                                            &pScan->pcValue );

          if ( ( (pScanNode->ulFlags & _SI_FL_MULTIPLE) == 0 ) &&
               ( pScanNode->cFound != 0 ) )
          {
            // Duplication.
            logWrite( "%s:%u Duplication node <%s>.",
                      pScan->xmlDoc->URL, xmlGetLineNo( pScan->xmlNode ),
                      pScan->xmlNode->name );
            return XMLU_SCAN_DUPLICATION;
          }

          if ( ( (pScanNode->ulFlags & _SI_FL_EMPTYALLOWED) == 0 ) &&
               !fNotEmpty )
          {
            // Empty.
            xmluScanLog( pScan, "Empty node." );
            return XMLU_SCAN_EMPTY;
          }

          if ( ( (pScanNode->ulFlags & _SI_FL_PATH) != 0 ) && fNotEmpty &&
               !utilPathExists( pScan->cbValue, pScan->pcValue, FALSE ) )
          {
            // Path does not exists.
            xmluScanLog( pScan, "Path <%s> does not exists: %s.",
                         xmluGetNodeTextSZ( pScan->xmlNode ) );
            return XMLU_SCAN_NO_PATH;
          }

          // Return index of user's node list.
          pScanNode->cFound++;
          return ulIdx;
        }
      }
    }

    // It was empty or unknown node - go to the next XML node.
    pScan->xmlNode = pScan->xmlNode->next;
  }  
}

// LONG xmluBeginScan(xmlNodePtr xmlNode, PXMLUSCAN *ppScan, PSZ pszNodes)
//
// Creates object ppScan for the tree xmlNode with list of required nodes
// pointed by pszNodes. Format of the list: nodeName[:flags] ...
// Sample: "valueA:rm data-path:rp"
// Flags: M - multiple node, R - required node, E - empty value is allowed,
//        P - existing path.
// Returns user's list index of the next founded node or code XMLU_SCAN_xxxx.

LONG xmluBeginScan(xmlNodePtr xmlNode, PXMLUSCAN *ppScan, PSZ pszNodes)
{
  PXMLUSCAN            pScan;
  ULONG                cbNodes = strlen( pszNodes );
  ULONG                cNodes = utilStrWordsCount( cbNodes, pszNodes );
  PXMLUSCANNODE        pScanNode;
  ULONG                cbWord;
  PCHAR                pcWord;
  PCHAR                pcColumn;

  // Allocate memory for the scan object.

  pScan = hcalloc( 1, ( sizeof(XMLUSCAN) - sizeof(XMLUSCANNODE) ) +
                          ( cNodes * sizeof(XMLUSCANNODE) ) );
  if ( pScan == NULL )
  {
    debug( "Not enough memory" );
    *ppScan = NULL;
    return XMLU_SCAN_NOT_ENOUGH_MEMORY;
  }

  // Fill scan obect data.

  pScan->cNodes = cNodes;
  pScan->xmlDoc = xmlNode->doc;
  pScan->xmlNode = xmlNode->children;

  pScanNode = &pScan->aNodes;
  while( TRUE )
  {
    utilStrCutWord( &cbNodes, &pszNodes, &cbWord, &pcWord );
    if ( cbWord == 0 )
      break;

    pScanNode->pcName = pcWord;
    pcColumn = memchr( pcWord, ':', cbWord );
    if ( pcColumn == NULL )
      pScanNode->cbName = cbWord;
    else
    {
      ULONG  ulFlag;

      pScanNode->cbName = pcColumn - pcWord;
      cbWord = cbWord - (pcColumn - pcWord) - 1;
      pcWord = pcColumn + 1;
      while( cbWord != 0 )
      {
        switch( toupper( *pcWord ) )
        {
          case 'M':
            ulFlag = _SI_FL_MULTIPLE;
            break;

          case 'R':
            ulFlag = _SI_FL_REQUIRED;
            break;

          case 'E':
            ulFlag = _SI_FL_EMPTYALLOWED;
            break;

          case 'P':
            ulFlag = _SI_FL_PATH;
            break;

          default:
            ulFlag = 0;
        }
        pScanNode->ulFlags |= ulFlag;

        pcWord++;
        cbWord--;
      }
    }

    pScanNode++;
  }

  *ppScan = pScan;
  return _xmluScan( pScan );
}

// LONG xmluScan(PXMLUSCAN pScan)
//
// Seeking the next node that is present in the list.
// Returns user's list index of the next founded node or code XMLU_SCAN_xxxx.

LONG xmluScan(PXMLUSCAN pScan)
{
  if ( pScan->xmlNode != NULL )
    pScan->xmlNode = pScan->xmlNode->next;
  return _xmluScan( pScan );
}

VOID xmluEndScan(PXMLUSCAN pScan)
{
  if ( pScan != NULL )
    hfree( pScan );
}

VOID xmluScanLog(PXMLUSCAN pScan, PSZ pszFormat, ...)
{
  CHAR       acBuf[1024];
  PCHAR      pcBuf = &acBuf;
  va_list    arglist;

  if ( pScan != NULL )
  {
    if ( pScan->xmlNode != NULL )
    {
      va_start( arglist, pszFormat );
      _xmluVLog( pScan->xmlNode, pszFormat, arglist );
      va_end( arglist );
      return;
    }

    if ( pScan->xmlDoc != NULL )
      pcBuf += _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 2,
                          "%s, ", pScan->xmlDoc->URL );
  }

  acBuf[sizeof(acBuf) - 1] = '\0';
  va_start( arglist, pszFormat );
  vsnprintf( pcBuf, sizeof(acBuf) - (pcBuf - &acBuf) - 1, pszFormat, arglist );
  va_end( arglist );

  logWrite( "%s", &acBuf );
}

#ifdef DEBUG_FILE
VOID xmluDebugScan(PXMLUSCAN pScan)
{
  PXMLUSCANNODE        pScanNode = &pScan->aNodes;
  ULONG                ulIdx;

  for( ulIdx = 0; ulIdx < pScan->cNodes; ulIdx++, pScanNode++ )
  {
    printf( "Node: %s <", debugBufPSZ( pScanNode->pcName, pScanNode->cbName ) );
    if ( (pScanNode->ulFlags & _SI_FL_MULTIPLE) != 0 )
      putchar( 'M' );
    if ( (pScanNode->ulFlags & _SI_FL_REQUIRED) != 0 )
      putchar( 'R' );
    if ( (pScanNode->ulFlags & _SI_FL_EMPTYALLOWED) != 0 )
      putchar( 'E' );
    if ( (pScanNode->ulFlags & _SI_FL_PATH) != 0 )
      putchar( 'P' );
    puts( ">" );
  }
}
#endif

VOID xmluLog(xmlNodePtr xmlNode, PSZ pszFormat, ...)
{
  va_list    arglist;

  va_start( arglist, pszFormat );
  _xmluVLog( xmlNode, pszFormat, arglist );
  va_end( arglist );
}

PSZ xmluGetNodeTextSZ(xmlNodePtr xmlNode)
{
  return ( ( xmlNode->children == NULL || xmlNode->children->content == NULL ||
           xmlNode->children->content[0] == '\0' )
           ? NULL
           : xmlNode->children->content );
}

BOOL xmluGetNodeText(xmlNodePtr xmlNode, PULONG pcbText, PCHAR *ppcText)
{
  ULONG      cbText;
  PCHAR      pcText = xmluGetNodeTextSZ( xmlNode );

  if ( pcText != NULL )
  {
    cbText = strlen( pcText );

    BUF_SKIP_SPACES( cbText, pcText );
    BUF_RTRIM( cbText, pcText );

    if ( cbText != 0 )
    {
      *ppcText = pcText;
      *pcbText = cbText;
      return TRUE;
    }
  }

  *ppcText = NULL;
  *pcbText = 0;
  return FALSE;
}

ULONG xmluChildElementCount(xmlNodePtr xmlParent, PSZ pszName)
{
  ULONG      ulRet = 0;
  xmlNodePtr xmlCur;

  if ( xmlParent == NULL )
    return 0;

  switch( xmlParent->type )
  {
    case XML_ELEMENT_NODE:
    case XML_ENTITY_NODE:
    case XML_DOCUMENT_NODE:
    case XML_DOCUMENT_FRAG_NODE:
    case XML_HTML_DOCUMENT_NODE:
      xmlCur = xmlParent->children;
      break;

    default:
      return 0;
  }

  for( ; xmlCur != NULL; xmlCur = xmlCur->next )
  {
    if ( ( xmlCur->type == XML_ELEMENT_NODE ) &&
         (
           ( pszName == NULL )
         ||
           ( ( xmlCur->name != NULL ) &&
             ( stricmp( xmlCur->name, pszName ) == 0 ) )
         )
       )
      ulRet++;
  }

  return ulRet;
}
