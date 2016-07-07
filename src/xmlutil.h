#ifndef XMLUTIL_H
#define XMLUTIL_H

#include "xpl.h"

#define XMLU_SCAN_END                      -1
#define XMLU_SCAN_DUPLICATION              -2
#define XMLU_SCAN_NOT_FOUND                -3
#define XMLU_SCAN_EMPTY                    -4
#define XMLU_SCAN_NO_PATH                  -5
#define XMLU_SCAN_NOT_ENOUGH_MEMORY        -6

typedef struct _XMLUSCANNODE {
  ULONG                cbName;
  PCHAR                pcName;
  ULONG                ulFlags;
  ULONG                cFound;
} XMLUSCANNODE, *PXMLUSCANNODE;

typedef struct _XMLUSCAN {
  xmlDocPtr            xmlDoc;
  xmlNodePtr           xmlNode;
  ULONG                cbValue;
  PCHAR                pcValue;
  ULONG                cNodes;
  XMLUSCANNODE         aNodes[1];
} XMLUSCAN, *PXMLUSCAN;

LONG xmluBeginScan(xmlNodePtr xmlNode, PXMLUSCAN *ppScan, PSZ pszNodes);
LONG xmluScan(PXMLUSCAN pScan);
VOID xmluEndScan(PXMLUSCAN pScan);
#ifdef DEBUG_FILE
VOID xmluDebugScan(PXMLUSCAN pScan);
#else
#define xmluDebugScan(p)
#endif
VOID xmluScanLog(PXMLUSCAN pScan, PSZ pszFormat, ...);

PSZ xmluGetNodeTextSZ(xmlNodePtr xmlNode);
BOOL xmluGetNodeText(xmlNodePtr xmlNode, PULONG pcbText, PCHAR *ppcText);
VOID xmluLog(xmlNodePtr xmlNode, PSZ pszFormat, ...);
ULONG xmluChildElementCount(xmlNodePtr xmlParent, PSZ pszName);

#endif // XMLUTIL_H
