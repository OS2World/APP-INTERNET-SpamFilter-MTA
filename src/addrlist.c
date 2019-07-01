#include <string.h>
#include "xpl.h"
#include "log.h"
#include "util.h"
#include "datafile.h"
#include "addrlist.h"
#include "hmem.h"
#include "debug.h"     // Must be the last.

static int _compKey(const void *pkey, const void *pbase)
{
  PADDRITEM            pItem = *(PADDRITEM *)pbase;

  return stricmp( (PSZ)pkey, &pItem->szAddr );
}


BOOL addrlstInit(PADDRLIST pAddrList, ULONG ulInitRecords)
{
  if ( ulInitRecords == 0 )
    ulInitRecords = 16;

  pAddrList->ppItems = hmalloc( sizeof(PADDRITEM) * ulInitRecords );
  if ( pAddrList->ppItems == NULL )
  {
    debug( "Not enough memory" );
    return FALSE;
  }

  xplMutexCreate( &pAddrList->hmtxList, FALSE );
  if ( pAddrList->hmtxList == NULLHANDLE )
  {
    debug( "xplMutexCreate() failed" );
    hfree( pAddrList->ppItems );
    pAddrList->ppItems = NULL;
    return FALSE;
  }

  pAddrList->ulMaxItems = ulInitRecords;
  pAddrList->cItems = 0;
  pAddrList->fChanged = FALSE;

  return TRUE;
}

VOID addrlstDone(PADDRLIST pAddrList)
{
  while( pAddrList->cItems != 0 )
  {
    pAddrList->cItems--;
    hfree( pAddrList->ppItems[pAddrList->cItems] );
  }

  hfree( pAddrList->ppItems );
  xplMutexDestroy( pAddrList->hmtxList );
  memset( pAddrList, 0, sizeof(ADDRLIST) );
}

// BOOL addrlstAdd(PADDRLIST pAddrList, PSZ pszAddr, ULONG ulTTL)
//
// Inserts a new address pszAddr to the list pAddrList for ulTTL seconds.
// It will be removed by addrlstClean() after ulTTL seconds. The address will
// newer removed from the list if ulTTL is 0.

BOOL addrlstAdd(PADDRLIST pAddrList, PSZ pszAddr, ULONG ulTTL)
{
  PADDRITEM  pItem;
  ULONG      cbAddr = strlen( pszAddr );
  ULONG      ulIndex;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );

  if ( !utilBSearch( (const void *)pszAddr, pAddrList->ppItems,
                     pAddrList->cItems, sizeof(PADDRITEM), _compKey,
                     &ulIndex ) )
  {
    // Address is not found in the list.

    pItem = hmalloc( sizeof(ADDRITEM) + cbAddr );
    if ( pItem == NULL )
    {
      debug( "Not enough memory" );
      xplMutexUnlock( pAddrList->hmtxList );
      return FALSE;
    }

    if ( pAddrList->cItems == pAddrList->ulMaxItems )
    {
      // Expand list for next 64 records.
      PADDRITEM        *ppItems = hrealloc( pAddrList->ppItems,
                              sizeof(PADDRITEM) * ( pAddrList->cItems + 64 ) );
      if ( ppItems == NULL )
      {
        debug( "Not enough memory" );
        hfree( pItem );
        xplMutexUnlock( pAddrList->hmtxList );
        return FALSE;
      }
      pAddrList->ppItems = ppItems;
      pAddrList->ulMaxItems += 64;
    }

    // Insert the new record at position ulIndex to keep order.
    memmove( &pAddrList->ppItems[ulIndex + 1],
             &pAddrList->ppItems[ulIndex],
             (pAddrList->cItems - ulIndex) * sizeof(PADDRITEM) );
    pAddrList->ppItems[ulIndex] = pItem;
    pAddrList->cItems++;

    strcpy( &pItem->szAddr, pszAddr );
  }
  else
  {
    pItem = pAddrList->ppItems[ulIndex];

    if ( pItem->timeExpire == 0 )
    {
      // Unremovable record.
      xplMutexUnlock( pAddrList->hmtxList );
      return TRUE;
    }
  }

  if ( ulTTL != 0 )
  {
    pItem->timeExpire = time( NULL ) + ulTTL;
    pAddrList->fChanged = TRUE;
  }
  else
    pItem->timeExpire = 0;

  xplMutexUnlock( pAddrList->hmtxList );
  return TRUE;
}

BOOL addrlstCheck(PADDRLIST pAddrList, PSZ pszAddr)
{
  BOOL       fFound;
  ULONG      ulIndex;

  if ( pszAddr == NULL )
    return FALSE;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );
  fFound = utilBSearch( (const void *)pszAddr, pAddrList->ppItems,
                        pAddrList->cItems, sizeof(PADDRITEM), _compKey,
                        &ulIndex );
  xplMutexUnlock( pAddrList->hmtxList );

  return fFound;
}

// VOID addrlstClean(PADDRLIST pAddrList)
//
// Removes all expired addresses.

VOID addrlstClean(PADDRLIST pAddrList)
{
  time_t     timeNow = time( NULL );
  LONG       lIdx;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );
  for( lIdx = pAddrList->cItems - 1; lIdx >= 0; lIdx-- )
  {
    if ( ( pAddrList->ppItems[lIdx]->timeExpire == 0 ) ||
         ( pAddrList->ppItems[lIdx]->timeExpire >= timeNow ) )
      continue;

    hfree( pAddrList->ppItems[lIdx] );

    pAddrList->cItems--;
    memcpy( &pAddrList->ppItems[lIdx], &pAddrList->ppItems[lIdx + 1],
            sizeof(PADDRITEM) * (pAddrList->cItems - lIdx) );

    pAddrList->fChanged = TRUE;
  }
  xplMutexUnlock( pAddrList->hmtxList );
}

// BOOL addrlstSave(PADDRLIST pAddrList, PSZ pszFile)
//
// Stores all temporary addresses (TTL != 0) to the file pszFile.
// Returns FALSE when an error occurs.

BOOL addrlstSave(PADDRLIST pAddrList, PSZ pszFile)
{
  CHAR       acTempFN[_MAX_PATH];
  FILE       *fdAddrList;
  PADDRITEM  pItem;
  ULONG      ulIdx;

  if ( dfSetUniqueExtension( sizeof(acTempFN), &acTempFN, pszFile ) == -1 )
    return FALSE;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );
  if ( !pAddrList->fChanged )
  {
    // Has no changes (for temporary addresses).
    xplMutexUnlock( pAddrList->hmtxList );
    return TRUE;
  }

  fdAddrList = fopen( &acTempFN, "w" );
  if ( fdAddrList == NULL )
  {
    xplMutexUnlock( pAddrList->hmtxList );
    log( 1, "Cannot open/create file: %s", &acTempFN );
    return FALSE;
  }

  for( ulIdx = 0; ulIdx < pAddrList->cItems; ulIdx++ )
  {
    pItem = pAddrList->ppItems[ulIdx];
    if ( pItem->timeExpire != 0 )
      fprintf( fdAddrList, "%s %u\n", &pItem->szAddr, pItem->timeExpire );
  }
  pAddrList->fChanged = FALSE;
  xplMutexUnlock( pAddrList->hmtxList );

  fclose( fdAddrList );

  return dfBackupFileReplace( pszFile, &acTempFN, "bkp", TRUE );
}

// BOOL addrlstLoad(PADDRLIST pAddrList, PSZ pszFile)
//
// Removes all temporary addresses (TTL != 0) from the list, loads temporary
// addreses from file pszFile.
// Returns FALSE when an error occurs.

BOOL addrlstLoad(PADDRLIST pAddrList, PSZ pszFile)
{
  CHAR       acBuf[_MAX_PATH];
  FILE       *fdAddrList = dfBackupOpenFile( pszFile, "bkp" );
  LONG       lIdx;
  time_t     timeNow, timeExpire;
  ULONG      cbText, cbAddr, cbExpire;
  PCHAR      pcText, pcAddr, pcExpire;

  if ( fdAddrList == NULL )
    return FALSE;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );

  // Remove temporary records from the list.
  for( lIdx = pAddrList->cItems - 1; lIdx >= 0; lIdx-- )
  {
    if ( pAddrList->ppItems[lIdx]->timeExpire == 0 )
      continue;

    hfree( pAddrList->ppItems[lIdx] );
    memcpy( &pAddrList->ppItems[lIdx], &pAddrList->ppItems[lIdx + 1],
            sizeof(PADDRITEM) * ((--pAddrList->cItems) - lIdx) );
  }

  // Read records from the file.
  time( &timeNow );
  while( fgets( &acBuf, sizeof(acBuf), fdAddrList ) != NULL )
  {
    cbText = strlen( &acBuf );
    pcText = &acBuf;

    utilStrCutWord( &cbText, &pcText, &cbAddr, &pcAddr );
    utilStrCutWord( &cbText, &pcText, &cbExpire, &pcExpire );
    if ( ( cbAddr == 0 ) ||
         !utilStrToULong( cbExpire, pcExpire, timeNow + 1, ~0, &timeExpire ) )
      continue;

    pcAddr[cbAddr] = '\0';
    addrlstAdd( pAddrList, pcAddr, timeExpire - timeNow );
  }
  pAddrList->fChanged = FALSE;

  xplMutexUnlock( pAddrList->hmtxList );
  fclose( fdAddrList );

  return TRUE;
}

ULONG addrlstGetCount(PADDRLIST pAddrList)
{
  ULONG      ulCount;

  xplMutexLock( pAddrList->hmtxList, XPL_INDEFINITE_WAIT );
  ulCount = pAddrList->cItems;
  xplMutexUnlock( pAddrList->hmtxList );

  return ulCount;
}
