#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "xpl.h"
#include "util.h"
#include "linkseq.h"
#include "config.h"
#include "log.h"
#include "datafile.h"
#include "greylist.h"
#include "debug.h"

#define GL_FILE        "GrLst.txt"
#define GL_CFFILE      "GrLstCf.txt"


typedef struct _GLRCPT {
  SEQOBJ               seqObj;

  time_t               timeExpire;
  ULONG                cFound;
  CHAR                 szAddr[1];
} GLRCPT, *PGLRCPT;

typedef struct _GLITEM {
  SEQOBJ               seqObj;

  struct in_addr       stInAddr;
  LINKSEQ              lsRcpt;
  CHAR                 szSender[1];
} GLITEM, *PGLITEM;

static HMTX            hmtxGL = NULLHANDLE;
static LINKSEQ         lsGL;


typedef struct _IPCF {
  struct in_addr       stInAddr;
  time_t               timeExpire;
  ULONG                ulNum;    // ulNum <= ulDen,
  ULONG                ulDen;
} IPCF, *PIPCF;

static PIPCF           paIPCf = NULL;
static ULONG           cIPCf = 0;
static ULONG           ulIPCfMax = 0;

static int __ipCfCompAddr(const void *pAddr, const void *pIPCf)
{
  ULONG      ulIP1 = ntohl( ((struct in_addr *)pAddr)->s_addr );
  ULONG      ulIP2 = ntohl( ((PIPCF)pIPCf)->stInAddr.s_addr );

  return ulIP1 < ulIP2 ? -1 : ( ulIP1 == ulIP2 ? 0 : 1 );
}

static VOID _ipCfChange(struct in_addr stInAddr, BOOL fIncr, time_t timeNow)
{
  PIPCF      pIPCf;
  ULONG      ulIndex;

  if ( pConfig->ulGreylistCfTTL == 0 )
    // Coefficients not used.
    return;

  if ( !utilBSearch( &stInAddr, paIPCf, cIPCf, sizeof(IPCF), __ipCfCompAddr,
                     &ulIndex ) )
  {
    // New record.

    if ( cIPCf == ulIPCfMax )
    {
      PIPCF    paNewIPCf = debugReAlloc( paIPCf, sizeof(IPCF) * (cIPCf + 256) );

      if ( paNewIPCf == NULL )
      {
        debug( "Not enough memory" );
        return;
      }

      paIPCf = paNewIPCf;
      ulIPCfMax += 256;
    }

    // Insert the new record at position ulIndex to keep order.
    memmove( &paIPCf[ulIndex + 1], &paIPCf[ulIndex],
             (cIPCf - ulIndex) * sizeof(IPCF) );
    cIPCf++;

    pIPCf = &paIPCf[ulIndex];
    pIPCf->stInAddr = stInAddr;
    pIPCf->ulNum = fIncr ? 1 : 0;
    pIPCf->ulDen = 1;
  }
  else
  {
    pIPCf = &paIPCf[ulIndex];

    if ( pIPCf->ulDen < pConfig->ulGreylistCfDen )
    {
      // Coefficient is not yet ready.
      pIPCf->ulNum += fIncr ? 1 : 0;
      pIPCf->ulDen++;
    }
    else if ( pIPCf->ulDen == pConfig->ulGreylistCfDen )
    {
      // Coefficient ready - change only numerator.
      if ( fIncr )
      {
        if ( pIPCf->ulNum < pIPCf->ulDen )
          pIPCf->ulNum++;
      }
      else if ( !fIncr )
      {
        if ( pIPCf->ulNum > 0 )
          pIPCf->ulNum--;
      }
    }
    else
    {
      // Correct coefficient for the new configured value.
      pIPCf->ulNum = ( pConfig->ulGreylistCfDen * pIPCf->ulNum ) / pIPCf->ulDen;
      pIPCf->ulDen = pConfig->ulGreylistCfDen;
    }
  } // if ( !utilBSearch() ) else

  pIPCf->timeExpire = timeNow + pConfig->ulGreylistCfTTL;
}

// static BOOL _ipCfCheck(PSESS pSess)
//
// Return TRUE when IP's coefficient high enough (i.e. do not use greylist).

static BOOL _ipCfCheck(PSESS pSess)
{
  PIPCF      pIPCf;
  ULONG      ulIndex;

  if ( ( pConfig->ulGreylistCfTTL == 0 ) ||
       !utilBSearch( &pSess->stInAddr, paIPCf, cIPCf, sizeof(IPCF),
                     __ipCfCompAddr, &ulIndex ) )
    return FALSE;

  pIPCf = &paIPCf[ulIndex];
  if ( ( pIPCf->ulDen != pConfig->ulGreylistCfDen ) ||
       ( pIPCf->ulNum <= pConfig->ulGreylistCfNum ) )
    return FALSE;

  sessLog( pSess, 5, SESS_LOG_INFO,
           "Greylist coefficient for %s high enough: %u/%u",
           inet_ntoa( pSess->stInAddr ), pIPCf->ulNum, pIPCf->ulDen );  

  return TRUE;
}


static VOID _freeGLItem(PGLITEM pItem)
{
  lnkseqFree( &pItem->lsRcpt, PGLRCPT, debugFree );
  debugFree( pItem );
}

static PGLITEM _findItem(struct in_addr stInAddr, PSZ pszSender)
{
  PGLITEM    pItem;

  for( pItem = (PGLITEM)lnkseqGetFirst( &lsGL ); pItem != NULL;
       pItem = (PGLITEM)lnkseqGetNext( pItem ) )
  {
    if ( ( stInAddr.s_addr == pItem->stInAddr.s_addr ) &&
         ( STR_ICMP( pszSender, &pItem->szSender ) == 0 ) )
      break;
  }

  return pItem;
}

// BOOL glInit(ULONG ulTTL)
//
// Greylist initialization.
// ulTTL is time to live for single recepient added to the list.

BOOL glInit()
{
  CHAR                 acBuf[_MAX_PATH];
  FILE                 *fdGL;
  ULONG                cParts;
  UTILSTRPART          aParts[4];
  struct in_addr       stInAddr;
  PGLITEM              pItem = NULL;
  PGLRCPT              pRcpt;
  BOOL                 fError = FALSE;
  ULONG                ulLine = 0;
  ULONG                ulIndex;
  IPCF                 stIPCf;

  if ( hmtxGL != NULLHANDLE )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  xplMutexCreate( &hmtxGL, FALSE );
  if ( hmtxGL == NULLHANDLE )
  {
    debug( "xplMutexCreate() failed" );
    return FALSE;
  }

  lnkseqInit( &lsGL );

  // Load greylist.

  fdGL = dfBackupOpenFile( GL_FILE, "bkp" );
  if ( fdGL != NULL )
  {
    while( fgets( &acBuf, sizeof(acBuf), fdGL ) != NULL )
    {
      ulLine++;

      if ( *((PUSHORT)&acBuf) == (USHORT)'\n' )
        continue;

      cParts = ARRAY_SIZE( aParts );
      if ( ( utilStrSplitWords( strlen( &acBuf ), &acBuf, &cParts, &aParts )
               != 0 ) ||
           ( aParts[0].cbPart != 1 ) )
        fError = TRUE;
      else
      {
        switch( *aParts[0].pcPart )
        {
          case 'I':      // I ip-address [sender@address.dom]
            if ( ( cParts < 2 ) || ( cParts > 3 ) ||
                 !utilStrToInAddr( aParts[1].cbPart, aParts[1].pcPart,
                                   &stInAddr ) )
            {
              fError = TRUE;
              break;
            }

            pItem = debugMAlloc( sizeof(GLITEM) + aParts[2].cbPart );
            if ( pItem != NULL )
            {
              lnkseqAdd( &lsGL, pItem );
              pItem->stInAddr = stInAddr;
              lnkseqInit( &pItem->lsRcpt );
              memcpy( &pItem->szSender, aParts[2].pcPart, aParts[2].cbPart );
              pItem->szSender[ aParts[2].cbPart ] = '\0';
            }
            break;

          case 'R':      // R time-expire found-counter recepient@address.dom
            if ( ( cParts == 4 ) && ( pItem != NULL ) )
            {
              pRcpt = debugMAlloc( sizeof(GLRCPT) + aParts[3].cbPart );
              if ( pRcpt == NULL )
                break;

              lnkseqAdd( &pItem->lsRcpt, pRcpt );
              if ( utilStrToULong( aParts[1].cbPart, aParts[1].pcPart, 0, ~0,
                                    &pRcpt->timeExpire ) &&
                   utilStrToULong( aParts[2].cbPart, aParts[2].pcPart, 0, ~0,
                                    &pRcpt->cFound ) )
              {
                memcpy( &pRcpt->szAddr, aParts[3].pcPart, aParts[3].cbPart );
                pRcpt->szAddr[ aParts[3].cbPart ] = '\0';
                break;
              }
            }

          default:
            fError = TRUE;
        }
      }

      if ( fError )
      {
        lnkseqFree( &lsGL, PGLITEM, _freeGLItem );
        log( 1, "Error in "GL_FILE" at line %u: \"%s\"", ulLine, &acBuf );
        break;
      }
    }

    fclose( fdGL );
    if ( !fError )
      log( 5, "%u item(s) loaded from "GL_FILE, lnkseqGetCount( &lsGL ) );
  } // if ( fdGL != NULL )

  // Load coefficients.

  fdGL = dfBackupOpenFile( GL_CFFILE, "bkp" );
  if ( fdGL != NULL )
  {
    ulLine = 0;
    while( fgets( &acBuf, sizeof(acBuf), fdGL ) != NULL )
    {
      ulLine++;
      cParts = ARRAY_SIZE( aParts );
      if ( ( utilStrSplitWords( strlen( &acBuf ), &acBuf, &cParts, &aParts )
               == 0 ) && ( cParts == 4 ) &&
           utilStrToInAddr( aParts[0].cbPart, aParts[0].pcPart,
                            &stIPCf.stInAddr ) &&
           utilStrToULong( aParts[1].cbPart, aParts[1].pcPart, 0, ~0,
                           &stIPCf.timeExpire ) &&
           utilStrToULong( aParts[2].cbPart, aParts[2].pcPart, 0, ~0,
                           &stIPCf.ulNum ) &&
           utilStrToULong( aParts[3].cbPart, aParts[3].pcPart, 0, ~0,
                           &stIPCf.ulDen ) )
      {
        if ( utilBSearch( &stIPCf.stInAddr, paIPCf, cIPCf, sizeof(IPCF),
                          __ipCfCompAddr, &ulIndex ) )
        {
          log( 1, "Duplicate address in "GL_CFFILE" at line %u: \"%s\"",
               ulLine, &acBuf );
          continue;
        }
        
        if ( cIPCf == ulIPCfMax )
        {
          // Expand coefficient list for next 128 records.
          PIPCF    paNewIPCf = debugReAlloc( paIPCf,
                                             sizeof(IPCF) * (cIPCf + 128) );
          if ( paNewIPCf == NULL )
          {
            debug( "Not enough memory" );
            break;
          }
          paIPCf = paNewIPCf;
          ulIPCfMax += 128;
        }

        memmove( &paIPCf[ulIndex + 1], &paIPCf[ulIndex],
                 (cIPCf - ulIndex) * sizeof(IPCF) );
        cIPCf++;
        paIPCf[ulIndex] = stIPCf;
        continue;
      }

      cIPCf = 0;
      log( 1, "Error in "GL_CFFILE" at line %u: \"%s\"", ulLine, &acBuf );
      break;
    }

    fclose( fdGL );
    if ( cIPCf != 0 )
      log( 5, "%u item(s) loaded from "GL_CFFILE, cIPCf );
  } // if ( fdGL != NULL )

  return TRUE;
}

VOID glDone()
{
  if ( hmtxGL == NULLHANDLE )
  {
    debug( "Was not initialized" );
    return;
  }

  lnkseqFree( &lsGL, PGLITEM, _freeGLItem );
  xplMutexDestroy( hmtxGL );
  hmtxGL = NULLHANDLE;

  if ( paIPCf != NULL )
    debugFree( paIPCf );
  paIPCf = NULL;
  cIPCf = 0;
  ulIPCfMax = 0;
}

// LONG glAdd(PSESS pSess)
//
// Inserts a new record(s) to the greylist. Returns number of new recepients in
// the list for given ip-address and sender or -1 when
// greylist should not be used.

LONG glAdd(PSESS pSess)
{
  PGLITEM              pItem;
  PGLRCPT              pRcpt;
  LONG                 cAdded = 0;
  ULONG                ulIdx;
  PSZ                  pszRcpt;
  struct in_addr       stInAddr;

  if ( pConfig->ulGreylistTTL == 0 )
    return -1;

  if ( sessClientListed( pSess, &pConfig->lsHostListGreylistIgnore ) )
  {
    sessLog( pSess, 5, SESS_LOG_INFO, "Ignore greylist for client [%s] %s",
             inet_ntoa( pSess->stInAddr ), STR_SAFE( pSess->pszHostName ) );

    return -1;
  }

  if ( cfgIsMatchPtrnList( pConfig->cbGreylistIgnoreSenders,
                           pConfig->pcGreylistIgnoreSenders,
                           STR_LEN( pSess->pszSender ), pSess->pszSender ) )
  {
    sessLog( pSess, 5, SESS_LOG_INFO, "Ignore greylist for sender <%s>",
             pSess->pszSender );
    return -1;
  }

  if ( xplMutexLock( hmtxGL, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    return -1;
  }

  if ( _ipCfCheck( pSess ) )
  {
    xplMutexUnlock( hmtxGL );
    return -1;
  }

  stInAddr.s_addr = pSess->stInAddr.s_addr & pConfig->stGreylistMask.s_addr;

  pItem = _findItem( stInAddr, pSess->pszSender );
  if ( pItem == NULL )
  {
    pItem = debugMAlloc( sizeof(GLITEM) + STR_LEN( pSess->pszSender ) );
    if ( pItem == NULL )
    {
      debug( "Not enough memory" );
      xplMutexUnlock( hmtxGL );
      return -1;
    }
    pItem->stInAddr = stInAddr;
    lnkseqInit( &pItem->lsRcpt );
    STR_COPY( &pItem->szSender, pSess->pszSender );
    lnkseqAdd( &lsGL, pItem );
  }

  for( ulIdx = 0; ulIdx < pSess->cRcpt; ulIdx++ )
  {
    pszRcpt = pSess->ppszRcpt[ulIdx];

    for( pRcpt = (PGLRCPT)lnkseqGetFirst( &pItem->lsRcpt );
         ( pRcpt != NULL ) && ( strcmp( pszRcpt, &pRcpt->szAddr ) != 0 );
         pRcpt = (PGLRCPT)lnkseqGetNext( pRcpt ) );

    if ( pRcpt != NULL )
      pRcpt->cFound++;
    else
    {
      pRcpt = debugMAlloc( sizeof(GLRCPT) + strlen( pszRcpt ) );
      if ( pRcpt == NULL )
      {
        debug( "Not enough memory" );
        break;
      }

      strcpy( pRcpt->szAddr, pszRcpt );
      pRcpt->cFound = 0;
      pRcpt->timeExpire = time( NULL ) + pConfig->ulGreylistTTL;
      lnkseqAdd( &pItem->lsRcpt, pRcpt );
      cAdded++;
    }
  }

  xplMutexUnlock( hmtxGL );
  return cAdded;
}

// VOID glClean()
//
// Removes all expired records from the greylist.

VOID glClean()
{
  time_t     timeNow = time( NULL );
  PGLITEM    pItem, pNextItem;
  PGLRCPT    pRcpt, pNextRcpt;
  ULONG      ulIdx;
  PIPCF      pIPCf;

  xplMutexLock( hmtxGL, XPL_INDEFINITE_WAIT );

  for( pItem = (PGLITEM)lnkseqGetFirst( &lsGL ); pItem != NULL; )
  {
    pNextItem = (PGLITEM)lnkseqGetNext( pItem );

    // Remove expired recepients from the greylist item.
    for( pRcpt = (PGLRCPT)lnkseqGetFirst( &pItem->lsRcpt ); pRcpt != NULL; )
    {
      pNextRcpt = (PGLRCPT)lnkseqGetNext( pRcpt );

      if ( pRcpt->timeExpire < timeNow )
      {
        _ipCfChange( pItem->stInAddr, pRcpt->cFound != 0, timeNow );
        lnkseqRemove( &pItem->lsRcpt, pRcpt );
        debugFree( pRcpt );
      }

      pRcpt = pNextRcpt;
    }

    // Remove greylist item without recipients.
    if ( lnkseqIsEmpty( &pItem->lsRcpt ) )
    {
      lnkseqRemove( &lsGL, pItem );
      _freeGLItem( pItem );
    }

    pItem = pNextItem;
  }

  // Remove expired coefficients.

  ulIdx = 0;
  pIPCf = paIPCf;
  while( ulIdx < cIPCf )
  {
    if ( pIPCf->timeExpire < timeNow )
    {
      cIPCf--;
      memcpy( pIPCf, &pIPCf[1], (cIPCf - ulIdx) * sizeof(IPCF) );
      continue;
    }
           
    ulIdx++;
    pIPCf++;
  }

  xplMutexUnlock( hmtxGL );
}

VOID glGetCounters(PULONG pulIPSender, PULONG pulIPCf)
{
  if ( xplMutexLock( hmtxGL, XPL_INDEFINITE_WAIT ) != XPL_NO_ERROR )
  {
    debug( "Mutex lock failed" );
    *pulIPSender = 0;
    *pulIPCf = 0;
    return;
  }

  *pulIPSender = lnkseqGetCount( &lsGL );
  *pulIPCf = cIPCf;
  xplMutexUnlock( hmtxGL );
}

BOOL glSave()
{
  CHAR       acTempFN[_MAX_PATH];
  FILE       *fdGL;
  PGLITEM    pItem;
  PGLRCPT    pRcpt;
  ULONG      ulIdx;
  PIPCF      pIPCf;

  if ( dfSetUniqueExtension( sizeof(acTempFN), &acTempFN, GL_FILE ) == -1 )
    return FALSE;

  fdGL = fopen( &acTempFN, "w" );
  if ( fdGL == NULL )
  {
    log( 1, "Cannot open/create file: %s", &acTempFN );
    return FALSE;
  }

  xplMutexLock( hmtxGL, XPL_INDEFINITE_WAIT );

  for( pItem = (PGLITEM)lnkseqGetFirst( &lsGL ); pItem != NULL;
       pItem = (PGLITEM)lnkseqGetNext( pItem ) )
  {
    fprintf( fdGL, "I %s %s\n", inet_ntoa( pItem->stInAddr ), &pItem->szSender );

    for( pRcpt = (PGLRCPT)lnkseqGetFirst( &pItem->lsRcpt ); pRcpt != NULL;
         pRcpt = (PGLRCPT)lnkseqGetNext( pRcpt ) )
    {
      fprintf( fdGL, "R %u %u %s\n", pRcpt->timeExpire, pRcpt->cFound,
               &pRcpt->szAddr );
    }
  }

  fclose( fdGL );
  if ( !dfBackupFileReplace( GL_FILE, &acTempFN, "bkp", TRUE ) )
  {
    debug( "Cannot rename %s to %s.", &acTempFN, GL_FILE );
  }

  if ( dfSetUniqueExtension( sizeof(acTempFN), &acTempFN, GL_CFFILE ) == -1 )
  {
    xplMutexUnlock( hmtxGL );
    debug( "dfSetUniqueExtension() failed" );
    return FALSE;
  }

  fdGL = fopen( &acTempFN, "w" );
  if ( fdGL == NULL )
  {
    xplMutexUnlock( hmtxGL );
    log( 1, "Cannot open/create file: %s", &acTempFN );
    return FALSE;
  }

  for( ulIdx = 0, pIPCf = paIPCf; ulIdx < cIPCf; ulIdx++, pIPCf++ )
  {
    fprintf( fdGL, "%s %u %u %u\n", inet_ntoa( pIPCf->stInAddr ), pIPCf->timeExpire,
             pIPCf->ulNum, pIPCf->ulDen );
  }

  xplMutexUnlock( hmtxGL );

  fclose( fdGL );
  return dfBackupFileReplace( GL_CFFILE, &acTempFN, "bkp", TRUE );
}
