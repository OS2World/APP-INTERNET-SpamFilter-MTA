#include <string.h>
#include <stdio.h>
#include <malloc.h>
#define SPF_C
#include "spf.h"
#include "dns.h"
#include "util.h"
#include "linkseq.h"
#include "hmem.h"
#include "debug.h"     // Must be the last.

//Check result names (index - spfCheckHost() return code).
PSZ apszSPFResult[7] = { "None", "Neutral", "Pass", "Fail", "SoftFail",
                         "TempError", "PermError" };

#define _MECHANISMS              "all include a mx ptr ip4 ip6 exists"
#define _MODIFIERS               "redirect exp"

#define _TOKEN_ALL               0
#define _TOKEN_INCLUDE           1
#define _TOKEN_A                 2
#define _TOKEN_MX                3
#define _TOKEN_PTR               4
#define _TOKEN_IP4               5
#define _TOKEN_IP6               6
#define _TOKEN_EXISTS            7
#define _TOKEN_REDIRECT          0
#define _TOKEN_EXP               1

typedef struct _MECHANISM {
  SEQOBJ               seqObj;

  ULONG                ulSign;
  ULONG                ulType;
  struct in_addr       stMask;
  CHAR                 acArg[1]; // <target-name> or struct in_addr for "ip4"
} MECHANISM, *PMECHANISM;


typedef struct _CHECKDATA {
  struct in_addr       stIP;
  PSZ                  pszSender;
  PSZ                  pszHELO;

  ULONG                cNSReq;
  CHAR                 acNSRes[512];
  CHAR                 acTargetName[512];  // Buffer for script result.
  PCHAR                pcExp;              // Text result ("Exp" modifier)
  ULONG                cbExp;
} CHECKDATA, *PCHECKDATA;

static CHAR  aHEX[] = "0123456789ABCDEF";

static BOOL __scriptAddToOutput(ULONG cbInput, PCHAR pcInput, PSZ pszDelimiter,
                                ULONG ulParts, BOOL fRev, BOOL fURIEnc,
                                PULONG pcbBuf, PCHAR *ppcBuf )
{
  ULONG      cbBuf;
  PCHAR      pcBuf;
  ULONG      cbStored;

  if ( fURIEnc )
  {
    pcBuf = alloca( cbInput );
    if ( pcBuf == NULL )
    {
      debug( "Not enough stack size" );
      return FALSE;
    }
    cbBuf = cbInput;
  }
  else
  {
    cbBuf = *pcbBuf;
    pcBuf = *ppcBuf;
  }

  if ( fRev || ( ulParts != 0 ) )
  {
    // Reverse/cut parts of the name (input string).
    cbStored = cbBuf;
    if ( !utilStrBuildParts( cbInput, pcInput, pszDelimiter,
                             ulParts, fRev, '.', &cbStored, pcBuf ) )
      return FALSE;
  }
  else if ( cbBuf >= cbInput )
  {
    memcpy( pcBuf, pcInput, cbInput );
    cbStored = cbInput;
  }
  else
    return FALSE;

  if ( !fURIEnc )
  {
    (*pcbBuf) -= cbStored;
    (*ppcBuf) += cbStored;
    return TRUE;
  }

  // URL-encoding

  {
    ULONG      cbOut = *pcbBuf;
    PCHAR      pcOut = *ppcBuf;

    for( ; cbBuf != 0; cbBuf--, pcBuf++ )
    {
      if ( !isalnum( *pcBuf ) && ( strchr( "-._~", *pcBuf ) == NULL ) )
      {
        if ( cbOut < 3 )
          return FALSE;
        *(pcOut++) = '%';
        *(pcOut++) = aHEX[ (*pcBuf) >> 4 ];
        *(pcOut++) = aHEX[ (*pcBuf) & 0x0F ];
        cbOut -= 3;
      }
      else if ( cbOut != 0 )
      {
        *(pcOut++) = *pcBuf;
        cbOut--;
      }
      else
        return FALSE;
    }

    *pcbBuf = cbOut;
    *ppcBuf = pcOut;
  }

  return TRUE;
}

// BOOL _scriptStr(PCHECKDATA pData, ULONG cbStr, PCHAR pcStr,
//                 PSZ pszDomain, ULONG cbBuf, PCHAR pcBuf)
//
// Executes macro from pcStr and places result at the pcBuf.
// Returns FALSE when an error occurs.


static BOOL _scriptStr(PCHECKDATA pData, ULONG cbStr, PCHAR pcStr,
                       PSZ pszDomain, ULONG cbBuf, PCHAR pcBuf)
{
  ULONG      ulRC;

  debug( "Input string: %s", debugBufPSZ( pcStr, cbStr ) );

  while( cbStr != 0 )
  {
    if ( *pcStr == '%' )
    {
      pcStr++;
      if ( (--cbStr) == 0 )
        return FALSE;

      switch( *pcStr )
      {
        case '%':                // "%%" -> %
          if ( cbBuf <= 1 )
            return FALSE;
          *(pcBuf++) = '%';
          cbBuf--;
          pcStr++;
          cbStr--;
          break;

        case '_':                // "%_" -> SP
          if ( cbBuf <= 1 )
            return FALSE;
          *(pcBuf++) = ' ';
          cbBuf--;
          pcStr++;
          cbStr--;
          break;

        case '-':                // "%-" -> URL-encoded space: "%20"
          if ( cbBuf <= 3 )
            return FALSE;
          *(pcBuf++) = '%';
          *(pcBuf++) = '2';
          *(pcBuf++) = '0';
          cbBuf -= 3;
          pcStr++;
          cbStr--;
          break;

        case '{':                // %{...} - macro-expand
          {
            CHAR       chLetter;           // Macro-letter.
            BOOL       fURIEnc;            // Result must be URI-encoded.
            ULONG      ulParts = 0;        // Transformer number.
            BOOL       fRev;               // Transformer "r".
            CHAR       acDelimiter[8];     // Delimiters.
            PCHAR      pcInputStr;         // String defined by macro-letter;
            ULONG      cbInputStr;         // ...and length of this string.
            PCHAR      pcAt;
            CHAR       acBuf[16];
            PCHAR      pcDelimiter;

            chLetter = tolower( *(++pcStr) );
            fURIEnc = isupper( *pcStr ) != 0;
            pcStr++;
            if ( (--cbStr) == 0 )
              return FALSE;

            if ( strchr( "slodiphcrtv", chLetter ) == NULL )
            {
              debug( "Not valid macro-letter: %c", chLetter );
              return FALSE;
            }

            for( ; (cbStr != 0) && isdigit( *pcStr ); pcStr++, cbStr-- )
            {
              ulParts = ( 10 * ulParts ) + ( *pcStr - '0' );
              if ( ulParts > 64 )
                return FALSE;
            }
            if ( cbStr == 0 )
              return FALSE;

            fRev = ( *pcStr == 'r' ) || ( *pcStr == 'R' );
            if ( fRev )
            {
              pcStr++;
              if ( (--cbStr) == 0 )
                return FALSE;
            }

            pcDelimiter = &acDelimiter;
            while( (pcDelimiter - &acDelimiter) < (sizeof(acDelimiter) - 1) &&
                   ( strchr( ".-+,/_=", *pcStr ) != NULL ) )
            {
              *(pcDelimiter++) = *(pcStr++);
              if ( (--cbStr) == 0 )
                return FALSE;
            }
            if ( pcDelimiter == &acDelimiter )
              *(pcDelimiter++) = '.';      // The default delimiter is a dot.
            *pcDelimiter = '\0';

            if ( *pcStr != '}' )
            {
              debug( "Right bracket '}' not found" );
              return FALSE;
            }
            pcStr++;
            cbStr--;

            // Get input string for the given macro-letter.

            switch( chLetter )
            {
              case 's':          // <sender>
                pcInputStr = pData->pszSender;
                cbInputStr = strlen( pcInputStr );
                break;

              case 'l':          // Local-part of <sender>, def. is postmaster.
                pcAt = strchr( pData->pszSender, '@' );

                if ( ( pcAt == NULL ) || ( pcAt == pData->pszSender ) )
                {
                  pcInputStr = "postmaster";
                  cbInputStr = 10;
                  break;
                }
                pcInputStr = pData->pszSender;
                cbInputStr = pcAt - pcInputStr;
                break;

              case 'o':          // Domain of <sender>.
                pcAt = strchr( pData->pszSender, '@' );
                pcInputStr = pcAt == NULL ? pData->pszSender : &pcAt[1];
                cbInputStr = strlen( pcInputStr );
                break;

              case 'd':          // <domain>.
                pcInputStr = pszDomain;
                cbInputStr = strlen( pcInputStr );
                break;

              case 'i':          // <ip>.
              case 'c':          // SMTP client IP (easily readable format).
                cbInputStr = sprintf( &acBuf, "%u.%u.%u.%u",
                           ((PCHAR)&pData->stIP)[0], ((PCHAR)&pData->stIP)[1],
                           ((PCHAR)&pData->stIP)[2], ((PCHAR)&pData->stIP)[3] );
                pcInputStr = &acBuf;
                break;

              case 'p':          // Validated domain name of <ip> or "unknown".
                {
                  CHAR           acBuf[512];
                  ULONG          cItems;
                  PCHAR          pcBuf;
                  ULONG          ulIdx;

                  ulRC = dnsValidateDomainNames( pData->stIP, &pData->cNSReq,
                                              sizeof(acBuf), &acBuf, &cItems );
                  if ( ( ulRC == DNS_NOERROR ) && ( cItems != 0 ) )
                  {
                    pcInputStr = NULL;

                    // If the <domain> is present in the list of validated
                    // domains, it SHOULD be used.
                    for( ulIdx = 0, pcBuf = &acBuf; ulIdx < cItems;
                         ulIdx++, pcBuf = strchr( pcBuf, '\0' ) + 1 )
                      if ( stricmp( pcBuf, pszDomain ) == 0 )
                      {
                        pcInputStr = pszDomain;
                        break;
                      }

                    if ( pcInputStr == NULL )
                    {
                      // Otherwise, if a subdomain of the <domain> is present,
                      // it SHOULD be used.
                      PCHAR      pcSub = strchr( pszDomain, '.' );

                      if ( pcSub != NULL )
                      {
                        pcSub++;
                        for( ulIdx = 0, pcBuf = &acBuf; ulIdx < cItems;
                             ulIdx++, pcBuf = strchr( pcBuf, '\0' ) + 1 )
                          if ( stricmp( pcBuf, pcSub ) == 0 )
                          {
                            pcInputStr = pcBuf;
                            break;
                          }
                      }

                      if ( pcInputStr == NULL )
                        // Otherwise, any name from the list can be used. 
                        pcInputStr = &acBuf; // First founded name.
                    }
                  }
                  else
                    // If there are no validated domain names or if a DNS error
                    // occurs, the string "unknown" is used.
                    pcInputStr = "unknown";

                  cbInputStr = strlen( pcInputStr );
                }
                break;

              case 'v':          // The string "in-addr".
                pcInputStr = "in-addr";
                cbInputStr = 7;
                break;

              case 'h':          // HELO/EHLO domain.
                pcInputStr = pData->pszHELO;
                cbInputStr = strlen( pcInputStr );
                break;

              default:
                debug( "Macro-letter '%c' was not implemented!", chLetter );

              case 'r':          // Domain name of host performing the check.
                pcInputStr = "unknown";              // The configured MTA
                cbInputStr = 7;                      // name or "unknown".
                break;

              case 't':          // Current timestamp.
                {
                  ultoa( time( NULL ), &acBuf, 10 );
                  pcInputStr = &acBuf;
                  cbInputStr = strlen( &acBuf );
                }
                break;
            }

            if ( !__scriptAddToOutput( cbInputStr, pcInputStr, &acDelimiter,
                                     ulParts, fRev, fURIEnc, &cbBuf, &pcBuf ) )
              return FALSE;
          }
          break;

        default:
          return FALSE;
      }

    } // if ( *pcStr == '%' )
    else
    {
      if ( (cbBuf--) == 0 )
        return FALSE;
      *(pcBuf++) = *(pcStr++);
      cbStr--;
    }
  }

  if ( cbBuf == 0 )
    return FALSE;
  *pcBuf = '\0';
  return TRUE;
}

static ULONG _checkHost(PCHECKDATA pData, PSZ pszDomain)
{
  ULONG      ulRC;
  PCHAR      pcSPF = NULL;
  LINKSEQ    lsMechanisms;
  PMECHANISM pMechanism;
  ULONG      ulRes;
  ULONG      cNSRes;
  PCHAR      pcNSRes;
  PSZ        pszRedirect;
  PSZ        pszExp;
  BOOL       fMuch = FALSE;

  // Record lookup.

  ulRC = dnsRequest( DNSREC_TYPE_TXT, pszDomain, sizeof(pData->acNSRes),
                     &pData->acNSRes, &cNSRes );
  if ( ulRC == DNS_NXDOMAIN )
  {
    debug( "Request TXT for %s - Non-Existent Domain", pszDomain );
    return SPF_NONE;
  }
  if ( ulRC != DNS_NOERROR )
    return SPF_TEMPERROR;

  for( pcNSRes = &pData->acNSRes; cNSRes > 0;
       cNSRes--, pcNSRes = strchr( pcNSRes, '\0' ) + 1 )
  {
    if ( ( memicmp( pcNSRes, "v=spf1", 6 ) == 0 ) &&
         ( pcNSRes[6] == ' ' || pcNSRes[6] == '\0' ) )
    {
      if ( pcSPF != NULL )
      {
        debug( "More than one record found" );
        return SPF_PERMERROR;
      }

      pcSPF = pcNSRes;
    }
  }

  if ( pcSPF == NULL )
  {
    debug( "Resultant record set includes no SPF records" );
    return SPF_NONE;
  }
  debug( "SPF for %s: %s", pszDomain, pcSPF );
  pcSPF += 6;          // Skip "v=spf1".

  // Build list of tokens.

  lnkseqInit( &lsMechanisms );
  ulRes = SPF_PERMERROR;
  {
    ULONG              cbSPF = strlen( pcSPF );
    ULONG              cbToken;
    PCHAR              pcToken;
    PCHAR              pcName;
    ULONG              cbName;
    PCHAR              pcDomainSpec;
    ULONG              cbDomainSpec;
    ULONG              ulCIDRLen;
    ULONG              ulSign;
    LONG               lIdx;
    struct in_addr     stMask;
    ULONG              acbModifiers[2] = { 0 };
    PCHAR              apcModifiers[2] = { NULL };
    static PSZ   pszSigns   = "+-?~";
    static ULONG aulSigns[] = { SPF_PASS, SPF_FAIL, SPF_NEUTRAL, SPF_SOFTFAIL };

    while( TRUE )
    {
      utilStrCutWord( &cbSPF, &pcSPF, &cbToken, &pcToken );
      if ( cbToken == 0 )
      {
        ulRes = SPF_NONE;
        break;
      }

      pcName = pcToken;
      while( ( cbToken > 0 ) && ( strchr( "=:/", *pcToken ) == NULL ) )
      {
        pcToken++;
        cbToken--;
      }
      cbName = pcToken - pcName;
      if ( cbName == 0 )
        break;

      pcDomainSpec = NULL;
      cbDomainSpec = 0;
      ulCIDRLen = 32;

      if ( cbToken != 0 )
      {
        if ( *pcToken == '=' )
        {
          // Modifier.

          lIdx = utilStrWordIndex( _MODIFIERS, cbName, pcName );
          if ( lIdx == -1 )
          {
            debug( "Ignore unknown modifier: %s", debugBufPSZ( pcName, cbName ) );
            continue;
          }
          if ( cbToken <= 1 )
          {
            debug( "Value was not specified for modifier: %s", debugBufPSZ( pcName, cbName ) );
            continue;
          }
          // ["redirect", "exp"] These two modifiers MUST NOT appear in a
          // record more than once each. If they do, then check_host() exits
          // with a result of "permerror".
          if ( apcModifiers[lIdx] != NULL )
          {
            debug( "Error: duplicate modifier: %s", debugBufPSZ( pcName, cbName ) );
            break;
          }
          apcModifiers[lIdx] = pcToken + 1;
          acbModifiers[lIdx] = cbToken - 1;
          continue;
        }

        if ( *pcToken == ':' )
        {
          pcToken++;
          cbToken--;
          pcDomainSpec = pcToken;
          while( ( cbToken > 0 ) && ( *pcToken != '/' ) )
          {
            pcToken++;
            cbToken--;
          }
          cbDomainSpec = pcToken - pcDomainSpec;
        }

        if ( ( cbToken != 0 ) && ( *pcToken == '/' ) &&
             !utilStrToULong( cbToken-1, &pcToken[1], 1, 128, &ulCIDRLen ) )
          break;
      }

/*      printf( "Name: %s, domain-spec: %s, cidr-length: %u\n",
              debugBufPSZ( pcName, cbName ), 
              debugBufPSZ( pcDomainSpec, cbDomainSpec ), 
              ulCIDRLen );*/

      // Sign before mechanism.

      pcToken = strchr( pszSigns, *pcName );
      if ( pcToken != NULL )
      {
        ulSign = aulSigns[ pcToken - pszSigns ];
        pcName++;
        cbName--;
      }
      else
        ulSign = SPF_PASS;

      // Make mechanism record.

      lIdx = utilStrWordIndex( _MECHANISMS, cbName, pcName );
      if ( lIdx == -1 )
      {
        debug( "Unknown mechanism: %s", debugBufPSZ( pcName, cbName ) );
        continue;
      }

      utilCIDRLenToInAddr( ulCIDRLen, &stMask );
      if ( lIdx == _TOKEN_IP4 )
      {
        if ( !utilStrToInAddr( cbDomainSpec, pcDomainSpec,
                               (struct in_addr *)&pData->acTargetName ) )
        {
          debug( "ip4, invalid address: %s",
                 debugBufPSZ( pcDomainSpec, cbDomainSpec ) );
          break;
        }
        ((struct in_addr *)&pData->acTargetName)->s_addr &= stMask.s_addr;
        cbDomainSpec = sizeof(struct in_addr);
        pcDomainSpec = &pData->acTargetName;
      }
      else if ( pcDomainSpec != NULL )
      {
        if ( !_scriptStr( pData, cbDomainSpec, pcDomainSpec, pszDomain,
                           sizeof(pData->acTargetName), &pData->acTargetName ) )
        {
          debug( "_scriptStr() failed" );
          break;
        }
        cbDomainSpec = strlen( &pData->acTargetName ) + 1;
        pcDomainSpec = &pData->acTargetName;
      }
      else
      {
        cbDomainSpec = strlen( pszDomain ) + 1;
        pcDomainSpec = pszDomain;
      }

      pMechanism = hmalloc( sizeof(MECHANISM) - 1 + cbDomainSpec );
      if ( pMechanism == NULL )
      {
        debug( "Not enough memory" );
        break;
      }
      pMechanism->ulSign = ulSign;
      pMechanism->ulType = lIdx;
      pMechanism->stMask = stMask;
      memcpy( &pMechanism->acArg, pcDomainSpec, cbDomainSpec );
      lnkseqAdd( &lsMechanisms, pMechanism );

    } // while( TRUE )

    // Check for spammer SPF - ALL and all all of previous mechanism have sign
    // PASS
    if ( ulRes == SPF_NONE )
    {
      for( pMechanism = (PMECHANISM)lnkseqGetFirst( &lsMechanisms );
           pMechanism != NULL;
           pMechanism = (PMECHANISM)lnkseqGetNext( pMechanism ) )
      {
        if ( pMechanism->ulSign != SPF_PASS )
          break;

        if ( pMechanism->ulType == _TOKEN_ALL )
        {
          debug( "SPF allows all. It seems that this is a spammer!" );
          ulRes = SPF_FAIL;
          break;
        }
      }
    }

    if ( ulRes != SPF_NONE )
    {
      lnkseqFree( &lsMechanisms, PMECHANISM, hfree );
      return ulRes; 
    }

    pszRedirect = utilStrNewSZ( acbModifiers[_TOKEN_REDIRECT],
                                apcModifiers[_TOKEN_REDIRECT] );
    pszExp = utilStrNewSZ( acbModifiers[_TOKEN_EXP], apcModifiers[_TOKEN_EXP] );
  }

  // Record evaluation.

  {
    struct in_addr     *pInAddr;
    PCHAR              pcPos;

    // If no mechanism or modifier matches, the default result is "Neutral".
    ulRes = SPF_NEUTRAL;

    for( pMechanism = (PMECHANISM)lnkseqGetFirst( &lsMechanisms );
         pMechanism != NULL;
         pMechanism = (PMECHANISM)lnkseqGetNext( pMechanism ) )
    {
      switch( pMechanism->ulType )
      {
        case _TOKEN_ALL:
          // Any "redirect" modifier MUST be ignored when there is an "all"
          // mechanism in the record, regardless of relative ordering of terms.
          // apcModifiers[_TOKEN_REDIRECT] = NULL;
          if ( pszRedirect != NULL )
          {
            hfree( pszRedirect );
            pszRedirect = NULL;
          }

          fMuch = TRUE;
          break;

        case _TOKEN_INCLUDE:
          switch( _checkHost( pData, &pMechanism->acArg ) )
          {
            case SPF_PASS:
              fMuch = TRUE;
              break;

            case SPF_TEMPERROR:
              ulRes = SPF_TEMPERROR;
              break;

            case SPF_PERMERROR:
            case SPF_NONE:
              ulRes = SPF_PERMERROR;
              break;

            // SPF_FAIL, SPF_SOFTFAIL, SPF_NEUTRAL: fMuch = FALSE;
          }
          break;

        case _TOKEN_A:
          if ( pData->cNSReq == 0 )
          {
            ulRes = SPF_PERMERROR;
            break;
          }
          pData->cNSReq--;

          ulRC = dnsRequest( DNSREC_TYPE_A, &pMechanism->acArg,
                             sizeof(pData->acNSRes), &pData->acNSRes, &cNSRes );
          if ( ulRC == DNS_NXDOMAIN )
            break;
          if ( ulRC != DNS_NOERROR )
          {
            ulRC = SPF_TEMPERROR;
            break;
          }

          for( pInAddr = (struct in_addr *)&pData->acNSRes;
               ( cNSRes > 0 ) && !fMuch; cNSRes--, pInAddr++ )
          {
            fMuch = (pInAddr->s_addr & pMechanism->stMask.s_addr) ==
                    (pData->stIP.s_addr & pMechanism->stMask.s_addr);
          }
          break;

        case _TOKEN_MX:
          if ( pData->cNSReq == 0 )
          {
            ulRes = SPF_PERMERROR;
            break;
          }
          pData->cNSReq--;

          ulRC = dnsRequest( DNSREC_TYPE_MX, &pMechanism->acArg,
                             sizeof(pData->acNSRes), &pData->acNSRes, &cNSRes );
          if ( ulRC == DNS_NXDOMAIN )
            break;
          if ( ulRC != DNS_NOERROR )
          {
            ulRC = SPF_TEMPERROR;
            break;
          }

          {
            PCHAR      pcARes = hmalloc( 512 );
            ULONG      cARes;

            for( pcNSRes = &pData->acNSRes; ( cNSRes > 0 ) && !fMuch;
                 cNSRes--, pcNSRes = strchr( &pcNSRes[2], '\0' ) + 1 )
            {
              if ( pData->cNSReq == 0 )
              {
                ulRes = SPF_PERMERROR;
                break;
              }
              pData->cNSReq--;

              ulRC = dnsRequest( DNSREC_TYPE_A, &pcNSRes[2], 512, pcARes, &cARes );
              if ( ulRC == DNS_NXDOMAIN )
                continue;
              if ( ulRC != DNS_NOERROR )
              {
                ulRC = SPF_TEMPERROR;
                break;
              }

              for( pInAddr = (struct in_addr *)pcARes;
                   ( cARes > 0 ) && !fMuch; cARes--, pInAddr++ )
              {
                fMuch = (pInAddr->s_addr & pMechanism->stMask.s_addr) ==
                        (pData->stIP.s_addr & pMechanism->stMask.s_addr);
              }
            }

            hfree( pcARes );
          }
          break;

        case _TOKEN_PTR:
          if ( pData->cNSReq == 0 )
          {
            ulRes = SPF_PERMERROR;
            break;
          }
          ulRC = dnsValidateDomainNames( pData->stIP, &pData->cNSReq,
                                         sizeof(pData->acNSRes),
                                         &pData->acNSRes, &cNSRes );
          if ( ulRC == DNS_NXDOMAIN )
            break;
          if ( ulRC != DNS_NOERROR )
          {
            ulRC = SPF_TEMPERROR;
            break;
          }

          // Check all validated domain names to see if they either match the
          // <target-name> domain or are a subdomain of the <target-name>.
          pcPos = strchr( &pMechanism->acArg, '.' );
          for( pcNSRes = &pData->acNSRes; ( cNSRes > 0 ) && !fMuch;
               cNSRes--, pcNSRes = strchr( pcNSRes, '\0' ) + 1 )
          {
            fMuch = ( stricmp( pcNSRes, &pMechanism->acArg ) == 0 ) ||
                    ( ( pcPos != NULL ) &&
                      ( stricmp( pcNSRes, &pcPos[1] ) == 0 ) );
          }
          break;

        case _TOKEN_IP4:
          fMuch = ((struct in_addr *)&pMechanism->acArg)->s_addr ==
                  (pData->stIP.s_addr & pMechanism->stMask.s_addr);
          break;

        case _TOKEN_IP6:
          break;

        case _TOKEN_EXISTS:
          if ( pData->cNSReq == 0 )
          {
            ulRes = SPF_PERMERROR;
            break;
          }
          pData->cNSReq--;

          ulRC = dnsRequest( DNSREC_TYPE_A, &pMechanism->acArg,
                             sizeof(pData->acNSRes), &pData->acNSRes, &cNSRes );
          if ( ( ulRC != DNS_NOERROR ) && ( ulRC != DNS_NXDOMAIN ) )
            ulRC = SPF_TEMPERROR;
          else
            fMuch = cNSRes != 0;
      } // switch( pMechanism->ulType )

      if ( fMuch || ( ulRes != SPF_NEUTRAL ) )
        break;
    } // for( pMechanism = ...

    if ( fMuch )
      ulRes = pMechanism->ulSign;
  }

  // Process modifiers

  if ( ( !fMuch || ( ulRes == SPF_NEUTRAL ) ) && ( pszRedirect != NULL ) )
  {
    // If all mechanisms fail to match, and a "redirect" modifier is present...

    if ( !_scriptStr( pData, strlen( pszRedirect ), pszRedirect, pszDomain,
                      sizeof(pData->acTargetName), &pData->acTargetName ) )
    {
      debug( "Redirect: _scriptStr() failed" );
      ulRes = SPF_PERMERROR;
    }
    else
    {
      ulRes = _checkHost( pData, pszRedirect );
      if ( ulRes == SPF_NONE )
        ulRes = SPF_PERMERROR;
    }
  }
  else if ( ( ulRes == SPF_FAIL ) && ( pszExp != NULL ) &&
            ( pData->cbExp != 0 ) )
  {
    if ( !_scriptStr( pData, strlen( pszRedirect ), pszExp, pszDomain,
                      sizeof(pData->acTargetName), &pData->acTargetName ) )
    {
      debug( "Exp <domain-spec>: _scriptStr() failed" );
    }
    else if ( pData->cNSReq != 0 )
    {
      pData->cNSReq--;

      ulRC = dnsRequest( DNSREC_TYPE_TXT, pszExp, sizeof(pData->acNSRes),
                         &pData->acNSRes, &cNSRes );
      // If there are any DNS processing errors (any RCODE other than 0), or
      // if no records are returned, or if more than one record is returned,
      // or if there are syntax errors in the explanation string, then proceed
      // as if no "exp" modifier was given.
      if ( cNSRes == 1 )
      {
        PCHAR          pcSenderDomain = strchr( pData->pszSender, '@' );
        LONG           cbExp = 0;

        // Software SHOULD make it clear that the explanation string comes from
        // a third party.
        if ( pcSenderDomain != NULL )
        {
          cbExp = _snprintf( pData->pcExp, pData->cbExp,
                             "The domain %s explains: ", &pcSenderDomain[1] );
          if ( cbExp == -1 )
            cbExp = 0;
        }

        if ( !_scriptStr( pData, strlen( &pData->acNSRes ), &pData->acNSRes,
                        pszDomain, pData->cbExp - cbExp, &pData->pcExp[cbExp] ) )
        {
          debug( "Exp (%s): _scriptStr() failed", &pData->acNSRes );
          pData->pcExp[0] = '\0';
        }
      }
    }
  }

  if ( pszRedirect != NULL )
    hfree( pszRedirect );
  if ( pszExp != NULL )
    hfree( pszExp );

  lnkseqFree( &lsMechanisms, PMECHANISM, hfree );

  return ulRes;
}


ULONG spfCheckHost(struct in_addr stIP, PSZ pszDomain, PSZ pszSender,
                   PSZ pszHELO, ULONG cbExp, PCHAR pcExp)
{
  CHECKDATA            stData;

  stData.stIP = stIP;
  stData.pszSender = pszSender;
  stData.pszHELO = pszHELO;
  stData.cNSReq = 10;
  stData.pcExp = pcExp;
  stData.cbExp = cbExp;
  if ( ( pcExp != NULL ) && ( cbExp != 0 ) )
    *pcExp = '\0';

  if ( pszDomain != NULL )
  {
    if ( !utilVerifyDomainName( strlen( pszDomain ), pszDomain ) )
      return SPF_NONE;
  }
  else
  {
    pszDomain = utilEMailDomain( strlen( pszSender ), pszSender, NULL );
    if ( pszDomain == NULL )
      return SPF_NONE;
  }

  return _checkHost( &stData, pszDomain );
}

/*VOID tt()
{
  ULONG                ulRC;
  struct in_addr       stIP;
  CHAR                 acExp[512];

  stIP.s_addr = inet_addr( "4.233.168.27" );
  ulRC = spfCheckHost( stIP, "gmail.com", "al0n.de0n@gmail.com",
                       "alt4.gmail-smtp-in.l.google.com",
                       sizeof(acExp), &acExp );
  printf( "spfCheckHost(), rc = %u\n", ulRC );
  printf( "Exp: %s\n", &acExp );

  exit( 0 );
}*/
