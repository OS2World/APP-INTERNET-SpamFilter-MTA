#ifndef UTIL_H
#define UTIL_H

#include <ctype.h> 
#include "xpl.h"

VOID setFlag0(PULONG flag);
#pragma aux setFlag0 = "lock or     dword ptr [eax],1" parm [eax]

// ULONG lockFlag0(PULONG flag)
//
// It sets the flag if it is not set and returns not zero. It returns zero if
// flag already been set.

ULONG lockFlag0(PULONG flag);
#pragma aux lockFlag0 = \
  "lock bts     dword ptr [eax],0"\
  "     jnc     @@RET            "\
  "     xor	eax,eax		 "\
  "   @@RET:                     "\
  parm [eax] value [eax];

// ULONG waitFlag0(PULONG flag)
//
// Waiting when the flag will be zero and set it. Returns 0 on success or other
// value on error (interruped).

// DosSleep() - What about Windows?
ULONG waitFlag0(PULONG flag);
#pragma aux waitFlag0 = \
  "     xor     eax, eax          "\
  "   @@LOCK:                     "\
  "lock bts     dword ptr [ebx], 0"\
  "     jnc     @@RET             "\
  "     push    1                 "\
  "     call    DosSleep          "\
  "     add     esp, 4            "\
  "     test    eax, eax          "\
  "     jz      @@LOCK            "\
  "   @@RET:                      "\
  parm [ebx] value [eax] modify [ecx];

VOID clearFlag0(PULONG flag);
#pragma aux clearFlag0 = \
  "lock and [eax],0xFFFFFFFE"\
  parm [eax]; 

// ULONG testFlag0(PULONG flag)
//
// It test the flag. It returns non zero if flag is set.

ULONG testFlag0(PULONG flag);
#pragma aux testFlag0 = \
  "  bt      dword ptr [eax],0"\
  "  jc      @@RET            "\
  "  xor     eax,eax          "\
  "@@RET:                     "\
  parm [eax] value [eax];

VOID setFlag1(PULONG flag);
#pragma aux setFlag1 = "lock or     dword ptr [eax],2" parm [eax]

ULONG lockFlag1(PULONG flag);
#pragma aux lockFlag1 = \
  "lock bts     dword ptr [eax],1"\
  "     jnc     @@RET            "\
  "     xor	eax,eax		 "\
  "   @@RET:                     "\
  parm [eax] value [eax];

ULONG waitFlag1(PULONG flag);
#pragma aux waitFlag1 = \
  "     xor     eax, eax          "\
  "   @@LOCK:                     "\
  "lock bts     dword ptr [ebx], 1"\
  "     jnc     @@RET             "\
  "     push    1                 "\
  "     call    DosSleep          "\
  "     add     esp, 4            "\
  "     test    eax, eax          "\
  "     jz      @@LOCK            "\
  "   @@RET:                      "\
  parm [ebx] value [eax] modify [ecx];

VOID clearFlag1(PULONG flag);
#pragma aux clearFlag1 = \
  "lock and [eax],0xFFFFFFFD"\
  parm [eax]; 

ULONG testFlag1(PULONG flag);
#pragma aux testFlag1 = \
  "  bt      dword ptr [eax],1"\
  "  jc      @@RET            "\
  "  xor     eax,eax          "\
  "@@RET:                     "\
  parm [eax] value [eax];



#define BUF_SKIP_SPACES(cb, pc) \
  while( (cb > 0) && isspace( *pc ) ) { cb--; pc++; }
#define BUF_MOVE_TO_SPACE(cb, pc) \
  while( (cb > 0) && !isspace( *pc ) ) { cb--; pc++; }
#define BUF_SKIP_DELIM(cb,pc,d) \
  while( (cb > 0) && ( (*pc == d ) || isspace(*pc) ) ) { cb--; pc++; }
#define BUF_RTRIM(cb, pc) \
  while( (cb > 0) && ( isspace( pc[cb - 1] ) ) ) cb--
#define BUF_ENDS_WITH(cb, pc, cbend, pcend) \
  ( ( (cb) >= (cbend) ) && ( memcmp( (pc)-(cbend), pcend, cbend ) == 0 ) )
#define BUF_I_ENDS_WITH(cb, pc, cbend, pcend) \
  ( ( (cb) >= (cbend) ) && ( memicmp( (&((pc)[cb]))-(cbend), pcend, cbend ) == 0 ) )

#define STR_SAFE(p) ( (p) == NULL ? "" : (p) )
#define STR_LEN(p) ( (p) == NULL ? 0 : strlen( p ) )
#define STR_ICMP(s1,s2) stricmp( STR_SAFE(s1), STR_SAFE(s2) )
#define STR_COPY(d,s) strcpy( d, STR_SAFE(s) )

#define STR_SKIP_SPACES(p) do { while( isspace( *p ) ) p++; } while( 0 )
#define STR_RTRIM(p) do { PSZ __p = strchr( p, '\0' ); \
  while( (__p > p) && isspace( *(__p - 1) ) ) __p--; \
  *__p = '\0'; \
} while( 0 )
#define STR_MOVE_TO_SPACE(p) \
  do { while( (*p != '\0') && !isspace( *p ) ) p++; } while( 0 )
#define STR_SKIP_DELIM(p,d) while( ( *p == d ) || isspace(*p) ) p++
// BUF_STR_IEQ() and BUF_STR_IEQ() returns TRUE or FALSE
#define BUF_STR_EQ(cb, pc, s) ((cb == strlen(s)) && (memcmp(pc,s,cb) == 0))
#define BUF_STR_IEQ(cb, pc, s) ((cb == strlen(s)) && (memicmp(pc,s,cb) == 0))

#define ARRAY_SIZE(a) ( sizeof(a) / sizeof(a[0]) )

// utilStrFindParts(,,,,PUTILSTRPART)
typedef struct _UTILSTRPART {
  ULONG      cbPart;
  PCHAR      pcPart;
} UTILSTRPART, *PUTILSTRPART;

// utilIPList*()
/*
typedef struct _UTILIPLISTREC {
  ULONG                ulFirstAddr;        // IP-address.
  ULONG                ulLastAddr;         // IP-address.
  ULONG                ulUser;             // User value.
} UTILIPLISTREC, *PUTILIPLISTREC;

typedef struct _UTILIPLIST {
  ULONG                ulCount;
  PUTILIPLISTREC       paList;
} UTILIPLIST, *PUTILIPLIST;
*/

ULONG utilStrWordsCount(ULONG cbText, PCHAR pcText);
BOOL utilStrCutWord(PULONG pcbText, PCHAR *ppcText,
                    PULONG pcbWord, PCHAR *ppcWord);
LONG utilStrWordIndex(PSZ pszList, ULONG cbWord, PCHAR pcWord);
BOOL utilStrAddWords(PULONG pcbText, PCHAR *ppcText,
                     ULONG cbWords, PCHAR pcWords,
                     ULONG (*fnFilter)(ULONG cbWord, PCHAR pcWord) );
BOOL utilStrAppend(PULONG pcbText, PCHAR *ppcText, ULONG cbStr, PCHAR pcStr,
                   BOOL fFullStr);
PCHAR utilStrFindKey(ULONG cbText, PCHAR pcText, ULONG cbKey, PCHAR pcKey,
                     PULONG pcbVal);
PSZ utilStrNewUnescapeQuotes(ULONG cbText, PCHAR pcText, BOOL fIfQuoted);
PCHAR utilStrFindOption(ULONG cbText, PCHAR pcText,
                        ULONG cbName, PCHAR pcName, PULONG pcbVal);
PSZ utilStrNewGetOption(ULONG cbText, PCHAR pcText, PSZ pszName);
BOOL utilStrToULong(ULONG cbStr, PCHAR pcStr, ULONG ulMin, ULONG ulMax,
                    PULONG pulValue);
BOOL utilStrToLong(ULONG cbStr, PCHAR pcStr, LONG lMin, LONG lMax,
                   PLONG plValue);
BOOL utilStrSplitWords(ULONG cbStr, PCHAR pcStr, PULONG pulWords,
                      PUTILSTRPART pWords);
BOOL utilStrFindParts(ULONG cbStr, PCHAR pcStr, PSZ pszDelimiter,
                      PULONG pulParts, PUTILSTRPART pParts);
BOOL utilStrBuildParts(ULONG cbStr, PCHAR pcStr, PSZ pszDelimiter,
                       ULONG ulParts, BOOL fRev, CHAR cNewDelim,
                       PULONG pcbBuf, PCHAR pcBuf);
ULONG utilStrFindURIHosts(ULONG cbText, PCHAR pcText,
                          BOOL (*fnFound)(ULONG cbAddr, PCHAR pcAddr, PVOID pData),
                          PVOID pData);
PSZ utilStrNewSZ(ULONG cbStr, PCHAR pcStr);
PCHAR utilStrLastChar(ULONG cbText, PCHAR pcText, CHAR chSearch);
BOOL utilStrToInAddr(ULONG cbStr, PCHAR pcStr, struct in_addr *pInAddr);
BOOL utilStrToMask(ULONG cbStr, PCHAR pcStr, struct in_addr *pInAddr);
BOOL utilStrToInAddrRange(ULONG cbStr, PCHAR pcStr, struct in_addr *pInAddr1,
                          struct in_addr *pInAddr2);
BOOL utilStrToInAddrPort(ULONG cbStr, PCHAR pcStr, struct in_addr *pInAddr,
                         PUSHORT pusPort, BOOL fAnyIP, USHORT usDefaultPort);
BOOL utilStrTimeToSec(ULONG cbStr, PCHAR pcStr, PULONG pulSec);
LONG utilSecToStrTime(ULONG ulSec, ULONG cbStr, PCHAR pcStr);
BOOL utilStrToBytes(ULONG cbStr, PCHAR pcStr, PULONG pulSec);
LONG utilStrFormat(ULONG cbBuf, PCHAR pcBuf, PSZ pszFormat,
                   ULONG (*fnValue)(CHAR chKey, ULONG cbBuf, PCHAR pcBuf,
                                    PVOID pData),
                   PVOID pData);

/*
#define utilIPListFree(pIPList) \
   if ( (pIPList)->paList != NULL ) debugFree( (pIPList)->paList )
BOOL utilIPListAddStr(PUTILIPLIST pIPList, ULONG cbList,
                      PCHAR pcList, ULONG ulUser);
BOOL utilIPListCheck(PUTILIPLIST pIPList, struct in_addr stInAddr,
                     PULONG pulUser);
*/

BOOL utilMakePathToFile(ULONG cbFName, PCHAR pcFName);
BOOL utilPathExists(ULONG cbName, PCHAR pcName, BOOL fFile);
LONG utilSetExtension(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile, PSZ pszExt);

BOOL utilCIDRLenToInAddr(ULONG ulCIDRLen, struct in_addr *pInAddr);
BOOL utilVerifyDomainName(ULONG cbDomain, PCHAR pcDomain);
PCHAR utilEMailDomain(ULONG cbAddr, PCHAR pcAddr, PULONG pcbDomain);
BOOL utilIsMatch(ULONG cbStr, PCHAR pcStr, ULONG cbPtrn, PCHAR pcPtrn);
BOOL utilBSearch(const void *pKey, PVOID pBase, ULONG ulNum, ULONG cbWidth,
                 int (*fnComp)(const void *pkey, const void *pbase),
                 PULONG pulIndex);

#endif // UTIL_H
