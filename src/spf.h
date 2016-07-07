#ifndef SPF_H
#define SPF_H

#include "xpl.h"

// SPF_xxxxx - Check results
#define SPF_NONE       0
#define SPF_NEUTRAL    1
#define SPF_PASS       2
#define SPF_FAIL       3
#define SPF_SOFTFAIL   4
#define SPF_TEMPERROR  5
#define SPF_PERMERROR  6

// apszSPFResult - Check result names (index - spfCheckHost() return code).
#ifndef SPF_C
extern PSZ apszSPFResult[7];
#endif

ULONG spfCheckHost(struct in_addr stIP, PSZ pszDomain, PSZ pszSender,
                   PSZ pszHELO, ULONG cbExp, PCHAR pcExp);

#endif // SPF_H
