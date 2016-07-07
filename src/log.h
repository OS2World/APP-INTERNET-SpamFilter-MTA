#ifndef LOG_H
#define LOG_H

#include <stdio.h> 
#include "xpl.h"
#include "config.h"

#define IF_LOGLEVEL(level) if ( pConfig->ulLogLevel >= level ) do {
#define ENDIF_LOGLEVEL } while( FALSE );
#define BREAK_LOGLEVEL break;

#define log(level,fmt,...) do { \
  if ( pConfig->ulLogLevel >= level ) logWrite( (fmt), ##__VA_ARGS__ ); \
} while( FALSE )

BOOL logInit();
VOID logDone();
BOOL logReOpen();
VOID logWrite(PSZ pszFormat, ...);
PSZ  logBufToPSZ(ULONG cbBuf, PCHAR pcBuf);

#endif // LOG_H
