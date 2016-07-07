#ifndef DATAFILE_H
#define DATAFILE_H

BOOL dfInit();
VOID dfDone();
LONG dfBackupGetName(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile, PSZ pszBakupExt);
FILE *dfBackupOpenFile(PSZ pszFile, PSZ pszBakupExt);
LONG dfSetUniqueExtension(ULONG cbBuf, PCHAR pcBuf, PSZ pszFile);
BOOL dfBackupFileReplace(PSZ pszDest, PSZ pszSrc, PSZ pszBakupExt,
                         BOOL fPostpondAllowed);
ULONG dfExecPostpond(BOOL fRemoveAll);

#endif // DATAFILE_H

