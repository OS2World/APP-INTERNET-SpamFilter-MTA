#ifndef MBOXCHK_H
#define MBOXCHK_H

#define MBC_OK                    0 // Mailbox exists
#define MBC_DONE_NOT_EXIST        1
#define MBC_DONE_NO_POSTMASTER    2
#define MBC_DONE_FAKE_CHECK       3
#define MBC_FAIL                  4
#define MBC_CONN_FAIL             5
#define MBC_CONN_TIMEOUT          6
#define MBC_CONN_REFUSED          7
#define MBC_NETUNREACH            8
#define MBC_NOBUFS                9

// apszMBCResult - Check result names (index - MailBoxCheck() return code).
#ifndef MBOXCHK_C
extern PSZ apszMBCResult[10];
#endif

ULONG MailBoxCheck(struct in_addr stServer, PSZ pszMailAddr);

#endif // MBOXCHK_H
