#ifndef DNS_H
#define DNS_H

#include <netinet\in.h>

// Return codes for dnsRequest()

// RCODE
#define DNS_NOERROR               0     // No Error
#define DNS_FORMERR               1     // Format Error, RFC1035
#define DNS_SERVFAIL              2     // Server Failure, RFC1035
#define DNS_NXDOMAIN              3     // Non-Existent Domain, RFC1035
#define DNS_NOTIMP                4     // Not Implemented, RFC1035
#define DNS_REFUSED               5     // Query Refused, RFC1035
#define DNS_YXDOMAIN              6     // Name Exists when it should not, RFC2136, RFC6672
#define DNS_YXRRSET               7     // RR Set Exists when it should not, RFC2136
#define DNS_NXRRSET               8     // RR Set that should exist does not, RFC2136
#define DNS_NOTAUTH               9     // Not Authorized, RFC2845
#define DNS_NOTZONE              10     // Name not contained in zone, RFC2136
//                               11-15 Unassigned
#define DNS_BADVERS              16     // Bad OPT Version, RFC6891
#define DNS_BADSIG               16     // TSIG Signature Failure, RFC2845
#define DNS_BADKEY               17     // Key not recognized, RFC2845
#define DNS_BADTIME              18     // Signature out of time window, RFC2845
#define DNS_BADMODE              19     // Bad TKEY Mode, RFC2930
#define DNS_BADNAME              20     // Duplicate key name, RFC2930
#define DNS_BADALG               21     // Algorithm not supported, RFC2930
#define DNS_BADTRUNC             22     // Bad Truncation, RFC4635
//                               23-3840 Unassigned
// Private DNS module codes (3841-4095 Reserved for Private Use).
#define DNS_INVALID_NAME         3841
#define DNS_SEND_FAILED          3842
#define DNS_RECV_FAILED          3843
#define DNS_INVALID_FORMAT       3844   // Invalid DNS packet received
#define DNS_UNREQ_ANSWER_TYPE    3845
#define DNS_OVERFLOW             3846
#define DNS_TIMEOUT              3847
#define DNS_CANCEL               3848

#define DNSREC_TYPE_A           0x0100   // Ipv4 address.
#define DNSREC_TYPE_NS          0x0200   // Name server.
#define DNSREC_TYPE_CNAME       0x0500   // Canonical name.
#define DNSREC_TYPE_SOA         0x0600   // Start of authority zone.
#define DNSREC_TYPE_PTR         0x0C00   // Domain name pointer.
#define DNSREC_TYPE_MX          0x0F00   // Mail server.
#define DNSREC_TYPE_TXT         0x1000

BOOL dnsInit();
VOID dnsDone();
BOOL dnsSetServer(struct in_addr *pAddr, USHORT usPort);
ULONG dnsRequest(USHORT usType, PSZ pszName, ULONG cbBuf, PCHAR pcBuf,
                 PULONG pulItems);
ULONG dnsPTRRequest(struct in_addr stInAddr, ULONG cbBuf, PCHAR pcBuf,
                    PULONG pulItems);
ULONG dnsValidateDomainNames(struct in_addr stIP, PULONG pulMaxReq, ULONG cbBuf,
                             PCHAR pcBuf, PULONG pulItems);
ULONG dnsGetCacheCount();
#endif // DNS_H
