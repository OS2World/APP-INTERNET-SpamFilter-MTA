#ifndef CONFIG_H
#define CONFIG_H

#include "rwmutex.h"
#include "util.h"
#include "linkseq.h"

#define MAX_STAGE                4

typedef struct _DNSBL {
  PSZ                  pszName;
    // Name of DNSBL (for ex. zen.spamhaus.org). Max. length is 112.
  LINKSEQ              lsHostListAnswers;
    // DNSBL ret. codes and scores.
} DNSBL, *PDNSBL;

typedef struct _CMDPARAM {
  ULONG                ulTTL;
  LONG                 lScoreLimit;
} CMDPARAM, *PCMDPARAM;

typedef struct _CONFIG {

  PSZ                  pszDataPath;
  PSZ                  pszLogPath;
  ULONG                ulLogLevel;
  ULONG                ulLogSize;
    // Logfiles will be rotated when the size exceeds this value.
    // Files will be renamed every day if zero specified.
  ULONG                ulLogHistory;
    // The maximum number of historic logfiles. If ulLogSize is zero -
    // maximum logged days.

  PSZ                  pszSocket;          // Max. length is 99.
  PSZ                  pszPipe;            // Max. length is 253.
  ULONG                ulPipes;
  ULONG                ulThreads;
  BOOL                 fWeaselLogPipe;     // Read weasel pipe to close sess/s.
  BOOL                 fWeaselLogToScreen; // Output Weasel log to the screen.
  struct in_addr       stNSAddr;           // DNS server address.
  USHORT               usNSPort;           // DNS server port.
  PSZ                  pszMailServerName;
    // Our mail server hostname. Maximum length is 255 characters (+ zero).
  ULONG                cbLocalDomains;
    // Length of string pointed by pcLocalDomains.
  PCHAR                pcLocalDomains;
    // The list of local domains patterns separated by spaces:
    // "domA.net *.domC.net local??.my-domains.net [192.168.1.*] ...".
  PSZ                  pszSpamStore;
    // Spam will be collected when pszSpamStore is not NULL. In this case
    // The string is formatted according to that template.
    // Format keys: %i - session ID, %s - sender mailbox, %S - dender domain,
    // %r - first receiver mailbox, %R - first receiver domain,
    // %d - date YYYYMMDD, %t - HHMMSS.
  BOOL                 fSpamTrapStore;
    // Save (TRUE) spam-trapped messages to pszSpamStore.
  BOOL                 fUpdateHeader;
  BOOL                 fUpdateHeaderLocal;
  LONG                 lStageScoringLimit[MAX_STAGE+1];
  ULONG                ulStageSessTTL[MAX_STAGE+1];
    // Times to live of session after each stage (Seconds, >0).
  CMDPARAM             aCmdParam[8];
  ULONG                ulCommandTimeout;

  // URIBL

  ULONG                cbURIBLProviders;
  PCHAR                pcURIBLProviders;
    // Domain Names of URIBLs to use.
  ULONG                ulURIBLHits;
    // Number of positive replies from providers to apply lScoreURIBLPositive.
  LONG                 lScoreURIBLPositive;
  LONG                 lScoreURIBLNeutral;
    // Will be applied when hits > 0 and < ulURIBLHits
  ULONG                cbURIBLNotSpam;
  PCHAR                pcURIBLNotSpam;
    // Trusted hosts (for ex., our web servers domain names).

  // Command @ACCEPT: Test SMTP client ip-address.

  LINKSEQ              lsHostListRelays;
    // ISP's mail servers or other frendly mail servers that can send mail
    // from the Internet to our server.
  LINKSEQ              lsHostListLocal;
    // Local users addresses.
  ULONG                ulIPFreqMaxAtAcceptNum;
    // Maximum frequency of commands @ACCEPT per IP-address.
  ULONG                ulIPFreqDuration;
    // Maximum frequency of commands @ACCEPT per IP-address duration.
  ULONG                ulIPFreqExpiration;
    // Expiration of maximum frequency.
  LINKSEQ              lsHostListIPFreqIgnore;
    // Clients that should not be tested with maximum frequency.
  LINKSEQ              lsHostListScore;
    // User's scoring of SMTP-clients.
  LONG                 lScoreNoPTR;
    // User defined scores for clients without PTR DNS records.
  ULONG                cbRWLProviders;
  PCHAR                pcRWLProviders;
    // Domain Names of RWLs to use.
  LONG                 alScoreRWL[3];
    // RWL results scoring for levels 1, 2, 3. (<0 or SF_SCORE_NOT_SPAM)
  LINKSEQ              lsHostListRWLIgnore;
    // Clients that should not be checked with RWL.

  // Command EHLO: Test HELO/EHLO host name.

  // Command MAIL: Test MAIL FROM address.

  LINKSEQ              lsHostListMailFrom;
    // User defined scores for MAIL FROM (patterns).
  LINKSEQ              lsHostListEHLO;
    // User defined scores for HELO/EHLO.
  ULONG                ulCheckEHLOOnRWL;
    // Do not check HELO/EHLO when RWL result lower (more reliable) than this
    // value: 1 - for any RWL result (always check HELO/EHLO);
    // 2 - for RWL results 2,3,4; 3 - for RWL result 3 and 4;
    // 4 - for RWL result 4 (do not check HELO/EHLO if clent IP listed in RWL).
  LONG                 lScoreInvalidEHLO;    // (>0)
  LINKSEQ              lsHostListEHLOURIBLIgnore;

  // Command DATA: Test the list of recipients.

  ULONG                ulTTLAutoWhiteListed;         // Seconds, >=0.
    // Time to live for white listed addresses (Where to sending local users).
    // Address will be not listed if 0 specified (but this makes no sense IMHO).
  ULONG                cbAutoWhitelistIgnoreSenders;
  PCHAR                pcAutoWhitelistIgnoreSenders;
    //
  ULONG                cbSpamTrap;
  PCHAR                pcSpamTrap;
    // The list of local "spam traps" addresses separated by spaces. "Spam
    // traps" will not be used when NULL specified.
  LONG                 lScoreSpamTrapClient;
    // Increment client IP-address score in the internal ip list. This list
    // will be used on stage 0. IP-address will not be listed if 0 specified.
  ULONG                ulSpamTrapClientTTL;   // Seconds, >=0.
    // Time to live client IP-address in internal ip list.
    // IP-address will not be listed if 0 specified.
  LONG                 lScoreExtClntLocSndrLocRcpt;
    // Score: Local sender and local recepient but sender connected not from
    // the local network.
  ULONG                ulCheckMailFromOnRWL;
    // Do not check MAIL FROM (DNSBL, URIBL, mail box, SPF, Graylist) when RWL
    // result lower (more reliable) than this value:
    // 1 - for any RWL result (always check MAIL FROM);
    // 2 - for RWL results 2,3,4; 3 - for RWL result 3 and 4;
    // 4 - for RWL result 4 (do not check MAIL FROM if clent IP listed in RWL).
  ULONG                ulGreylistTTL;
    // Time to live for greylist records,
  struct in_addr       stGreylistMask;
    // The mask is applied to addresses coming into the gray list. Some mail
    // services may have multiple servers on the same subnet and the attempt to
    // deliver delayed message can be carried from another address in some net.
  ULONG                ulGreylistCfNum;
    // Coefficient numerator. The greylist will not be used when current
    // numerator for IP > this value.
  ULONG                ulGreylistCfDen;
    // Coefficient denominator (>= 10).
  ULONG                ulGreylistCfTTL;
    // Time to live for greylist unused coefficient records,
  ULONG                cbGreylistIgnoreSenders;
  PCHAR                pcGreylistIgnoreSenders;
    // Do not delay mail from this senders.
  LINKSEQ              lsHostListGreylistIgnore;
    // IP addresses that you don't want to be delayed.
  ULONG                cDNSBL;
  PDNSBL               paDNSBL;
    // List of DNSBL services. Field pszName of last record should be NULL.
  ULONG                ulDNSBLMaxHits;
    // DNSBL systems max. hits.
  LINKSEQ              lsHostListDNSBLIgnore;
    // Client IPs that should not be checked with DNSBL.
  LINKSEQ              lsHostListMailFromURIBLIgnore;
  BOOL                 fMailBoxCheck;
  LONG                 alScoreMailBoxCheck[10];
    // Size of this array must be same as mboxchk.c -> apszMBCResult[]
  ULONG                cbMailBoxCheckIgnoreSenders;
  PCHAR                pcMailBoxCheckIgnoreSenders;
  LINKSEQ              lsMailBoxCheckIgnore;
  LONG                 alScoreSPF[7];      // Scores for each SPF result code.
  LINKSEQ              lsHostListSPFIgnore;

  // @CONTENT: Test message body

  LONG                 lScoreSuspiciousMsgId;
    // Score for suspicious values of the header fields "Message-ID:"
  LINKSEQ              lsHostListMsgId;
    // User defined scores for "Message-ID:" (patterns, not host names).
  LINKSEQ              lsHostListMsgIdIgnore;
  ULONG                ulCheckMsgBodyOnRWL;
    // Do not check message body when RWL result lower than this value.
  ULONG                ulMaxMessage;
    // How many bytes of message will be tested.
  ULONG                ulMaxBodyPart;
    // How many bytes of each(!) body's part of message will be tested.
  ULONG                ulSpamURIHostTTL;
    // Time to live for host addresses from spam links.
  LONG                 lScoreSpamURIHost;
    // SF_SCORE_SPAM / value > 0
  // ++ Host names listed at pcURIBLNotSpam will be not collected.

} CONFIG, *PCONFIG;

#ifndef CONFIG_C
extern PCONFIG         pConfig;
#endif

BOOL cfgInit();
VOID cfgDone();
BOOL cfgReconfigure();

// Modules must locks code blocks by cfgReadLock() / cfgReadUnlock() to read
// configuration datas.
BOOL cfgReadLock();
VOID cfgReadUnlock();

BOOL cfgHostListAdd(PLINKSEQ plsList, LONG lScore, ULONG cbHost, PCHAR pcHost);
BOOL cfgHostListCheck(PLINKSEQ plsList, struct in_addr stInAddr,
                      ULONG cbName, PCHAR pcName, PLONG plScore);
BOOL cfgHostListCheckIP(PLINKSEQ plsList, struct in_addr stInAddr,
                        PLONG plScore);
BOOL cfgHostListCheckName(PLINKSEQ plsList, ULONG cbHost, PCHAR pcHost,
                          PLONG plScore);

BOOL cfgIsMatchPtrnList(ULONG cbPtrnList, PCHAR pcPtrnList,
                        ULONG cbWord, PCHAR pcWord);
BOOL cfgIsLocalEMailDomain(ULONG cbDomain, PCHAR pcDomain);

#endif // CONFIG_H
