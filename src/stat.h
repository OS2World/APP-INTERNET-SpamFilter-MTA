#ifndef STAT_H
#define STAT_H 1

#define STAT_SESSIONS            0
#define STAT_SPAM                1
#define STAT_NOT_SPAM            2
#define STAT_DELAYED             3
#define STAT_SESS_TIMEDOUT       4
#define STAT_SPAM_TRAP           5
#define STAT_IP_FREQ_LIMIT       6
#define STAT_SPAM_URIHOSTS_FOUND 7
#define STAT_COMMAND_TIMEOUT     8
#define STAT_AUTHFAIL_BLOCK      9

BOOL statInit();
VOID statDone();
BOOL statSaveChanges();
VOID statChange(ULONG ulItem, LONG lValue);

#endif // STAT_H
