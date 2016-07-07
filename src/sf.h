#define SF_SCORE_NONE            0
#define SF_SCORE_SPAM            0x80000000
#define SF_SCORE_NOT_SPAM        0xC0000000

#define SF_MAX_SESS_ID_LENGTH    16

#define SIG_CLEANING             1000
#define SIG_LISTS_STORE          1001
#define SIG_SHUTDOWN             1002
#define SIG_RECONFIGURE          1003
#define SIG_POSTPONDED_BACKUP    1004
