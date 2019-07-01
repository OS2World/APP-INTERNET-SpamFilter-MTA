#ifndef SIGQUEUE_H
#define SIGQUEUE_H

#define EV_ERROR                 ((ULONG)(-1))
#define EV_NO_EVENT              ((ULONG)(-2))
#define EV_SHUTDOWN              0
#define EV_RECONFIGURE           1
#define EV_CLEANING              2
#define EV_LISTS_STORE           3
#define EV_PIPE                  4
#define EV_POSTPONDED_BACKUP     5

BOOL evInit();
VOID evDone();
BOOL evPost(ULONG ulEvent);
ULONG evWait(ULONG ulTimeout);
HEV evGetEvSemHandle(ULONG ulEvent);

#endif // SIGQUEUE_H
