#ifndef SIGQUEUE_H
#define SIGQUEUE_H

#define SIG_ERROR      ((ULONG)(-1))

BOOL sqInit();
VOID sqDone();
BOOL sqSetTimer(ULONG ulSignal, ULONG ulTimeout);
BOOL sqPost(ULONG ulSignal);
ULONG sqWait();

#endif // SIGQUEUE_H
