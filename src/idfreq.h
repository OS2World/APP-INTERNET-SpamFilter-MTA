#ifndef IDFREQ_H
#define IDFREQ_H

typedef struct _IDREC *PIDREC;

typedef struct _IDFREQ {
  ULONG      ulTimeWindow;
  ULONG      ulActivLimit;
  PIDREC     paList;
  ULONG      cList;
  ULONG      ulListMax;
  HMTX       hmtxList;
} IDFREQ, *PIDFREQ;

BOOL idfrInit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit);
VOID idfrDone(PIDFREQ pIDFreq);
BOOL idfrActivation(PIDFREQ pIDFreq, ULONG ulId, BOOL fRemoveOnLimit);
VOID idfrClean(PIDFREQ pIDFreq);
BOOL idfrSetLimit(PIDFREQ pIDFreq, ULONG ulTimeWindow, ULONG ulActivLimit);

#endif // IDFREQ_H
