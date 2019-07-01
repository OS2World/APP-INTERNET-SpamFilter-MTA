#ifndef HMEM_H
#define HMEM_H

#ifndef IS_HIGH_PTR
#define IS_HIGH_PTR(p)   ((unsigned long int)(p) >= (512*1024*1024))
#endif

#ifdef __WATCOMC__
#include "hmem_wraps.h"
#endif

void *hmalloc(size_t ulSize);
void hfree(void *pPointer);
void *hrealloc(void *pPointer, size_t ulSize);
char *hstrdup(char *pcStr);
void *hcalloc(size_t ulN, size_t ulSize);

#endif // HMEM_H
