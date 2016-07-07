#ifndef XPL_H
#define XPL_H

#include <process.h>

#ifdef __OS2__

#include <types.h>
#include <arpa\inet.h>
#include <netdb.h>
#include <sys\socket.h>
#include <sys\time.h>
#include <sys\ioctl.h>
#include <sys\un.h>
#include <net\route.h>
#include <net\if.h>
#include <net\if_arp.h>
#include <nerrno.h>
#include <unistd.h>
#define INCL_DOSSEMAPHORES
#define INCL_DOSQUEUES
#define INCL_DOSPROCESS
#define INCL_DOSMISC
#define INCL_DOSERRORS
#define INCL_DOSMODULEMGR
#define INCL_DOSEXCEPTIONS
#include <os2.h>

#define XPL_INDEFINITE_WAIT		SEM_INDEFINITE_WAIT

#define XPL_NO_ERROR			NO_ERROR
#define XPL_ERROR_TIMEOUT		ERROR_TIMEOUT
#define XPL_ERROR_OWNER_DIED		ERROR_SEM_OWNER_DIED

#define XPLTHREADFN			void FAR
#define XPLTHREADDATA			void FAR

typedef int HSOCKET, *PHSOCKET;
typedef long long LLONG, *PLLONG;
typedef unsigned long long ULLONG, *PULLONG;

#define xplInit() sock_init()
#define xplDone()
// xplMutexCreate(phMtx) : *phMtx == NULLHANDLE on error.
#define xplMutexCreate(phMtx,fLocked) \
  if ( DosCreateMutexSem( NULL, phMtx, 0, fLocked ) != NO_ERROR ) *(phMtx) = NULLHANDLE
#define xplMutexDestroy(hMtx) DosCloseMutexSem( hMtx )
#define xplMutexLock(hMtx, ulTimeout) DosRequestMutexSem( hMtx, ulTimeout )
#define xplMutexUnlock(hMtx) DosReleaseMutexSem( hMtx )
// xplEventCreate() : *phEv == NULLHANDLE on error
#define XPL_EV_MANUAL_RESET      0
#define XPL_EV_AUTO_RESET        DCE_POSTONE
#define xplEventCreate(phEv,xplEvReset,fPosted) \
  if ( DosCreateEventSem( NULL, phEv, xplEvReset, fPosted ) != NO_ERROR ) *(phEv) = NULLHANDLE
#define xplEventDestroy(hEv) DosCloseEventSem( hEv )
#define xplEventPost(hEv) DosPostEventSem( hEv )
#define XPL_EV_SIGNAL  NO_ERROR // Return code of xplEventWait().
#define xplEventWait(hEv, ulTimeout) DosWaitEventSem( hEv, ulTimeout )
#define xplEventReset(hEv) do { \
  ULONG		_xpl_ulCount; \
  DosResetEventSem( hEv, &_xpl_ulCount ); \
} while( FALSE)
#define xplTime(pulTime) DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, pulTime, sizeof(ULONG) )
#define xplSleep(ulTime) DosSleep( ulTime )

#define XPL_THREAD_START_FAIL (-1)
#define xplThreadStart(fnThread,pData) _beginthread( fnThread, NULL, 65536, pData )
#define xplThreadEnd() _endthread()
#define xplThreadId(phThread) do { \
  PTIB		_xpl_ptib; \
  PPIB		_xpl_ppib; \
  *(phThread) = DosGetInfoBlocks( &_xpl_ptib, &_xpl_ppib ) != NO_ERROR ? \
    0 : _xpl_ptib->tib_ptib2->tib2_ultid; \
} while( FALSE )
#define xplSockClose(hSocket) soclose( hSocket )
#define xplSockPError(pszFunc) psock_errno( pszFunc )
#define xplSockError() sock_errno()
#define xplSockIOCtl(hSocket,iCmd,pData) ioctl( hSocket, iCmd, (PCHAR)pData )

#define XPL_COPYFILE_OK			NO_ERROR
#define xplCopyFile(pszOld, pszNew, fOverwrite) DosCopy(pszOld, pszNew, fOverwrite ? DCPY_EXISTING : 0)

#else // -------------------------------------------------------------

#include <windows.h>
#include <unistd.h>

#define SOCENOTSOCK			WSAENOTSOCK
#define SOCEWOULDBLOCK			WSAEWOULDBLOCK
#define SOCEINPROGRESS			WSAEWOULDBLOCK
#define SOCEINTR			WSAEINTR
#define SOCECONNREFUSED			WSAECONNREFUSED
#define SOCENETUNREACH			WSAENETUNREACH
#define SOCENOBUFS			WSAENOBUFS
#define SOCETIMEDOUT			WSAETIMEDOUT
#define sock_errno()			WSAGetLastError()

#define XPL_INDEFINITE_WAIT		INFINITE

#define XPL_NO_ERROR			WAIT_OBJECT_0
#define XPL_ERROR_TIMEOUT		WAIT_TIMEOUT
#define XPL_ERROR_OWNER_DIED		WAIT_ABANDONED

#define XPLTHREADFN			void
#define XPLTHREADDATA			void

#define NULLHANDLE			NULL

typedef HANDLE HMTX, *PHMTX, HEV, *PHEV;
typedef SOCKET HSOCKET, *PHSOCKET;
typedef PVOID *PPVOID;

#define xplInit() do { \
  WSADATA	_xpl_wsad; \
  WSAStartup( 0x0202, &_xpl_wsad ); \
} while( FALSE )
#define xplDone() WSACleanup()
// xplMutexCreate(phMtx) : *phMtx is NULLHANDLE on error.
#define xplMutexCreate(phMtx,fLocked) *(phMtx) = CreateMutex( NULL, fLocked, NULL )
#define xplMutexDestroy(hMtx) CloseHandle( hMtx )
#define xplMutexLock(hMtx,ulTimeout) WaitForSingleObject( hMtx, ulTimeout )
#define xplMutexUnlock(hMtx) ReleaseMutex( hMtx )
// xplEventCreate() : *phEv == 0 on error
#define XPL_EV_MANUAL_RESET      TRUE
#define XPL_EV_AUTO_RESET        FALSE
#define xplEventCreate(phEv,xplEvReset,fPosted) \
  *(phEv) = CreateEvent( NULL, xplEvReset, fPosted, NULL )
#define xplEventDestroy(hEv) CloseHandle( hEv )
#define xplEventPost(hEv) SetEvent( hEv )
#define XPL_EV_SIGNAL  WAIT_OBJECT_0 // Return code of xplEventWait().
#define xplEventWait(hEv, ulTimeout) WaitForSingleObject( hEv, ulTimeout )
#define xplEventReset(hEv) ResetEvent( hEv )
#define xplTime(pulTime) *(pulTime) = GetTickCount()
#define xplSleep(ulTime) Sleep( ulTime )

#define XPL_THREAD_START_FAIL ((unsigned long)(-1))
#define xplThreadStart(fnThread,pData) _beginthread( fnThread, 65536, pData )
#define xplThreadEnd() _endthread()
#define xplThreadId(phThread) *(phThread) = GetCurrentThread()

#define xplSockClose(hSocket) closesocket( hSocket )
#define xplSockPError(pszFunc) printf( "winsock error: %u\n", WSAGetLastError() )
#define xplSockError() WSAGetLastError()
#define xplSockIOCtl(hSocket,iCmd,pData) ioctlsocket( hSocket, iCmd, (PULONG)pData )

#define XPL_COPYFILE_OK			TRUE
#define xplCopyFile(pszOld, pszNew, fOverwrite) CopyFile(pszOld, pszNew, TRUE, !fOwerride)

#endif


#endif // XPL_H
