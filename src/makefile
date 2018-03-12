#
# OpenWatcom makefile.
#

BINPATH = ..\sf
LIBPATH = .\lib
EXENAME = sf
VERSION = 1.1.3
AUTOR = Andrey Vasilkin
COMMENT = SpamFilter for OS/2 and eComStation
#DEBUG = 1

EXEFILE = $(BINPATH)\$(EXENAME).exe

CFLAGS = -i=.;$(%WATCOM)\H\OS2;$(%WATCOM)\H;.\h -bt=os2 -q -d0 -w2

SRCS = requests.c util.c dns.c config.c sessions.c log.c sockets.c &
       spf.c addrlist.c greylist.c rwmutex.c sigqueue.c mboxchk.c msgfile.c &
       mcodec.c stat.c xmlutil.c ifsock.c ifpipe.c datafile.c sf.c &
       weasel.c idfreq.c

!ifdef DEBUG
CFLAGS += -DDEBUG_FILE="$(EXENAME).dbg"
SRCS += debug.c
COMMENT = $(COMMENT) (debug version)
!endif

OBJS = $(SRCS:.c=.obj)

LIBS = os2iconv libuls libconv libxml2 zlib
# LIBS = libxml2.lib zlib.lib os2iconv.lib libcmi.lib libconv.lib

.extensions:
.extensions: .lib .dll .obj .c

$(EXEFILE): infCompiling $(OBJS) $(EXENAME).lnk
  @echo * Link: $@
  @wlink @$(EXENAME).lnk

$(EXENAME).lnk: .ALWAYS
  @%create $@
  @%append $@ SYSTEM os2v2
  @%append $@ NAME $(EXEFILE)
  @%append $@ OPTION QUIET
  @%append $@ OPTION OSNAME='OS/2 and eComStation'
  @%append $@ OPTION ELIMINATE
  @%append $@ LIBPATH $(LIBPATH)
  @for %i in ($(LIBS)) do @%append $@ LIB %i
  @for %i in ($(OBJS)) do @%append $@ FILE %i
!ifdef %osdir
  @$(%osdir)\KLIBC\BIN\date +"OPTION DESCRIPTION '@$#$(AUTOR):$(VERSION)$#@$#$#1$#$# %F %T      $(%HOSTNAME)::ru:RUS:::@@$(COMMENT)'" >>$^@
!else
  @%append $@ OPTION DESCRIPTION '@$#$(AUTOR):$(VERSION)$#@$#$#1$#$#                          $(%HOSTNAME)::ru:RUS:0::@@$(COMMENT)'
!endif

.c.obj:
  wcc386 $(CFLAGS) $<

infCompiling: .SYMBOLIC
  @echo * Compiling: $(COMMENT) $(VERSION) ...

clean: .SYMBOLIC
  @echo * Clean: $(EXENAME)
  @if exist *.obj @del *.obj
  @if exist *.err @del *.err
  @if exist *.err @del *.err
  @if exist $(EXENAME).lnk @del $(EXENAME).lnk
  @if exist $(EXEFILE) @del $(EXEFILE)
  @if exist $(BINPATH)\$(EXENAME).dbg @del $(BINPATH)\$(EXENAME).dbg
