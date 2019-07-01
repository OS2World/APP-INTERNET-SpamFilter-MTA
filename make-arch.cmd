@echo off
call clean.cmd

rem Under eCS we can get curent date for archive file name.

if exist %osdir%\KLIBC\BIN\date.exe goto ecsdate
set archdate=""
goto enddate
:ecsdate
%osdir%\KLIBC\BIN\date +"set archdate=-%%Y%%m%%d" >archdate.cmd
call archdate.cmd
del archdate.cmd
:enddate

rem Make archives of sources and binaries.

rem First archive - sources.
set fname=sf-src%archdate%.zip
echo Packing: %fname%.
if exist %fname% del %fname%
7za.exe a -tzip -mx7 -r0 -x!*.zip %fname% .\sf .\src clean.cmd make-arch.cmd >nul

rem Compiling the project...
set PUBLICBUILD=YES
cd src
wmake -h -s
cd rxsf
wmake -h -s
cd ..\..

rem Second archive - binaries.
set fname=sf-bin%archdate%.zip
echo Packing: %fname%.
if exist %fname% del %fname%
7za.exe a -tzip -mx7 -r0 -x!*.zip %fname% .\sf >nul
