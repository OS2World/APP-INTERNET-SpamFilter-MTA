@echo off
cd src
wmake -h -s clean
cd rxsf
wmake -h -s clean

cd ..\..\sf\data
set dataFiles=GrLst.* GrLstCf.* stat.* spamlink.* whitelst.* stat.*
for %%i in (%dataFiles%) do if exist %%i del %%i

cd ..\log
if exist *.log del *.log
cd ..\spam
if exist *. del *. /N

cd ..\..
