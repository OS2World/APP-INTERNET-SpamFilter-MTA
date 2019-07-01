
                   Spam filter for OS/2 and eComStation.
                      Written for Weasel mail server.


Introduction
------------

The program was developed mainly for use with Weasel mail server. On every
stage REXX scripts are called by Weasel to query SpamFilter via local
socket.


Installation
------------

1. Unpack sf.zip to any directory on your disk.

2. Read ..\readme.txt "How to start" and edit XML configuration file
   config.xml. Specify hostname of your mail server in <mail-server-name>.
   The server should be accessible from Internet. If you're using Weasel
   Setup Notebook then you can find it on "Options 1" page.

3. Copy files sfQuery.cmd, sfStage0.cmd, sfStage1.cmd, sfStage2.cmd,
   sfStage3.cmd, sfStage4.cmd and rxsf.dll to your Weasel directory.

4. If you already have filters then open sfQuery.cmd and specify them
   in userFilter.N variable, where N is an appropriate stage which uses this
   filter.

5. Run SF.EXE.

6. In Weasel Setup notebook:

   - On page "Filters" specify new filters:

       Filter 0: sfStage0.cmd
       Filter 1: sfStage1.cmd
       Filter 2: sfStage2.cmd
       Filter 3: sfStage3.cmd
       Filter 4: sfStage4.cmd

     Check "Serialise filter operations" if your filters require it or
     leave it unchecked for better performance.

     WARNING! Do not use option nonexistent-locsender in SpamFilter
     configuration file while you are using "Serialise filter operations".
     See the comments for nonexistent-locsender in the config.xml file.

   - Turn off any antispam checking. On page "Blacklists" - uncheck all boxes. 
     Disable "postmaster" check if your Weasel version has it.

7. Run Weasel and check messages in log file
     <direcory where SF.EXE runned>\log\sf.log
   for additional tuning of SpamFilter.

NOTE: There is a bug in Weasel versions below 2.26 which causes program failure
      when stage 0 filter is used.



Donations are most welcome!
PayPal: digi@os2.snc.ru
Yandex.Money: 410017073387496

Andrey Vasilkin, 2016-2019
E-mail: digi@os2.snc.ru
