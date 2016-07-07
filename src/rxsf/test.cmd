/* */

/* call rxsfDropFuncs */

/*if RxFuncQuery( "rxsfLoadFuncs" ) == 1 then*/
do
  call RxFuncAdd "rxsfLoadFuncs","rxsf","rxsfLoadFuncs"
  call rxsfLoadFuncs
end

sid = "001"
do 1
socket = rxsfOpen( "SPAMFILTER" )
say "Open: " || socket
say "> " || rxsfRequest( socket, "SESSION "sid" @ACCEPT 8.8.8.8 smtp.googlemail.com" )
say "> " || rxsfRequest( socket, "SESSION "sid" EHLO network1.dom" )
say "> " || rxsfRequest( socket, "SESSION "sid" MAIL FROM:<qwe@asd.ru>" )
say "> " || rxsfRequest( socket, "SESSION "sid" RCPT To:digi@asdas" )
say "> " || rxsfRequest( socket, "SESSION "sid" DATA" )
say "> " || rxsfRequest( socket, "SESSION "sid" @CONTENT 123.eml" )
call rxsfClose socket
end
exit

say "> " || rxsfRequest( "SPAMFILTER2", "SESSION 001 @ACCEPT 8.8.8.8" )
say "> " || rxsfRequest( "SPAMFILTER2", "SESSION 001 EHLO network.dom" )
say "> " || rxsfRequest( "SPAMFILTER2", "SESSION 001 MAIL FROM : <@!@#!@qdqw:digi@os2.snc.ru> qweq" )
say "> " || rxsfRequest( "SPAMFILTER2", "SESSION 001 RCPT To:digi@asdas" )

/*
socket = rxsfOpen()
say "Open: " || socket

"pause"

answer = rxsfRequest( socket, "stage 0 REXX 212.6.1.74" )
say "Request: " || answer

say "You can use more rxsfRequest() on single socket to speed up queries."

"pause"

call rxsfClose socket
*/

/*sessId = time( "S" )
say "> " || rxsfRequest( , "stage 0 " || sessId || " 12.168.1.11 ns.some.net.dom" )
say "> " || rxsfRequest( , "stage 1 " || sessId || " ns.some.net.dom" )
say "> " || rxsfRequest( , "stage 2 " || sessId || " <user@abc.dom>" )
say "> " || rxsfRequest( , "stage 3 " || sessId || " localuser@my.network.dom" )
say "> " || rxsfRequest( , "stage 4 " || sessId || " file.msg" )*/
/* say "> " || rxsfRequest( , "shutdown" ) */
