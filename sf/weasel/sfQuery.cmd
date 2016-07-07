/*
   Send request to the spam filter. This is external function for scripts
   sfStage0.cmd ... sfStage4.cmd. Arguments: stage number, request.
*/

/* ------------------------------[ Settings ]----------------------------- */

/* Debug is 1 - print requests to the spam filter and spam filter answers to
   the screen. */
debug = 1

/* Specify the variable socketName same as <socket> in the spam filter
   configuration. */
socketName = "SPAMFILTER"

/* Your filters (number after dot is the stage number). */
userFilter.0 = ""
userFilter.1 = ""
userFilter.2 = ""
userFilter.3 = ""
userFilter.4 = ""

/* ----------------------------------------------------------------------- */

parse source . callType .
if callType \= "FUNCTION" then
do
  say "This code should be called from sfStage?.cmd scripts."
  exit
end

/* Get arguments from Weasel for main script. */
'@ECHO "%1 %2"|rxqueue'
parse pull weaselArg
parse value strip( strip( weaselArg, 'B', '"' ) ) with nameFile" "msgFile
/* Get session id from namefile's name */
parse value filespec( "name", nameFile ) with name"."sessId

/* Get arguments for this routine. */
parse arg stage
if stage < 0 | stage > 4 then
do
  say "[sfQuery] Invalid arguments"
  return 0
end

/* Read data from the namefile. */
if stage < 4 then
do
  parse value linein( nameFile ) with "["clientIP"] "clientHostName

  if stage >= 1 then
    EHLO = linein( nameFile )

  if stage >= 2 then
    mailFrom = linein( nameFile )

  if stage = 3 then
  do
    do while linein( nameFile ) \= ""
      nop
    end

    do idx = 1 by 1 while lines( nameFile ) \= 0
      rcpt.idx = linein( nameFile )
    end
    if rcpt.idx = "" then idx = idx - 1
    rcpt.0 = (idx - 1)
  end
  call stream nameFile, "c", "close"
end

/* Load spam filter REXX API */
if RxFuncQuery( "rxsfLoadFuncs" ) == 1 then
do
  call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"
  call rxsfLoadFuncs
end

select
  when stage = 0 then
  do
/*  -- For Weasel versions below 2.26 --
    sfRes = "OK: " */

    /* For ver. >= 2.26 */
    sfRes = rxsfRequest( socketName, ,
                         "SESSION "sessId" @ACCEPT "clientIP" "clientHostName )
  end

  when stage = 1 then
  do
/*  -- For Weasel versions below 2.26 --
    sfRes = rxsfRequest( socketName, ,
                         "SESSION "sessId" @ACCEPT "clientIP" "clientHostName )
    if left( sfRes, 3 ) = "OK:" then */
      sfRes = rxsfRequest( socketName, "SESSION "sessId" EHLO "EHLO )
  end

  when stage = 2 then
  do
    sfRes = rxsfRequest( socketName, "SESSION "sessId" MAIL FROM:"mailFrom )
  end

  when stage = 3 then
  do
    socket = rxsfOpen( socketName )
    if socket = -1 then
    do
      say "[sfQuery] Cannot open socket for SpamFilter"
      sfRes = "ERROR: Cannot open socket for SpamFilter"
    end
    else
    do
      do idx = 1 to rcpt.0
        sfRes = rxsfRequest( socket, "SESSION "sessId" RCPT TO:<"rcpt.idx">" )
      end
      sfRes = rxsfRequest( socket, "SESSION "sessId" DATA" )
      call rxsfClose socket
    end
  end

  otherwise
    sfRes = rxsfRequest( socketName, "SESSION "sessId" @CONTENT "msgFile )
end

/* Parse Spam Filter answer, format: ANSWER: details */
parse var sfRes answer":"details

/* Set return code for Weasel */
select
  when answer = "OK" then
  do
    if left( details, 10 ) = " spamtrap=" then
      /* Message from the local user to spamtrap is received. Say Weasel answer
         250 OK but do not save the message (code 2). */
      res = 2
    else
      /* Need checks on the next stages. */
      res = 0
  end

  when answer = "SPAM" then
    /* Don't deliver the message, and return the default rejection message to
       the client. */
    res = 3

  when answer = "DELAYED" then
    do
      /* Message delayed. Client ip-address, sender e-mail and recipients are
         stored in the greylist. */
      call stream nameFile, "c", "open"
      call stream nameFile, "c", "seek =0"
      call lineout nameFile, "451 Please try again later"
      call stream nameFile, "c", "close"
      res = 4          /* 4 - return SMTP message from the nameFile */
    end

  otherwise
    do
      /* Continue message receiving on any other code (return 0 or 16).
         In particular, if the spam filter is not running, all messages will be
         delivered to the recipients. */
      if debug = 1 then
        say "[sfQuery] Answer: " || sfRes
      res = 0
    end
end

if debug = 1 then
  say "[sfQuery] Stage "stage", session "sessId", result code for Weasel: "res

/* Run user filter. */
if res = 0 & symbol( "userFilter."stage ) = "VAR" & userFilter.stage \= "" then
do
  cmd = userFilter.stage || " " || nameFile || " " || msgFile
  if debug = 1 then
    say "[sfQuery] Run: " || cmd

  "@cmd /c " || cmd
  if rc > 4 & rc \= 16 then
    res = 0   /* Invalid result code - return 0 (continue processing). */
  else
    res = rc  /* Return code of the user filter to Weasel */
end

return res
