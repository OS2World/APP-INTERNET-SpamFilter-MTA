/*

   Subroutine for sending requests to the spam filter. This is external
   function for scripts sfStage0.cmd ... sfStage4.cmd.
   Argument: stageNumber
   Returns the code that weasel expects from the filter.

   Dynamic library RXSF.DLL will be used only for communication with SpamFilter
   through a local socket (this is the default and recommended). It will not be
   loaded if a system pipe is used.
*/


/* ************************************************************* */
/*                        User settings                          */
/* ************************************************************* */


/* Your filters (number after dot is the stage number).
   These filters will be called after receiving a successful response from the
   SpamFilter.

   Example:
     userFilter.4 = "imapStage4.cmd"
*/
userFilter.0 = ""
userFilter.1 = ""
userFilter.2 = ""
userFilter.3 = ""
userFilter.4 = ""


/* The spam filter can receive requests through the local socket or a system
   pipe. You can choose a local socket by setting variable socketName or a pipe
   by setting variable pipeName. If both are specified, an attempt will be made
   to use the socket first. The names of the local socket and/or shared pipe
   are defined in SpamFilter configuration.
*/

/* The name of the socket for communication with SpamFilter. */
socketName = "SPAMFILTER"

/* The name of the pipe to communication with SpamFilter. */
pipeName = "SPAMFILTER"


/* Debug information will be displayed if debugMode is equal to 1. */
debugMode = 1



/* ************************************************************* */
/*                        Initialization                         */
/* ************************************************************* */

/* Set trap conditions. */
signal on Error
signal on Failure name Error
signal on Halt
signal on Syntax name Error

parse source . callType .
if callType \= "FUNCTION" then
  call die "This code should be called from sfStage?.cmd scripts."

socketHandle = -1      /* Socket handle opened by sfOpen(). */
usePipe = 0            /* Will be set by sfOpen()           */

/* Global variables list. */
global = "pipeName socketName usePipe socketHandle debugMode"


/* ************************************************************* */
/*                        Collect input                          */
/* ************************************************************* */

/* Get arguments from Weasel for main (that called us) script:
   namefile and messagefile. */
'@ECHO "%1 %2"|rxqueue'
parse pull weaselArg
parse value strip( strip( weaselArg, "B", '"' ) ) with nameFile" "msgFile
/* Get session id from namefile's name */
parse value filespec( "name", nameFile ) with name"."sessId
drop weaselArg name

/* Get argument for this routine - stage number. */
parse arg stage
if stage < 0 | stage > 4 then
  call die "Invalid arguments"

call debug "Stage " || stage || ", session " || sessId


/* Read data from the namefile given by Weasel. */

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


/* ************************************************************* */
/*    Request to SpamFilter, getting response code for Weasel    */
/* ************************************************************* */

/* Open connection to the SpamFilter interface. */
if \sfOpen() then
do
  res = 0
  call log "Could not connect to SpamFilter"
end
else
do

  /* Send requests to SpamFilter corresponding to Weasel filter stage. */

  select
    when stage = 0 then
    do
  /*  -- For Weasel versions below 2.26 --
      sfRes = "OK: " */

      /* For ver. >= 2.26 */
      sfRes = sfRequest( "SESSION "sessId" @ACCEPT "clientIP" "clientHostName )
    end

    when stage = 1 then
    do
  /*  -- For Weasel versions below 2.26 --
      sfRes = sfRequest( "SESSION "sessId" @ACCEPT "clientIP" "clientHostName )
      if left( sfRes, 3 ) = "OK:" then */
        sfRes = sfRequest( "SESSION "sessId" EHLO "EHLO )
    end

    when stage = 2 then
    do
      sfRes = sfRequest( "SESSION "sessId" MAIL FROM:"mailFrom )
    end

    when stage = 3 then
    do
      do idx = 1 to rcpt.0
        sfRes = sfRequest( "SESSION "sessId" RCPT TO:<"rcpt.idx">" )
      end
      sfRes = sfRequest( "SESSION "sessId" DATA" )
    end

    otherwise /* stage 4 */
      sfRes = sfRequest( "SESSION "sessId" @CONTENT "msgFile )
  end  /* select */

  /* Close SpamFilter interface connection. */
  call sfClose

  /* Parse Spam Filter answer, format: ANSWER:details */
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

    when answer = "ERROR" then
      /* If the spam filter is not working, all messages will be delivered to
         recipients. */
      call log answer
      res = 0

    otherwise
      do
        call log "Unknown SpamFilter answer: " || sfRes
        res = 0
      end
  end

  call debug "Stage "stage", session "sessId": Result code for Weasel: "res

end  /* if \sfOpen() then else */

/* Now we have the answer for Weasel in variable res. */


/* ************************************************************* */
/*                       Run user filter                         */
/* ************************************************************* */

if res = 0 & symbol( "userFilter."stage ) = "VAR" & userFilter.stage \= "" then
do
  cmd = userFilter.stage || " " || nameFile || " " || msgFile
  call debug "Run: " || cmd

  "@cmd /c " || cmd
  if rc > 4 & rc \= 16 then
  do
    call log "Invalid result code from the user filter: " || rc
    res = 0   /* Invalid result code - return 0 (continue processing). */
  end
  else do
    call debug "Result code from the user filter: " || rc
    res = rc  /* Return code of the user filter to Weasel */
  end
end


/* Done!
   Return result code to Weasel. */
call log "Stage "stage", session "sessId": Result code for Weasel: "res
return res

/* ************************************************************* */



/* ************************************************************* */
/*           SpamFilter interface universal routines             */
/* ************************************************************* */

/* sfOpen()

   Open pipe (global variable usePipe is not 0) or socket (usePipe is 0).
   Returns 0 if an error occurred or 1 if successful.
*/

_sfOpenSock: procedure expose (global)
  if symbol( "socketName" ) \= "VAR" then
    return 0

  /* Load SpamFilter local socket REXX API */
  if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
  do
    call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"

    if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
    do
      call debug "Error loading library RXSF.DLL"
      return 0
    end
  end

  socketHandle = rxsfOpen( socketName )
  if socketHandle = -1 then
  do
    call debug "Socket " || socketName || " open error"
    return 0
  end

  call debug "Socket " || socketName || " is open"
  return 1

_sfOpenPipe: procedure expose (global)
  if symbol( "pipeName" ) \= "VAR" then
    return 0

  /* Expand the pipe name according to the system requirements. */
  if translate( left( pipeName, 6 ) ) \= "\PIPE\" then
    pipeName = "\PIPE\" || pipeName

  rc = stream( pipeName, "c", "open" )
  if left( rc, 6 ) = "READY:" then
  do
    call debug "Pipe " || pipeName || " is open"
    return 1
  end

  if left( rc, 9 ) = "NOTREADY:" then
  do
    rc = substr( rc, 10 )
    select
      when rc = 231 then       /* ERROR_PIPE_BUSY */
        rc = rc || ", pipe is busy"
   
      when rc = 3 then         /* ERROR_PATH_NOT_FOUND  */
        rc = rc || ", pipe does not exist"
    end
  end
  call debug "Pipe " || pipeName || " open error: " || rc

  return 0

sfOpen: procedure expose (global)
  if _sfOpenSock() then
  do
    usePipe = 0
    return 1
  end

  if _sfOpenPipe() then
  do
    usePipe = 1
    return 1
  end

  return 0


/* sfClose()

   Closes the socket or pipe opened by function sfOpen().
*/
sfClose: procedure expose (global)
  if usePipe then
  do
    call debug "close pipe"
    call stream pipeName, "c", "close"
  end
  else if socketHandle \= -1 then
  do
    call debug "close socket"
    call rxsfClose socketHandle
    socketHandle = -1
  end
  return


/* sfRequest( request )

   Sends a request and receives a response.
   Returns the spam filter response like: [OK|SPAM|DELAYED|ERROR]:details
*/
sfRequest: procedure expose (global)
  request = arg( 1 )

  if usePipe then
  do

    /* Send a request through the pipe. */
    call debug "Request: " || request
    rc = lineout( pipeName, request )
    if rc \= 0 then
    do
      call log "Error writing to the pipe " || pipeName
      return "ERROR:Error writing to the pipe"
    end

    /* Get a response from SpamFilter. */
    sfRes = linein( pipeName )

  end   /* if usePipe */
  else
    sfRes = rxsfRequest( socketHandle, request )

  call debug "Answer: " || sfRes
  return sfRes

/* ************************************************************* */

Error:
  parse source . . cmdFile
  say "---"
  say "Signal " || condition( "C" ) || " in " || cmdFile
  say "  Source line " || SIGL || ": " || sourceline( SIGL )

  haveRC = symbol("RC") = "VAR"

  if condition( "D" ) \= '' then
    say "  Description: " || condition( "D" )
  if ( condition( "C" ) = 'SYNTAX' ) & haveRC then
    say "  Error (" || RC || "): " || errortext( RC )
  else if haveRC then
    say "  Error " || RC

  exit 0


/* log( message )
   Prints messages on the screen. */
log: procedure
  say "[sfQuery] " || arg( 1 )
  return

/* debug( message ) */
debug:
  if debugMode = 1 then
    call log "DEBUG " || arg( 1 )
  return

/* die( message ) */
die: procedure
  call log "ERROR " || arg( 1 )
  exit 0
