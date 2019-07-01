
                Spam filter for OS/2, eComStation and ArcaOS.


What it is
----------

The SpamFilter is a free and Open Source software able to detect and reject
e-mail messages containing unwanted advertising. SpamFilter is a multi-threaded
daemon and features local sockets and named pipes interfaces to receive
queries and send answers to mail server software (MTA).


What it is not
--------------

This software does not support the "open relay" situations (MTA must be
configured correctly) and do not perform anti-virus protection. SpamFilter is
not SMTP proxy, it interacts with mail server software by using queries.


How it works
------------

Each SMTP session on MTA should generate a series of queries to SpamFilter with
a common identifier (session Id). Queries runs sequentially as clarification
information comes: client ip-address and host name, EHLO host name, sender
address, recepients, message content.

Session score changes by processing incoming information. Spam Filter
tells the server that spam is detected if the score has reached a limit.

On each stage the following steps are performed:

  Stage 0. Client ip-address.

    1. Detect relay mail server by checking client ip-address/host name.
       (set flag "relay", skip all stages till 5, on the last stage we can read
       ip address from message header fields "Received:" and pass through all
       stages again).
    2. Set flag local-client if client ip-address/host name mathes configured
       local networks.
       (set flag local-client, end of stage 0 for "local sender").
    3. Scoring a client with missing PTR record.
    4. Scoring by internal dynamic ip-address list.
    5. Client ip-address/host name scoring (by user settings).

  Stage 1: HELO/EHLO host name.

    1. Saving EHLO to current session object.

  Stage 2: MAIL FROM address.

    1. Check if email address is from one of local domains
       (set flag local-sender, end of stage 2 for "local sender").
    2. Search MAIL FROM address by auto-whitelist, it is not a SPAM if
       listed.

    Skip next steps flag local-client or local-sender set.

    3. Scoring by configured patterns for MAIL FROM.
    4. Check ip-address with RWL(*).
    5. Check received EHLO on the stage 1 (step is skipped for connections
       from relays).
       - Name of local domain is specified in EHLO - SPAM!
       - Scoring by configured patterns for HELO/EHLO.
       - Comparing EHLO with client's IP/hostname. Scoring if they are
         different.
       - Scoring EHLO by URIBL(*).

  Stage 3: Recipient is specified.

    1. Saving recepient address to session object.

  Stage 4: Last entry in recipient list

    1. If it is a local sender then add all external recipients to 
       auto-whitelist (see stage 2, step 2) and finish stage 4.
    2. Look for recepients addresses in spam trapped adresses.
       If a message falls into a trap then keep address of the trap, change
       score for client's IP-address in an internal dynamic list (see stage 0,
       step 4), end stage 4.
    3. Search/insert in greylist or delaying messages.
       Close current session if the message is delayed.
    4. Scoring sender address by DNSBL(*).
    5. Scoring sender address by URIBL(*).
    6. Checking existence of a sender mailbox.
    7. Scoring by SPF(*).

  Stage 5: Message is received and saved to file.

    1. For messages from one of our relays (see stage 0, step 1) get first
       "external" IP-address (host behind all of our relays) and go through
       stages 0, 2, 4.
    2. Check the message. Collect host names of URIs from message body.
       - For spam-trapped messages store host names to spam-hostname list
         and set score session as SPAM.
       - For others:
           - Check the message field "Message-ID".
           - Scoring with message body check result (look for URIs at the
             collected spam-hostnames and URIBL(*)).

  (*)
  RWL   - On-line DNS based White Lists is a list of mail server's IP addresses
          who have been deemed worthy of sending "Legitimate" spam-like email.
          It should reduce the number of false positives.
  URIBL - On-line DNS based Black Lists for the domain names.
  DNSBL - On-line DNS based Black Lists for the IP-addresses.
  SPF   - Sender Policy Framework. Allow to check that incoming mail from a
          domain comes from a host authorized by that domain's administrators.
  greylist - see https://en.wikipedia.org/wiki/Greylisting


Queries to spam filter
----------------------

Queries may be send via local socket or named pipe. Check configuration file
config.xml for nodes <socket> and <pipe>. Queries are case-insensitive.

  SMTP session queries. The format is "SESSION sessId <command> [parameters]".
  Where "sessId" is a unique string identifier for an individual SMTP-session
  (TCP/IP socket number or something else).

  "SESSION sessId @ACCEPT nnn.nnn.nnn.nnn hostname"

    Open a new session with identifier sessId for the SMTP-client with
    IP-address nnn.nnn.nnn.nnn and host name (determined by reverse DNS lookup).
    If IP-address have no PTR-record (host name), then hostname is just a repeat
    of the IP-address.
    If MTA does not check reverse DNS zone the host name should be omitted. In
    this case spam filter performs the reverse DNS lookup.
    IP-address and host name may be enclosed in square brackets.

  "SESSION sessId EHLO string"

    The HELO/EHLO string as specified by a client in SMTP session.

  "SESSION sessId MAIL FROM:address"

    Sender address as specified by a client in MAIL command.
    Format of "address" is described in RFC 5321 (4.1.1.2., 4.1.2.):
      Reverse-path [SP Mail-parameters]
    or maybe just the e-mail address, enclosed or not in "<"
    and ">" symbols.

  "SESSION sessId RCPT TO:address"

    Recepient address as specified by a client in RCPT command.

  "SESSION sessId DATA"

    End of recipient list. Command DATA was received from a client.

  "SESSION sessId RSET"

    Reset data that was stored by all previous commands, except @ACCEPT.

  "SESSION sessId @CONTENT D:\path\file"

    Message was received and saved to D:\path\file.

  "SESSION sessId QUIT"

    End of session.

  Other queries.

  "SHUTDOWN"

     Save all current internal data and quit.

  "RECONFIGURE"

     Read modified configuration file and use it if it's valid.

On any query SpamFilter returns answer in format: "ANSWER: details".
Where ANSWER may be one of:

  OK:       - Success. / Command accepted.
  SPAM:     - Session was marked as spam, MTA should reject the session.
  DELAYED:  - Message was delayed. IP-address, sender and recepient addresses
              are recorded in the greylist. MTA should return code 451 to a
              client (for example: "451 Please try again later") and close SMTP
              session.
  ERROR:    - Various errors.

Some details may be specified after the colon and space. This may be a
description of the error or something else.


How to start
------------

Edit configuration file config.xml. At minimum, you must specify next options:

  name-server
    DNS server (SpamFilter does not automatically detect it yet),

  mail-server-name
    Your MTA host name.

  local-domain
    Your local mail domain name(s).

  uribl / not-spam
    Optional if you have ftp/web-servers specify their domain names.

  command-ataccept / relay
    Optional if incoming mail is forwarded to your MTA from provider mail
    server - specify address of this mail server here.

  command-ataccept / local
    Your local network(s).

  command-data / spamtrap
    Optional spamtrap mailboxes on your MTA.

Run (in single session or detached) SF.EXE. For the first run it is better not
to use "detach" to see configuration error/warning messages.

Now you can try to send queries to running spam filter. For example, use
command line switch -r .

SF.EXE switches:

  -c <file>      Use given configuration file instead of config.xml.
  -v             Verify configuration file and exit.
  -r <request>   Parse configuration file, then send query to running copy
                 and exit. It can be specified multiple times.
  -R             Send queries specified by switch -r through a named pipe
                 instead of a socket.",

  For example:
    sf.exe -r reconfigure
    sf.exe -r shutdown
    sf.exe -R -r "session TEST @accept 192.168.1.2"


At this point you need to adjust interaction with your mail server software.
Read .\weasel\readme.txt to get information how to use SpamFilter with Weasel
mail server.


Filter tuning
-------------

The main source of information about filter's activity is its log file:
  <direcory where SF.EXE runned>\log\sf.log.
By comparing records in a log file with stage sequence described in the section
"How it works", you will be able to understand what is necessary to change in
configuration to improve filtration. Please refer to comments in the
configuration file.

Another source of information can be a statistic file:

  <direcory where SF.EXE runned>\data\stat.xml.

It contains two XML-trees:

  "general" - Cumulative statistics. This data will not be reset between stops
  and starts SpamFilter.

  "snapshot" - Statistics of the current state, nodes contain the following
  information:

    "dns-cache" - amount of cached DNS queries.

    "sessions" - amount of open sessions.

    "greylist-sender-records" - amount of triplets with common ip-address
    and sender's address. It corresponds to amount of I-lines in GrLst.txt.

    "greylist-ip-ratings" - amount of ratings of passage
    delayed messages by ip-addresses. It corresponds to the number of lines in
    the file GrLstCf.txt.

    "requests" - amount of requests queued for processing.

    "dynamic-ip" - amount of entries in the dynamic list of IP-addresses.
    See stage 0, step 2,4 and stage 3, step 2 at the section "How it works".

    "spam-urihosts" - amount of host names collected from the spam-trapped
    messages. It corresponds to amount of records in the file spamlink.txt.

    "auto-whitelist" - amount of entries in the automatic white list.
    Check stage 2, step 5 and stage 3, step 1 at the section "How it works".


Not filtered spam messages can be forwarded to spamtrap adresses by local
users. In this case host names from the message body will be collected in the
same way as for messages cathed by spamtrap from Internet.



Donations are most welcome!
PayPal: digi@os2.snc.ru
Yandex.Money: 410017073387496

Andrey Vasilkin, 2016-2019
E-mail: digi@os2.snc.ru
