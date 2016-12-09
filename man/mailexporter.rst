==============
 mailexporter
==============

NAME
====

mailexporter - export metrics about mail server functionalty

SYNOPSIS
========

mailexporter [options]

OPTIONS
=======

**-config-file** config-file to use (default "/etc/mailexporter.conf")

**-config.log-timestamps** Log with timestamps

**-v=<level>** verbosity; higher means more output (default 1)

**-web.listen-address** colon separated address and port mailexporter shall listen on (default ":8080")

**-web.metrics-endpoint** HTTP endpoint for serving metrics (default "/metrics")

EXPORTED METRICS
================

* *mail_deliver_success*: indicates if last successfully sent mail was delivered in time (`1` if so, `0` if not)
* *mail_last_deliver_time* last time a mail was successfully delivered to the system as a unix timestamp (in seconds)
* *mail_last_deliver_duration* time it took for the last received mail to be delivered (doesn't matter if timed out or not) in milliseconds
* *mail_late_mails* number of probing-mails being received after their respective timeout
* *mail_deliver_durations* histogram of `last_mail_deliver_duration` with 50ms-buckets up to 100s currently (to observe even massively late mails)
* *mail_send_fails* indicates the number of failed attempts to send a probing mail via the specified SMTP-Server

SEE ALSO
========

mailexporter.conf(5)
