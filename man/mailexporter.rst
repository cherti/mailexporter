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

**-config.file** config-file to use (default "/etc/mailexporter.conf")

**-log.timestamps** Log with timestamps

**-v=<level>** verbosity; higher means more output (default 1)

**-web.listen-address** colon separated address and port mailexporter shall listen on (default ":9225")

**-web.telemetry-path** HTTP endpoint for serving metrics (default "/metrics")

EXPORTED METRICS
================

* *mail_deliver_success* indicates if last successfully sent mail was delivered in time (`1` if so, `0` if not)
* *mail_send_fails* indicates the number of failed attempts to send a probing mail via the specified SMTP-Server
* *mail_last_send_duration_seconds* duration of last valid mail handover to external SMTP-server in seconds
* *mail_send_durations_seconds* histogram of gauge `mail_last_send_duration_seconds`
* *mail_last_deliver_duration_seconds* time it took for the last received mail to be delivered (doesn't matter if timed out or not) in seconds
* *mail_deliver_durations_seconds* histogram of gauge `last_mail_deliver_duration`
* *mail_last_deliver_time* last time a mail was successfully delivered to the system as a unix timestamp (in seconds)
* *mail_late_mails* number of probing-mails being received after their respective timeout

SEE ALSO
========

mailexporter.conf(5)
