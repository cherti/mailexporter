==============
 mailexporter
==============

NAME
====

mailexporter - export metrics about mail server functionalty

GENERAL OPTIONS
===============

**monitoringinterval** Interval betwteen subsequent probing attempts for one external server 

**startupoffset** Delay between starting the monitoring-subroutines per server

**mailchecktimeout** Timeout until mails are considered "didn't make it"

**disablefiledeletion** <false|true> Disables the mailexporters function to delete probing mails if filesystem access should be restricted to avoid spamming the log with warnings; defaults to false, i.e. detected probing mails are deleted, and can be ommitted if unneeded

SERVER-OPTIONS
==============

**name** name for internal prometheus-metric
**server** SMTP-server to use
**port** port to use on Server for SMTP
**login** login name on server (leave empty together with passphrase to disable authentication)
**passphrase** SMTP-login-password (leave empty together with login to disable authentication)
**from** From-Header of monitoring-Mail (e.g. for filtering)
**to** address to deliver to
**detectiondir** Maildir in which to look for monitoring-mail

SEE ALSO
========

mailexporter(1)
