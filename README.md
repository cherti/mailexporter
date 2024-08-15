# Mailexporter

Metrics Exporter for Mailserver for the [Prometheus](www.prometheus.io)-monitoring-system.
This exporter can be used for mailsetups based on Maildir. Other storage formats are currently not supported.

It tries to send e-mails in specified time intervals over the specified SMTP-servers and verifies delivery into the specified according maildirs.
Success is indicated by a value of `1` of the metric `mail_deliver_success`, failure is indicated by `0`.


## Exported metrics

The following metrics are exported, for each metric there is one instance per probe-config, distinguishable by label `configname` (which contains the value of the `Name`-field of the respective configuration section).

* `mail_deliver_success`: indicates if last successfully sent mail was delivered in time (`1` if so, `0` if not; be aware: if sending is already unsuccessful, this metric will not change, see also `mail_send_fails_total` as well as `mail_last_deliver_time`)
* `mail_send_fails_total`: indicates the number of failed attempts to send a probing mail via the specified SMTP-Server
* `mail_last_send_duration_seconds`: duration of last valid mail handover to external SMTP-server in seconds
* `mail_send_durations_seconds`: histogram of gauge `mail_last_send_duration_seconds`
* `mail_last_deliver_duration_seconds`: time it took for the last received mail to be delivered (doesn't matter if timed out or not) in seconds
* `mail_deliver_durations_seconds`: histogram of gauge `last_mail_deliver_duration`
* `mail_last_deliver_time`: last time a mail was successfully delivered to the system as a unix timestamp (in seconds)
* `mail_late_mails_total`: number of probing-mails being received after their respective timeout


## Building and running

### manually

    # actually build and run
    git clone https://github.com/cherti/mailexporter.git
    cd mailexporter
    go get ./...
    go build mailexporter.go
    ./mailexporter


### automatically using go-toolchain

    go get -u "github.com/cherti/mailexporter"
    ./mailexporter


## Configuration

By defaut, mailexporter reads `/etc/mailexporter.conf` as its configfile. This can be changed via the command line flag `-config-file`.
The Mailexporter doesn't support TLS and auth natively. This is left to tools intended for that.
Nevertheless you are encouraged to use it with TLS and auth, e.g. by binding to `-web.listen-address=127.0.0.1:8083`
in combination with an HTTP-reverseproxy capable of doing so (for example nginx, Apache or [AuthGuard](https://github.com/cherti/authguard)).

The address mailexporter should listen on is specified by the commandline-flag `-web.listen-address` in the format `<address>:<port>`.
Furthermore you can adjust the HTTP endpoint for metrics by setting the `web.telemetry-path`-flag, which defaults to `/metrics`.

Further configuration is done via the configuration file. See `mailexporter.conf` or `man mailexporter.conf` for further info.


### mailexporter.conf

The configuration is done in [YAML](https://yaml.org).

For detailed info see `mailexporter.conf` as the provided example configuration or `man mailexporter.conf`, if the manpage is installed on your system.

By default, mailexporter looks for a configuration file `/etc/mailexporter.conf`. This can be changed via `-config-file=/path/to/file` as cli-flag.


## License

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license in the `LICENSE` file or at https://www.gnu.org/licenses/gpl-3.0.txt.
