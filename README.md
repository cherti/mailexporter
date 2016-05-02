# Mailexporter

Metrics Exporter for Mailserver for the [Prometheus](www.prometheus.io)-monitoring-system.
This exporter can be used for mailsetups based on Maildir. Other storage formats are currently not supported.

It tries to send e-mails in specified time intervals over the specified SMTP-servers and verifies delivery into the specified according maildirs.
Success is indicated by a value of `1` of the metric `mail_deliver_success`, failure is indicated by `0`.


## Exported metrics

The following metrics are exported, for each metric there is one instance per probe-config, distinguishable by label `configname` (which contains the value of the `Name`-field of the respective configuration section).

* `mail_deliver_success`: indicates mail delivery functionality (`1` if functional, `0` if not)
* `mail_last_deliver_time`: last time a mail was successfully delivered to the system as a unix timestamp (in seconds)
* `mail_last_deliver_duration`: time it took for the last received mail to be delivered (doesn't matter if timed out or not) in milliseconds
* `mail_late_mails`: number of probing-mails being received after their respective timeout
* `mail_deliver_durations`: histogram of `last_mail_deliver_duration` with 50ms-buckets up to 100s currently (to observe even massively late mails)
* `mail_send_fails`: indicates the number of failed attempts to send a probing mail via the specified SMTP-Server

## Building and running

### manually

    # get dependencies
    go get -u "github.com/prometheus/client_golang/prometheus"
    go get -u "gopkg.in/yaml.v2"
    go get -u "github.com/abbot/go-http-auth"
    
    # actually build and run
    git clone https://github.com/cherti/mailexporter.git
    cd mailexporter
    go build mailexporter.go
    ./mailexporter


### automatically using go-toolchain

    go get -u "github.com/cherti/mailexporter"
    ./mailexporter


## Configuration

By defaut, mailexporter reads `/etc/prometheus/mailexporter.conf` as its configfile. This can be changed via the command line flag `-config-file`.
Also, by default, it uses HTTP basic auth on the metrics-endpoint as well as TLS.
If desired, both can be disabled by using the `-auth=false` or the `-tls=false` commandline flags respectively.

The address mailexporter should listen on is specified by the commandline-flag `-web.listen-address` in the format `<address>:<port>`.
Furthermore you can adjust the HTTP endpoint for metrics by setting the `web.metrics-endpoint`-flag, which defaults to `/metrics`.

Further configuration is done via the configuration file. See config.yml for further info.


### config.yml

The configuration is done in [YAML](www.yaml.org).

For detailed info see `config.yml` as the provided example configuration.

By default, mailexporter looks for a configuration file ./mailexporter.conf. This can be changed via `-config-file=/path/to/file` as cli-flag.


## License

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license at https://www.gnu.org/licenses/gpl-3.0.txt.
