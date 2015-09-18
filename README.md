# Mailexporter

Metrics Exporter for Mailserver for the [Prometheus](www.prometheus.io)-monitoring-system.
This exporter can be used for mailsetups based on Maildir. Other storage formats are currently not supported.

It tries to send e-mails in specified time intervals over the specified SMTP-servers and verifies delivery into the specified according maildirs.
Success is indicated by a value of `1` of the metric `mail_deliver_success`, failure is indicated by `0`.


## Exported metrics

The following metrics are exported, for each metric there is one instance per probe-config, distinguishable by label `configname` (which contains the value of the `Name`-field of the respective configuration section).

* `mail_deliver_success`: indicates mail delivery functionality (`1` if functional, `0` if not)
* `last_mail_deliver_time`: last time a mail was successfully delivered to the system as a unix timestamp (in seconds)
* `last_mail_deliver_duration`: time it took for the last received mail to be delivered (doesn't matter if timed out or not) in milliseconds
* `late_mails`: number of probing-mails being received after their respective timeout

## Building and running

### manually

    # get dependencies
    go get -u "github.com/prometheus/client_golang/prometheus"
    go get -u "gopkg.in/yaml.v2"
    go get -u auth "github.com/abbot/go-http-auth"
    
    # actually build and run
    git clone https://github.com/cherti/mailexporter.git
    go build mailexporter.go
    ./mailexporter


### automatically using go-toolchain

    go get -u "github.com/cherti/mailexporter"
    ./mailexporter


## Configuration

By defaut, mailexporter reads `/etc/prometheus/mailexporter.conf` as its configfile. This can be changed via the command line option `-config-file`.
Also, by default, it uses HTTP basic auth on the metrics-endpoint as well as TLS.
If desired, both can be disabled by using the `-auth=false` or the `-tls=false` commandline options respectively.

Further configuration is done via the configuration file.


### config.yml

The configuration is done in [YAML](www.yaml.org).

For detailed info see `config.yml` as the provided example configuration.

By default, mailexporter looks for a configuration file ./mailexporter.conf. This can be changed via `-config-file=/path/to/file` as cli-option.


## License

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license at https://www.gnu.org/licenses/gpl-3.0.txt.
