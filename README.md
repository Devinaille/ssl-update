# ssl-update

Push acme.sh-renewed certificates to multiple destinations (Safeline WAF CE, Aliyun ESA) via a single config file. Plug-in architecture for adding new destinations.

## Features

- **Pluggable destinations** — each target implements a Go interface and self-registers
- **Stateful** — remembers last-deployed cert id to update in place instead of creating duplicates
- **Per-destination failure policy** — `required: true` makes that destination's failure abort the whole run
- **Standalone + acme.sh integration** — works as a `--reloadcmd` or invoked directly

## Install

Requires Go 1.22+ on the build host. Runtime: any Linux amd64 / arm64.

```bash
git clone <this-repo>
cd ssl-update
go build -o ssl-update ./cmd/ssl-update
sudo install -m 0755 ssl-update /usr/local/bin/ssl-update
```

## Configure

```bash
sudo install -d -m 0700 /etc/ssl-update
sudo install -d -m 0755 -o root -g adm /var/log/ssl-update
sudo install -m 0644 /dev/null /var/log/ssl-update/ssl-update.log
sudo cp config.example.yaml /etc/ssl-update/config.yaml
sudo chmod 600 /etc/ssl-update/config.yaml
$EDITOR /etc/ssl-update/config.yaml   # fill in real credentials
sudo cp contrib/logrotate/ssl-update /etc/logrotate.d/
```

## Use

```bash
# validate config + connectivity (no cert push)
ssl-update --config /etc/ssl-update/config.yaml validate

# manual deploy (reads cert from config or env)
ssl-update --config /etc/ssl-update/config.yaml run

# deploy only one destination (debug)
ssl-update --config /etc/ssl-update/config.yaml run --only prod-safeline

# show what's been deployed
ssl-update --config /etc/ssl-update/config.yaml show-state

# dry run
ssl-update --config /etc/ssl-update/config.yaml run --dry-run
```

## Integrate with acme.sh

If this is your first acme.sh install, use `--install-cert` with `--reloadcmd`:

```bash
acme.sh --install-cert -d "*.a.com" \
  --reloadcmd "/usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run"
```

If you already have acme.sh running, edit the domain's conf file (don't re-run `--install-cert`):

```bash
vi ~/.acme.sh/\*.a.com/\*.a.com.conf
# add at the end:
Le_ReloadCmd='/usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run'
```

To verify immediately:

```bash
~/.acme.sh/acme.sh --renew -d "*.a.com" --force
tail -n 50 /var/log/ssl-update/ssl-update.log
```

## Logging

Default destination is `/var/log/ssl-update/ssl-update.log` (rotated by the provided logrotate config).

For journald instead, leave `log.file: ""` and wrap the reloadcmd:

```bash
Le_ReloadCmd='/usr/bin/systemd-cat -t ssl-update /usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run'
journalctl -t ssl-update -f
```

## Add a new destination

Implement the `destination.Destination` interface in a new Go package under `internal/destination/<name>/`. Register in `init()`:

```go
func init() {
    destination.Register("mytype", New)
}
```

Add a blank import in `cmd/ssl-update/main.go`:

```go
import (
    _ "ssl-update/internal/destination/mytype"
)
```

Done. No other code change needed — your new `type: mytype` will work in config.

## License

TBD.
