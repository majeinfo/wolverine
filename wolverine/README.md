# Wolverine

Wolverine reads logs, turns each line into an event, finds suspicious
patterns and reacts to them: it sends an email, runs a command over ssh
(e.g. to block an IP on a firewall) or calls a webhook (Slack...).

```
sources ──> parser ──> enrichment ──> detection rules ──> actions
logfile     regexp     sshd: user,    threshold:          email
journal     journal    IP, method...  N events per IP     ssh command
                                      within a window     webhook / Slack
```

Out of the box it detects SSH brute force: 5 failed logins from the same IP
within 5 minutes.

## Contents

- [Build](#build)
- [Run](#run)
- [Configure](#configure)
  - [Sources](#sources)
  - [Rules](#rules)
  - [Actions](#actions)
  - [Allowlist](#allowlist)
  - [State file](#state-file)
- [Install as a service](#install-as-a-service)
- [Project layout](#project-layout)

## Build

Requirements:

- Go 1.27 or later.
- For the `systemd-service` source (reading the systemd journal): cgo, a C
  compiler and the libsystemd headers (`dnf install gcc systemd-devel`, or
  `apt install gcc libsystemd-dev`). At run time only `libsystemd.so.0` is
  needed; it is loaded when the journal is opened.

```bash
make            # builds bin/wolverine
make check      # go vet, the tests and a gofmt check
```

Without the systemd headers, build a static binary that has every feature
except the `systemd-service` source:

```bash
make build-nosystemd      # CGO_ENABLED=0, -tags nosystemd
```

Other targets: `make test`, `make vet`, `make fmt`, `make clean`.

## Run

```bash
bin/wolverine -config config/wolverine.yaml
```

| Option | Meaning |
|---|---|
| `-config FILE` | configuration file (default `config/wolverine.yaml`) |
| `-state FILE` | state file where the position of each source is saved; overrides `state_file` from the configuration. `-state none` disables it |
| `-events FILE` | append every event, after parsing and enrichment, as a JSON line to FILE (`-` for stdout) |
| `-v` | describe the configuration and what wolverine does (alerts, actions run, log rotations...) |
| `-v -v` or `-vv` | debugging details: rule counters per IP, every unparsed line, each action started... |

- **stdout** receives the alerts, one JSON object per line.
- **stderr** receives the logs: errors, the summary at exit and the `-v`
  messages.

Wolverine stops cleanly on Ctrl-C or SIGTERM: the queued actions run and the
position of each source is saved. Sources with `follow: false` are read once
and wolverine exits when they are all done.

### Checking a configuration

To try a regexp or a rule on a log file without touching anything:

1. Copy the configuration.
2. In the copy:
   - set `follow: false` on the sources;
   - set `disabled: true` on the actions.
3. Run without the state file, so the test starts from `start_at` and
   saves nothing:

```bash
bin/wolverine -config test.yaml -state none -events events.jsonl -v -v
```

`events.jsonl` then shows what each line became. Lines the regexp did not
match have a `parse_error` field. With `-v -v`, the log shows how each rule
counts the events.

## Configure

The configuration is a YAML file with five sections:

```yaml
allowlist:  [...]      # IPs that must never be blocked
state_file: ...        # where the position of each source is saved
sources:    [...]      # where events come from
actions:    [...]      # what to do when an alert fires
rules:      [...]      # what to detect, and which actions to run
```

[`config/wolverine.yaml`](config/wolverine.yaml) is a complete, commented
example. Unknown keys are rejected, so a typo does not silently disable part
of a rule. Every source, action and rule has an `id` and can be turned off
with `disabled: true`. Durations are written like `30s`, `5m` or `1h`.

### Sources

Every source has an `id`, a `type`, `follow` and `start_at`:

- **`follow: true`** keeps reading new lines as they are written, like
  `tail -F` or `journalctl -f`.
- **`start_at`** is `beginning` (the default) or `end`. `end` reads only new
  lines and requires `follow: true`.

When the [state file](#state-file) knows a source, its saved position is used
instead of `start_at`.

#### `logfile`: a log file

```yaml
- id: messages
  type: logfile
  path: /var/log/messages
  follow: true
  start_at: end
  regexp: '^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?:(?P<service>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?)?(?P<message>.*)$'
  timestamp_formats: [rfc3164, rfc3339]
  timezone: Europe/Paris   # optional, for timestamps without a timezone
  category: system         # default: system
```

Each line is parsed with `regexp` (Go syntax, single-quoted in YAML). Its
named groups `(?P<name>...)` fill the event:

| Group | Fills |
|---|---|
| `timestamp` | the event time, parsed with `timestamp_formats` (without it, the time the line was read) |
| `pri` | the syslog priority `<34>`: the severity and `facility` |
| `message` | the message (without it, the whole line) |
| `hostname`, `service`, `category`, `severity`, `source_ip`, `dest_ip`, `username`, `action`, `status` | the event field of the same name |
| any other name | stored in the event's `Fields`, as a string |

`timestamp_formats` are tried in order:

- `rfc3164`: `Nov  8 10:12:01`. The year is assumed to be the current one,
  or the previous one if that would put the date in the future.
- `rfc3339`: `2026-11-08T10:12:01.123+01:00`.
- A [Go time layout](https://pkg.go.dev/time#pkg-constants), for example
  `"02/Jan/2006:15:04:05 -0700"` for Apache and nginx logs.

Lines that do not match the regexp are kept as events with a `parse_error`
field. The first 10 are logged; with `-v -v`, all of them are.

Log rotation (rename or copytruncate) is handled while following, and also
while wolverine is stopped (see [State file](#state-file)).

#### `systemd-service`: a service's entries in the systemd journal

```yaml
- id: sshd-journal
  type: systemd-service
  unit: sshd               # same as sshd.service
  follow: true
  start_at: end
  regexp: '^Failed (?P<auth_method>\S+) for'   # optional
```

No regexp is needed: the fields come from the journal.

| Event field | From |
|---|---|
| time | the journal timestamp (exact, with the year) |
| `Hostname` | `_HOSTNAME` |
| `Service` | `SYSLOG_IDENTIFIER`, e.g. `sshd-session` (or `_COMM`) |
| `Severity` and `Fields.facility` | `PRIORITY`, `SYSLOG_FACILITY` |
| `Fields.pid`, `Fields.unit` | `SYSLOG_PID` (or `_PID`), `_SYSTEMD_UNIT` |

The optional `regexp` is applied to the message only, to extract more
fields. A message that does not match it is not an error.

Only the entries written by the unit itself are read, using
`_SYSTEMD_UNIT`, a field that journald sets and processes cannot forge. A
log file is different: any local user can write a fake sshd line to
`/var/log/messages` with `logger -t sshd`.

Reading the system journal requires root or membership in the
`systemd-journal`, `adm` or `wheel` group. Otherwise the source sees no
entries; with `-v`, wolverine says so.

> Do not read the same messages twice, for example sshd from both the journal
> and a log file that rsyslog also writes them to: every attempt would be
> counted twice.

#### Enrichment

Events whose service is `sshd` or `sshd-*` (e.g. `sshd-session`) get these
fields from the message:

- `Username`, `SourceIP` and `Fields.source_port`
- `Fields.auth_method`, e.g. `password` or `publickey`
- `Fields.invalid_user`
- `Category: authentication`
- `Action`: `login`, `session_open`, `session_close`, `connect` or
  `disconnect`
- `Status`: `success`, `failure` or `denied`

This applies to every source.

### Rules

```yaml
rules:
  - id: ssh-failed-logins-per-ip
    type: threshold
    description: Repeated failed SSH logins from the same IP
    severity: high
    match:
      category: authentication
      action: login
      status: failure
      has_fields: [auth_method]
    group_by: SourceIP
    count: 5
    window: 5m
    suppress: 1h
    actions: [email-admin, block-ip, slack]
```

`threshold` is the only rule type. It raises an alert when `count` matching
events with the same `group_by` value occur within `window`:

- **`match`**: every condition given must hold. `category`, `service`,
  `action` and `status` must be equal to the event's. `has_fields` lists
  `Fields` keys that must be present.
- **`group_by`**: an event field (`SourceIP`, `Username`, `Hostname`,
  `Service`, `Source`...) or a key of `Fields`. Events without a value are
  ignored.
- **Event time:** the window uses the event timestamps, not the clock, so
  replaying an old log gives the same alerts.
- **After an alert,** the counter of that group restarts from zero.
- **`suppress`**: no new alert for the same group during that time (`0`:
  no suppression).
- **`actions`**: the ids of the actions to run.

The example rule only counts `Failed <method> for ...` messages, which are
the ones with an `auth_method`. sshd also logs `Invalid user` and pam_unix
lines for the same attempt, and counting those would count each attempt two
or three times.

Alerts are written to stdout as JSON:

```json
{"ID":"…","RuleID":"ssh-failed-logins-per-ip","Severity":"high","Message":"Repeated failed SSH logins from the same IP: 5 events for SourceIP=203.0.113.7 within 1m12s","Events":[…],"Metadata":{"value":"203.0.113.7","count":5,"group_by":"SourceIP","window":"5m0s"}}
```

### Actions

Actions run in the background, so a slow SMTP server does not delay
detection.

**Secrets stay out of the file.** Settings ending in `_env` name an
environment variable that holds the value. If the variable is not set,
wolverine refuses to start. When running as a service, put the variables in
`/etc/wolverine/wolverine.env`.

#### `email`

```yaml
- id: email-admin
  type: email
  smtp:
    host: smtp.example.com
    port: 587                 # default 25; STARTTLS is used when offered
    username: wolverine       # optional
    password_env: WOLVERINE_SMTP_PASSWORD
    timeout: 30s              # default
  from: wolverine@example.com
  to: [admin@example.com]
  max_events: 20              # log lines included in the mail
```

#### `ssh`: run a command on a remote host

```yaml
- id: block-ip
  type: ssh
  ssh:
    host: firewall.example.com
    port: 22
    user: wolverine
    identity_file: /etc/wolverine/id_ed25519
    timeout: 30s              # default
  command: sudo ipset add wolverine-blocklist {{.SourceIP}} -exist
```

- **The ssh client** is the system one, in batch mode, so it never prompts.
  The key must not have a passphrase. The host key must already be in
  `known_hosts`.
- **Template variables** in `command`:

  | Variable | Value |
  |---|---|
  | `{{.SourceIP}}`, `{{.Username}}`, `{{.Hostname}}` | from the last event of the alert |
  | `{{.Value}}` | the `group_by` value |
  | `{{.AlertID}}`, `{{.RuleID}}`, `{{.Severity}}` | from the alert |

- **Quoting:** values are shell-quoted automatically, so do not put quotes
  around them. Log contents cannot inject commands.
- **Empty values:** if a variable used in the command is empty, the action
  fails instead of running a broken command.
- **Allowlist:** alerts involving an allowlisted IP are skipped.

#### `webhook`: HTTP POST

```yaml
- id: webhook
  type: webhook
  webhook:
    url: https://hooks.example.com/wolverine   # or url_env: VARIABLE
    headers: {X-Source: wolverine}
    headers_env: {Authorization: WOLVERINE_WEBHOOK_TOKEN}
    timeout: 10s              # default
    retries: 2
  max_events: 20
  use_allowlist: false        # true if this webhook blocks IPs
```

- **Body:** the alert as JSON, by default.
- **Retries:** network errors, 429 and 5xx answers are retried with
  exponential backoff.
- **Secret URLs:** use `url_env` when the URL itself is the secret (Slack,
  Teams...). Webhook URLs are never written to the logs.

For a custom body such as a Slack message, write a `body` template:

```yaml
- id: slack
  type: webhook
  webhook:
    url_env: WOLVERINE_SLACK_WEBHOOK_URL
    escape: slack
    body: |
      {"text": ":rotating_light: *[{{.SeverityUpper}}] {{.Message}}*\n```{{range .Events}}{{.}}\n{{end}}```"}
  max_events: 10
```

- **Template variables:**
  - From the alert: `AlertID`, `RuleID`, `Severity`, `SeverityUpper`,
    `Message`, `Time`, `Value`.
  - From its last event: `SourceIP`, `Username`, `Hostname`.
  - About its events: `Count`; `Events`, the log lines (at most
    `max_events`); and `MoreEvents`, the number of lines left out.
- **Escaping:** values are escaped to go inside JSON strings.
  `escape: slack` also neutralises Slack's `<links>`, `<!channel>` and `&`.
- **Startup check:** wolverine renders the template with sample values when
  it starts and refuses an invalid JSON result.

### Allowlist

```yaml
allowlist:
  - 127.0.0.0/8
  - ::1
  - 192.168.1.0/24
```

IP addresses and CIDR ranges that must never be blocked: your admin
workstations, monitoring hosts, gateways...

- **Actions skipped:** `ssh` actions, and `webhook` actions with
  `use_allowlist: true`, are skipped for alerts involving these addresses.
- **Still raised:** the alert itself, and the email and notification
  webhooks, so you still see the problem.

### State file

```yaml
state_file: /var/lib/wolverine/state.json
```

Without a state file, every start follows `start_at`, so a restart either
reads everything again or skips what was written while wolverine was
stopped. With one, wolverine saves the position of every source and a
restart resumes after the last line or entry processed:

- **Log files** are identified by inode and a checksum of their first 1 KB.
  If a file was rotated while wolverine was stopped, wolverine finishes the
  rotated file (`messages-20261108`, `messages.1`), then reads the new one.
  If the old file is gone (compressed, deleted) or was truncated, the current
  file is read from the beginning.
- **Journal sources** resume after the cursor of the last entry processed.

When positions are saved:

- A position is recorded only once its event has been processed.
- The file is written every 5 seconds and when wolverine stops.
- After a crash, at most the last few seconds are read again.

A corrupt state file stops wolverine at startup: delete it to start over
from `start_at`.

The `-state FILE` option overrides `state_file`, for example to keep a
separate state for a test run. `-state none` disables it for one run.

## Install as a service

```bash
make                        # as yourself: sudo does not need Go
sudo make install
```

This installs:

| File | |
|---|---|
| `/usr/local/bin/wolverine` | the binary |
| `/etc/wolverine/wolverine.yaml` | the configuration. If it already exists, it is kept and the new one is written as `wolverine.yaml.new` |
| `/etc/wolverine/wolverine.env` | the secrets (`*_env` variables), mode 0600. Only created if missing |
| `/etc/systemd/system/wolverine.service` | the systemd unit |
| `/usr/lib/sysusers.d/wolverine.conf` | creates the `wolverine` system user |

`PREFIX` (default `/usr/local`) and `SYSCONFDIR` (default `/etc`) change the
locations. `DESTDIR` installs into a staging directory for packaging, without
touching the system.

Then:

1. **Edit `/etc/wolverine/wolverine.yaml`.**
   - Every source must have `follow: true`; otherwise wolverine reads once
     and the service stops.
   - For the first start, use `start_at: end`. Otherwise all the existing
     history is read, and the actions run for old attacks.
2. **Put the secrets in `/etc/wolverine/wolverine.env`**, if the
   configuration uses any.
3. **For the `ssh` action,** set up the key and the remote host's key as
   the `wolverine` user:

   ```bash
   sudo install -d -o wolverine -g wolverine -m 700 /var/lib/wolverine /var/lib/wolverine/.ssh
   sudo -u wolverine ssh-keygen -t ed25519 -N '' -f /var/lib/wolverine/.ssh/id_ed25519
   sudo -u wolverine sh -c 'ssh-keyscan firewall.example.com >> /var/lib/wolverine/.ssh/known_hosts'
   ```

   Set `identity_file: /var/lib/wolverine/.ssh/id_ed25519` in the
   configuration. Check the scanned host key before trusting it.
4. **Start the service:**

   ```bash
   sudo systemctl enable --now wolverine
   journalctl -u wolverine -f        # logs and alerts
   ```

What the service can do:

- **User:** it runs as the `wolverine` user, not as root.
- **Reading:**
  - The `systemd-journal` group gives access to the journal.
  - The `CAP_DAC_READ_SEARCH` capability lets it read root-only log files
    such as `/var/log/messages`. If you would rather give the `wolverine`
    user access to those files yourself (ACL, group), remove the two
    `Capabilit…` lines from the unit.
- **Writing:** only `/var/lib/wolverine` (the state file and `.ssh`).
- **Hardening:**
  - The rest of the system is read-only.
  - `/home` and `/tmp` are hidden.
  - System calls are filtered.
  - Only IP and local sockets are allowed.

After changing the configuration: `sudo systemctl restart wolverine`.

To uninstall:

```bash
sudo make uninstall
```

This stops the service and removes the binary, the unit and the sysusers
file. It keeps `/etc/wolverine`, `/var/lib/wolverine` and the `wolverine`
user.

## Project layout

```
cmd/wolverine/            main: flags, signals
config/wolverine.yaml     example configuration
deploy/systemd/           unit, sysusers file, example secrets file
internal/
  config/                 configuration file
  engine/                 builds the pipeline from the configuration and runs it
  event/                  Event and Alert
  source/                 Source interface
    syslog/               "logfile" source and its regexp parser
    systemd/              "systemd-service" source (sd-journal)
  parser/                 Parser interface, event field helpers
  processor/enrichment/   sshd enrichment
  detection/              rules (threshold)
  action/                 dispatcher, allowlist, email, ssh, webhook
  state/                  state file (positions of the sources)
  verbose/                -v / -v -v logging
```
