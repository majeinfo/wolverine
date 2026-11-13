# Wolverine

Wolverine reads logs, turns each line into an event, finds suspicious
patterns and reacts to them: it sends an email, runs a command over ssh
(e.g. to block an IP on a firewall) or calls a webhook (Slack...).

```
sources ──> parser ──> enrichment ──> exclude lists ──> detection rules ──> actions
logfile     regexp     sshd: user,    source IP in      threshold:          email
journal     journal    IP, method...  trusted lists?    N events per IP     ssh command
aws-s3                                                  within a window     webhook / Slack
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
  - [Exclude lists](#exclude-lists)
  - [`exclude_if` conditions](#exclude_if-conditions)
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
| `-detailed-events` | include in the alerts written to stdout the events (log lines) that raised them |
| `-v` | describe the configuration and what wolverine does (alerts, actions run, log rotations...) |
| `-v -v` or `-vv` | debugging details: rule counters per IP, every unparsed line, each action started... |

- **stdout** receives the alerts, one JSON object per line. They do not
  include the log lines that raised them unless `-detailed-events` is
  given.
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

The configuration is a main YAML file with these sections:

```yaml
exclude_lists: [...]     # named lists of IPs that rules can ignore
state_file:    ...       # where the position of each source is saved
include_dir:   rules.d   # directory of additional configuration files
sources:       [...]     # where events come from
actions:       [...]     # what to do when an alert fires
rules:         [...]     # what to detect, and which actions to run
```

[`config/wolverine.yaml`](config/wolverine.yaml) is a complete, commented
example. Unknown keys are rejected, so a typo does not silently disable part
of a rule. Every exclude list, source, action and rule has an `id` and can be turned off
with `disabled: true`. Durations are written like `30s`, `5m` or `1h`.

### Configuration directory

The configuration can be split into several files. Every `*.yaml` and
`*.yml` file in `include_dir` is read after the main file, in lexical order
of the file names. Prefix the names with numbers to choose the order:
`10-ssh.yaml` is read before `20-web.yaml`.

```
/etc/wolverine/
  wolverine.yaml          main file: state_file, include_dir, shared actions...
  rules.d/
    10-ssh.yaml           rules, sources, actions or exclude lists
    20-web.yaml
```

- **Merging:** the `exclude_lists`, `sources`, `actions` and `rules` of
  each file are added to those already read. A rule can use an action or an
  exclude list defined in another file, and a list can include a list of
  another file.
- **Unique ids:** an id used twice is an error that names both files.
- **Main file only:** `state_file` and `include_dir` can only be set in the
  main file.
- **Location:** `include_dir` is relative to the main file's directory, or
  absolute.
  - Without `include_dir`, `rules.d` next to the main file is read if it
    exists.
  - When `include_dir` is set, the directory must exist.
  - `include_dir: ""` disables it.
- **Ignored:** subdirectories, hidden files (starting with `.`) and other
  extensions. To disable a file, rename it, for example to
  `20-web.yaml.disabled`.

With `-v`, wolverine lists the included files it read.

### Sources

Every source has an `id`, a `type`, `follow` and `start_at`:

- **`follow: true`** keeps reading new lines as they are written, like
  `tail -F` or `journalctl -f`.
- **`start_at`** is `beginning` (the default) or `end`. `end` reads only new
  lines and requires `follow: true`.

When the [state file](#state-file) knows a source, its saved position is used
instead of `start_at`.

Any source can also drop events before any rule sees them: `exclude` names
[exclude lists](#exclude-lists), and `exclude_if` is a
[condition](#exclude_if-conditions) on the event's fields.

#### `logfile`: log files

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

Every event gets the name of the file it comes from in `Fields.file`.

Instead of `path`, a source can read every file of a directory whose name
matches a regexp, for example the logs of all the virtual hosts of a web
server:

```yaml
- id: nginx
  type: logfile
  directory: /var/log/nginx
  filename_regexp: '^.*access\.log$'   # matched against the file name only
  follow: true
  regexp: '...'
```

- **Matching:** `filename_regexp` is a Go regexp matched against the file
  name, not the full path. Use `^` and `$` to match the whole name. The
  directory is not searched recursively. Subdirectories and non-regular
  files are ignored.
- **New files:** while following, files that appear later and match are
  read from their beginning.
- **Rotation:** files are tracked by inode, not by name.
  - A file renamed to another matching name (`access.log` ->
    `access.log-20261108`) is not read again.
  - A file renamed to a name that no longer matches, or deleted, is read to
    its end, then dropped. Its last lines come before those of the file that
    replaced it.
- **No matching file** at startup is not an error, unlike a missing `path`.

**Compressed files** (gzip and bzip2) are decompressed automatically. They
are recognized by their content, not their extension, with `path` as well
as with `filename_regexp`.

- **Read once:** a compressed file does not grow, so it is read to its end
  and then remembered as done. A restart does not decompress it again.
- **Rotated and compressed files are not read twice.** logrotate replaces
  `messages-20261108` with `messages-20261108.gz`, a new file with the same
  lines. When the first 1 KB of a compressed file, once decompressed, is
  the same as a file already read, it is that file:
  - if that file is still being read, the compressed copy is skipped;
  - otherwise reading continues in the compressed copy where that file
    stopped. This also works when the rotation and compression happened
    while wolverine was stopped, even if the compressed name does not match
    `filename_regexp`.
- **History:** to read older rotations once, let `filename_regexp` match
  them, for example `'^secure(-\d{8})?(\.gz)?$'` with
  `start_at: beginning`. With `start_at: end`, the compressed files present
  at the first run are skipped.
- **Other formats** (xz, zstd) are read as plain text: make sure
  `filename_regexp` does not match them.

Log rotation (rename or copytruncate) is handled while following, and also
while wolverine is stopped (see [State file](#state-file)).

##### Dated file names

For applications that write one file per day (or hour), `path` can name the
file after the date with macros in the file name:

```yaml
- id: app
  type: logfile
  path: /var/log/app/app.log.${year}-${month}-${day}
  follow: true
  regexp: '...'
```

- **Variables:** `${year}`, `${month}`, `${day}`, `${hour}`, `${minute}`,
  `${second}`, from the current date in the source's `timezone` (default:
  local time). The year has 4 digits, the others 2: `app.log.2026-11-09`.
- **Shifting the date:** `${day-1}` is yesterday, `${hour+1}` the next
  hour. A shift moves the whole date, and every macro of the path follows
  it. On March 1, `app.log.${year}-${month}-${day-1}` is
  `app.log.2026-02-28`, and on January 1 it is `app.log.2025-12-31`. A shift
  is written `name`, `name+N` or `name-N`, with N an integer. A variable can
  only be shifted by one amount in a path.
- **Expressions:** any other expression
  ([govaluate](https://github.com/Knetic/govaluate) syntax) is computed from
  the shifted date: `${year%100}` gives `26`, `${hour - hour%6}` gives `00`,
  `06`, `12` or `18`, and `${day > 15 ? 2 : 1}` gives `01` or `02`. The
  arithmetic is done on decimal numbers, so `${hour/6}` at 13:00 is 2.17;
  the result is rounded down and written with at least 2 digits (`02`).
- **Which file:** the one named after the current date. When the date
  changes, the previous file is read to its end, then the new one from its
  beginning, as soon as it exists. A missing file is not an error.
  Files named after other dates are not read.
- **Directory:** the macros are only allowed in the file name, not in the
  directories of `path`.
- **Example:** to process yesterday's complete file once a day, from cron,
  use `path: /var/log/app/app.log.${year}-${month}-${day-1}` with
  `follow: false`. With the state file, a file already read is not read
  again.

#### `aws-s3`: log files written to an S3 bucket

For logs delivered to S3: load balancer and CloudFront access logs, VPC
flow logs, S3 server access logs, or files your applications upload.

```yaml
- id: alb
  type: aws-s3
  queue_url: https://sqs.eu-west-3.amazonaws.com/123456789012/alb-logs
  key_regexp: '\.log\.gz$'      # optional: only these objects
  follow: true
  visibility_timeout: 5m          # default
  aws:
    access_key_id_env: WOLVERINE_ALB_AWS_KEY_ID
    secret_access_key_env: WOLVERINE_ALB_AWS_SECRET
  regexp: '...'
  timestamp_formats: [rfc3339]
  category: web
```

The bucket notifies an SQS queue of each new object. For each notification,
wolverine:

1. downloads the object;
2. decompresses it if it is gzip or bzip2, recognized by its content;
3. parses its lines with `regexp`, like a `logfile` source (`timestamp_formats`,
   `timezone` and `category` too). `Fields.file` is `s3://bucket/key`;
4. deletes the message once every line has gone through the rules.

**Setting up AWS:**

- **Queue:** create an SQS queue in the bucket's region. Give it a
  dead-letter queue (redrive policy), so that a message that keeps failing
  stops coming back.
- **Notifications:** in the bucket's properties, send the "All object create
  events" to the queue (the queue's access policy must allow the bucket to
  send messages). Notifications delivered through SNS (without raw message
  delivery) or EventBridge are understood too.
- **Permissions** of the credentials wolverine uses:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow",
       "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"],
       "Resource": "arn:aws:sqs:eu-west-3:123456789012:alb-logs"},
      {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-log-bucket/*"}
    ]
  }
  ```

  Add `kms:Decrypt` on the key if the bucket is encrypted with SSE-KMS.

**Credentials and region**, per source, in `aws`:

| Setting | Credentials used |
|---|---|
| `access_key_id_env`, `secret_access_key_env` (and `session_token_env`) | the keys in these environment variables. Each source can have its own; a missing variable stops wolverine at startup |
| `profile`, `credentials_file`, `config_file` | a profile of the shared credentials and config files (default `~/.aws/credentials` and `~/.aws/config`, default profile `default`). `config_file` usually holds the region |
| none of them | the AWS SDK's defaults: the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` variables, then the default profile of `~/.aws`, then the role of the EC2 instance or ECS task |

The region is `aws.region`, else the one of the profile or `AWS_REGION`,
else the one in `queue_url`. `aws.endpoint_url` replaces the AWS endpoints,
for S3- and SQS-compatible services such as LocalStack or MinIO.

With `-v`, wolverine shows each source's region and where its credentials
come from, and checks at startup that the queue can be reached.

**Behavior:**

- **At least once.** A message is deleted only after all the lines of its
  file have been processed. If wolverine stops or crashes before, the
  message becomes visible again and the file is read again: its events
  can be counted twice. S3 itself may also notify an object twice, rarely.
- **One file at a time.** Messages are received one by one. While a file
  is read, the visibility timeout of its message is extended, so a long
  download is not handed to another reader. When wolverine stops in the
  middle of a file, its message is released right away for the next run.
- **`follow`:** with `follow: true`, wolverine waits for new notifications
  (SQS long polling). With `follow: false`, it stops when the queue is
  empty, which suits a run from cron. `start_at` does not apply: the queue
  holds what has not been read yet.
- **Errors:**
  - An object deleted since its notification is skipped.
  - Any other download error leaves the message in the queue: it is tried
    again after the visibility timeout.
  - A message that is not an S3 notification is logged and left in the
    queue: the dead-letter queue takes it after a few attempts.
  - Deletion notifications and S3's test event are deleted without
    downloading anything.
  - When the queue cannot be reached while following, wolverine retries,
    waiting up to a minute between attempts.
- **Line-oriented files only.** Files made of one JSON document, such as
  CloudTrail logs, are read as a single line.

When wolverine runs as a service, `~/.aws` is `/var/lib/wolverine/.aws`.
Put the keys in `/etc/wolverine/wolverine.env` (with `*_env` settings), or
in a credentials file readable by the `wolverine` user, for example
`/etc/wolverine/aws/credentials` owned by `root:wolverine` with mode 0640.

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
    exclude: [trusted]
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
- **`exclude`**: the ids of the [exclude lists](#exclude-lists) whose
  events the rule ignores.
- **`exclude_if`**: a [condition](#exclude_if-conditions); the rule ignores
  the events for which it is true.
- **`actions`**: the ids of the actions to run.

The example rule only counts `Failed <method> for ...` messages, which are
the ones with an `auth_method`. sshd also logs `Invalid user` and pam_unix
lines for the same attempt, and counting those would count each attempt two
or three times.

Alerts are written to stdout as JSON:

```json
{"ID":"…","RuleID":"ssh-failed-logins-per-ip","Timestamp":"…","Severity":"high","Message":"Repeated failed SSH logins from the same IP: 5 events for SourceIP=203.0.113.7 within 1m12s","Metadata":{"value":"203.0.113.7","count":5,"group_by":"SourceIP","window":"5m0s"}}
```

With `-detailed-events`, they also have an `Events` array: the events that
raised the alert, with their log lines (`Raw`) and fields. The actions
always get the events: emails and webhooks include up to `max_events` log
lines.

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
- **Protecting addresses:** give the rules that run a blocking action an
  `exclude` list of the addresses that must never be blocked (see
  [Exclude lists](#exclude-lists)).

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

### Exclude lists

```yaml
exclude_lists:
  - id: localhost
    description: the machine itself
    entries: [127.0.0.0/8, '::1']
  - id: admins
    entries:
      - 192.168.1.0/24
      - 2001:db8:1::/48
  - id: trusted
    description: addresses never blocked
    entries: [localhost, admins, 198.51.100.10]
  - id: internal-targets
    field: DestIP             # default: SourceIP
    entries: [10.0.0.0/8]

sources:
  - id: nginx
    exclude: [localhost]      # health checks: dropped for every rule
    ...

rules:
  - id: ssh-failed-logins-per-ip
    exclude: [trusted]
    ...
  - id: ssh-root-logins
    exclude: [localhost]      # admins still count here
    ...
```

Named lists of addresses to ignore, for a whole source or for some rules:
your admin workstations, monitoring hosts, gateways...

- **Entries:** IP addresses, CIDR ranges, or the id of another list, whose
  entries are added. A list may name a list defined after it, or in another
  file of the [configuration directory](#configuration-directory). A list
  that includes itself, directly or not, is an error. Quote IPv6 addresses
  inside `[...]`: `'::1'`.
- **Field:** `field` is the event field that holds the address to check:
  `SourceIP` (the default), `DestIP`, or a key of `Fields` set by a source's
  regexp (e.g. `client_ip` behind a proxy). The names are those of
  `group_by`. An event whose field is empty or not an IP address is not in
  the list. The entries of an included list are checked against the field
  of the list that includes it.
- **Per source:** a source's `exclude` names the lists whose events are
  dropped from it. No rule sees them, and `-events` does not print them.
  The count of dropped events is logged with the source's line count when
  wolverine stops.
- **Per rule:** a rule's `exclude` names the lists whose events it ignores.
  Excluded events are not counted, so they never raise an alert or run the
  rule's actions. The other rules still see them.
- **Which to use:** per source, for traffic you never want to analyze
  (health checks, your own scanners); per rule, when only some rules must
  ignore it (never block the admins, but still alert on their failures).
- **Pipeline:** after parsing and enrichment, a filter first drops the
  events that are in a list of their source. Then it checks the others
  against the lists that enabled rules use, each on its field, and records
  the lists they are in. With `-events FILE`, those appear in the event's
  `ExcludedBy`. With `-v -v`, both are logged.
- **Replaces `allowlist`:** earlier versions had a single `allowlist` that
  only stopped the `ssh` actions (and webhooks with `use_allowlist`). A
  configuration that still uses `allowlist` or `use_allowlist` is refused
  with a message pointing here. To keep the same protection, define a list
  and add it to the `exclude` of every rule that runs a blocking action.

### `exclude_if` conditions

`exclude_if` is an expression in [CEL](https://cel.dev) (Common Expression
Language), on a source or a rule:

- **Source:** the events of the source for which it is true are dropped,
  like those of its `exclude` lists. No rule sees them.
- **Rule:** the rule ignores the events for which it is true, like those of
  its `exclude` lists. Other rules still see them. The condition is only
  evaluated for the events that match the rule otherwise.

```yaml
sources:
  - id: nginx
    type: logfile
    path: /var/log/nginx/access.log
    regexp: '^(?P<source_ip>\S+) \S+ (?P<username>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<user_agent>[^"]*)"$'
    exclude: [localhost]
    exclude_if: >-
      in_list(source_ip, "scanners")
      || user_agent.matches("(?i)(curl|python-requests|bot)")
      || (path == "/health" && method == "GET")

rules:
  - id: ssh-failed-logins-per-ip
    exclude: [trusted]
    # The deploy account may fail from the CI runners; the rule
    # ignores those failures, other rules still count them.
    exclude_if: username == "deploy" && in_list(source_ip, "ci-runners")
    ...
```

- **Variables:**

  | Variable | Value |
  |---|---|
  | `source_ip`, `dest_ip`, `hostname`, `service`, `username`, `action`, `status`, `category`, `severity`, `message`, `raw`, `source` | the event fields, as strings (`""` when unset) |
  | `timestamp` | the event time: `timestamp.getHours() < 6` |
  | the other groups of the source's `regexp` (for a rule: of every enabled source's) | strings: `user_agent`, `method`, `path` above (`""` when the group did not match, or the event's source has no such group) |
  | `fields` | every other field, e.g. `fields.file`, `fields.auth_method` (sshd), `fields.pid` (journal) |

  A group whose name is not a valid identifier, or a CEL word such as `in`,
  is only in `fields`: `fields["in"]`.
- **Missing fields:** `fields.x` is an error when the event has no `x`.
  Test it with `has(fields.x)` or use `fields.?x.orValue("")`.
- **Functions:** CEL's standard ones (`matches` with RE2 syntax,
  `startsWith`, `endsWith`, `contains`, `in [...]`, `size`, comparisons,
  `&&`, `||`, `!`...), the
  [string extensions](https://pkg.go.dev/cel.dev/cel-go/ext#Strings)
  (`lowerAscii`, `split`, `substring`...), and `in_list(address, "list")`,
  which tells whether an address is in an [exclude list](#exclude-lists).
- **Checked at startup:** syntax, variable names, types (`status == 200` is
  an error: `status` is a string), regular expressions, and the lists
  named in `in_list`, which must be written in quotes. The expression must
  return `true` or `false`.
- **Errors while running** (a missing key of `fields`...) keep the event:
  wolverine would rather analyze an event too many. The first 10 errors of
  each condition are logged, all of them with `-v -v`.
- **YAML:** write the expression after `>-` to split it over several lines,
  or in single quotes on one line.

### State file

```yaml
state_file: /var/lib/wolverine/state.json
```

Without a state file, every start follows `start_at`, so a restart either
reads everything again or skips what was written while wolverine was
stopped. With one, wolverine saves the position of every source and a
restart resumes after the last line or entry processed:

- **Log files** have one position per file, identified by inode and a
  checksum of its first 1 KB.
  - If a file was rotated while wolverine was stopped, wolverine finishes the
    rotated file (`messages-20261108`, `messages.1`), then reads the new one.
  - If it was also compressed, wolverine finishes it from the compressed
    copy (see [compressed files](#logfile-log-files)).
  - If the old file is gone (deleted) or was truncated, the current file is
    read from the beginning.
  - Files that appeared while wolverine was stopped are read entirely:
    `start_at` only applies to the first run of a source.
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
| `/etc/wolverine/rules.d/` | the included configuration files from `config/rules.d/`, with the same rule: existing files are kept, new versions get a `.new` suffix |
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
  processor/filter/       exclude lists
  detection/              rules (threshold)
  action/                 dispatcher, email, ssh, webhook
  state/                  state file (positions of the sources)
  verbose/                -v / -v -v logging
```
