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
  - [Configuration directory](#configuration-directory)
  - [Variables](#variables)
  - [Sources](#sources)
  - [Rules](#rules)
  - [Actions](#actions)
    - [Undoing an action](#undoing-an-action)
  - [Exclude lists](#exclude-lists)
  - [`exclude_if` conditions](#exclude_if-conditions)
  - [State file](#state-file)
  - [Maximum lifetime](#maximum-lifetime)
- [Web server, API and dashboard](#web-server-api-and-dashboard)
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
| `-http ADDRESS` | run the [web server](#web-server-api-and-dashboard) (REST API and dashboard) on ADDRESS, e.g. `127.0.0.1:8080`; overrides `http.listen`. `-http none` disables it |
| `-max-lifetime DURATION` | how long the data memorized by the rules and the alerts raised are kept, e.g. `12h`; overrides `max_lifetime` (default `24h`). See [maximum lifetime](#maximum-lifetime) |
| `-events FILE` | append every event, after parsing and enrichment, as a JSON line to FILE (`-` for stdout) |
| `-detailed-events` | include in the alerts written to stdout the events (log lines) that raised them |
| `-minimal-events` | include in the alerts written to stdout only the last event, the one that raised them |
| `-v` | describe the configuration and what wolverine does (alerts, actions run, log rotations...) |
| `-v -v` or `-vv` | debugging details: rule counters per IP, every unparsed line, each action started... |

- **stdout** receives the alerts, one JSON object per line. They do not
  include the log lines that raised them, unless `-minimal-events` (the
  last one) or `-detailed-events` (all of them) is given.
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
max_lifetime:  24h       # how long rule data and alerts are kept in memory
http:          {...}     # embedded web server: REST API and dashboard
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
  wolverine.yaml          main file: state_file, max_lifetime, include_dir, shared actions...
  rules.d/
    10-ssh.yaml           rules, sources, actions or exclude lists
    20-web.yaml
```

- **Merging:** the `exclude_lists`, `sources`, `actions` and `rules` of
  each file are added to those already read. A rule can use an action or an
  exclude list defined in another file, and a list can include a list of
  another file.
- **Unique ids:** an id used twice is an error that names both files.
- **Main file only:** `state_file`, `max_lifetime`, `http` and
  `include_dir` can only be set in the main file.
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

### Variables

The `variables` section of a file names values that several sources,
actions or rules share. Write `${name}` to use one:

```yaml
variables:
  logdir: /var/log/app
  threshold: 5
  admins: [192.0.2.10, 192.0.2.11]
  waf_aws:
    region: eu-west-3
    profile: wolverine
  description: more than ${threshold} failures   # a variable may use others

exclude_lists:
  - id: admins
    entries: ${admins}                      # a list

actions:
  - id: waf-block
    type: aws-waf-ipset
    ipset: {name: blocklist}
    aws: ${waf_aws}                         # a mapping

rules:
  - id: brute-force
    count: ${threshold}                     # a number
    description: ${description} in 10 min   # inside text
```

- **Alone** as a value, `${name}` is replaced by the variable's value,
  whatever its type: a number, a duration, a list or a mapping.
- **Inside text**, `${name}` is replaced by the variable's text: the
  variable must then be a single value, not a list or a mapping.
  `"${threshold}0"` gives 50.
- **Scope:** the variables of the main file can be used in every file.
  Those of an included file can only be used in that file, and cannot
  redefine a variable of the main file.
- **Errors:** an undefined variable, or one that refers to itself, is an
  error that gives the file and the line.
- **Date macros:** `year`, `month`, `day`, `hour`, `minute` and `second` are
  the [date macros of a path](#logfile-log-files) (`${day-1}`...), not
  variables: they are left for the path, and cannot be variable names.
  `path: ${logdir}/app.log.${year}-${month}-${day}` uses both.
- **Escape:** `$${` gives a literal `${`.
- **Only values:** the keys (`count:`, `rules:`...) are not replaced.
- **Secrets:** keep them in environment variables, with the `*_env`
  settings, not in variables.

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
| `date` and `time` | the event time when there is no `timestamp` (or it is empty): see below. Also stored in `Fields` |
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

Some logs give the date and the time in two columns instead of a timestamp,
such as the CloudFront and the W3C (IIS) logs. When the `timestamp` group is
missing or empty, and the `date` and `time` groups are both set, they are
joined by a space (`2026-11-08 10:12:01`) and parsed with
`timestamp_formats`, then with the built-in layouts `2006-01-02 15:04:05` and
`2006-01-02 15:04:05Z07:00` (a fractional second is accepted). So an ISO date
and time need no `timestamp_formats`; another format needs a layout for the
joined value, such as `"01/02/2006 15:04"`:

```yaml
- id: cloudfront
  type: aws-s3
  # ...
  skip_lines: 2       # the #Version and #Fields lines
  regexp: '^(?P<date>\S+)\t(?P<time>\S+)\t\S+\t\S+\t(?P<source_ip>\S+)\t(?P<method>\S+)\t\S+\t(?P<path>\S+)\t(?P<status>\d+)'
  timezone: UTC       # CloudFront writes UTC times
```

Lines that do not match the regexp are kept as events with a `parse_error`
field. The first 10 are logged; with `-v -v`, all of them are.

Every event gets the name of the file it comes from in `Fields.file`.

**`skip_lines`** ignores that many lines at the beginning of each file, for
files that start with a header, such as the column names of a CSV file or
the `#Version` and `#Fields` lines of a W3C log:

```yaml
- id: access-csv
  type: logfile
  path: /var/log/app/access.csv
  skip_lines: 1             # the line "date,ip,user,status"
  regexp: '^(?P<timestamp>[^,]+),(?P<source_ip>[^,]+),(?P<username>[^,]*),(?P<status>\d+)$'
```

- **Each file:** with `directory`, every file has its header skipped,
  compressed ones too.
- **Wherever the reading starts:** after a restart, the lines are counted
  from the beginning of the file, so the header is skipped even when the
  saved position is in it, and no line after it is skipped. Likewise with
  `start_at: end`.
- **Truncated file:** a file truncated and rewritten (copytruncate) has its
  new header skipped.
- **Not counted:** the skipped lines are neither events nor unparsed lines
  in the counters. With `-v -v`, each is logged.

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
   `timezone`, `category` and `skip_lines` too, the latter for each object).
   `Fields.file` is `s3://bucket/key`;
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
- **`window` and `suppress`** must not exceed the
  [maximum lifetime](#maximum-lifetime).
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
raised the alert, with their log lines (`Raw`) and fields. With
`-minimal-events`, the array only holds the last event, the one that made
the count reach the threshold. The two options cannot be used together. The actions
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
- **Temporary blocks:** see [undoing an action](#undoing-an-action).

#### `aws-waf-ipset`: block an address in AWS WAF

Adds the source IP address of the alert to an AWS WAF (v2) IP set, or
removes it. A web ACL rule that blocks the addresses of the IP set then
blocks the attacker in front of a load balancer, an API Gateway or a
CloudFront distribution.

```yaml
- id: waf-block
  type: aws-waf-ipset
  ipset:
    name: wolverine-blocklist
    id: 1a2b3c4d-5678-90ab-cdef-111122223333   # optional: looked up by name
    scope: REGIONAL            # default; CLOUDFRONT for CloudFront
  aws:                         # as for an aws-s3 source
    region: eu-west-3
    profile: wolverine
    credentials_file: /etc/wolverine/aws/credentials
  undo:
    after: 1h
    actions: [waf-unblock]

- id: waf-unblock
  type: aws-waf-ipset
  ipset:
    name: wolverine-blocklist
    operation: remove
  aws:
    region: eu-west-3
    access_key_id_env: WOLVERINE_WAF_KEY_ID          # keys in environment variables
    secret_access_key_env: WOLVERINE_WAF_SECRET_KEY
```

| Setting | Meaning |
|---|---|
| `ipset.name` | the name of the IP set (required) |
| `ipset.id` | its id. Without it, the IP set is looked up by name the first time the action runs |
| `ipset.scope` | `REGIONAL` (default) or `CLOUDFRONT`. CloudFront IP sets are in `us-east-1`, used when `aws.region` is not set |
| `ipset.operation` | `add` (default) or `remove` |
| `ipset.field` | the event field holding the address, in the last event of the alert (default `SourceIP`), e.g. a `client_ip` group behind a proxy |
| `ipset.timeout` | for the calls to AWS (default `30s`) |

**Credentials and region**, per action, in `aws`: the same settings as for
an [`aws-s3` source](#aws-s3-log-files-written-to-an-s3-bucket).

| Setting | Credentials used |
|---|---|
| `access_key_id_env`, `secret_access_key_env` (and `session_token_env`) | the keys in these environment variables |
| `profile`, `credentials_file`, `config_file` | a profile of the shared credentials and config files (default `~/.aws/credentials` and `~/.aws/config`, default profile `default`) |
| none of them | the AWS SDK's defaults: the `AWS_*` variables, then the default profile of `~/.aws`, then the role of the EC2 instance or ECS task |

- **Region:** `aws.region`, else the one of the profile or `AWS_REGION`. It
  is required, except with `scope: CLOUDFRONT` (always `us-east-1`).
- **Endpoint:** `aws.endpoint_url` replaces the AWS endpoint, e.g. for tests.
- **Per action:** each action has its own `aws` settings, independent of
  those of the sources and of the other actions.

- **Undo:** to unblock an address after some time, give the blocking
  action an [`undo`](#undoing-an-action) that runs an `aws-waf-ipset`
  action with `operation: remove` on the same IP set, as above.
- **Addresses:** the address is added as `192.0.2.7/32` (IPv4) or
  `2001:db8::1/128` (IPv6). An IP set holds one IP version: an address of
  the other one makes the action fail. A value that is not an IP address
  fails too, and nothing is changed.
- **Idempotent:** adding an address already in the set, or removing one that
  is not in it, changes nothing. `remove` only removes that exact address,
  not a range that contains it.
- **Concurrent changes:** the IP set is read, then written with its lock
  token. If it changed meanwhile (another action, the console), it is read
  and written again, up to 5 times. Its description is kept.
- **Limits:** an IP set holds at most 10,000 addresses: when it is full,
  the action fails. AWS WAF takes from a few seconds to a minute to apply a
  change everywhere.
- **Protecting addresses:** as for `ssh`, give the rules that block an
  `exclude` list of the addresses that must never be blocked.

The IAM policy needs `wafv2:GetIPSet` and `wafv2:UpdateIPSet` on the IP
set, and `wafv2:ListIPSets` if `id` is not set:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
     "Resource": "arn:aws:wafv2:eu-west-3:123456789012:regional/ipset/wolverine-blocklist/*"},
    {"Effect": "Allow", "Action": "wafv2:ListIPSets", "Resource": "*"}
  ]
}
```

#### Undoing an action

An action can last for some time only: `undo` runs other actions that long
after it succeeded, for example to unblock an IP address an hour after
blocking it.

```yaml
- id: block-ip
  type: ssh
  ssh: {host: firewall.example.com, user: wolverine}
  command: sudo ipset add wolverine-blocklist {{.SourceIP}} -exist
  undo:
    after: 1h
    actions: [unblock-ip]

- id: unblock-ip
  type: ssh
  ssh: {host: firewall.example.com, user: wolverine}
  command: sudo ipset del wolverine-blocklist {{.SourceIP}} -exist
```

- **Same alert:** the undo actions get the alert of the action they undo,
  so they have the same template variables (`{{.SourceIP}}`...). Its
  `Metadata` also has `undo_of`, the id of the action undone, for emails and
  webhooks. Any type of action can undo another one, and several actions
  can be listed, e.g. `[unblock-ip, email-admin]`.
- **Only what succeeded** is undone. The undo actions do not need to be in
  the `actions` of a rule.
- **Repeated alerts:** when the action runs again for the same rule and
  `group_by` value (the same IP blocked again), its undo is postponed: the
  block lasts `after` from the last time.
- **Failures:** an undo action that fails is tried again every minute, up to
  5 times. The undo actions that succeeded are not run again.
- **Restarts:** the undos not run yet are saved in the
  [state file](#state-file). Those that came due while wolverine was stopped
  run as soon as it starts. Without a state file they are lost, and
  wolverine warns about it at startup.
- **Stopping:** the undos due run before wolverine exits. With sources that
  are read once (`follow: false`), the others wait for the next run.
- **Checks at startup:** the undo actions must exist, be enabled when the
  action is, differ from it, and not have an `undo` themselves.

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
- **Actions to undo** (see [undoing an action](#undoing-an-action)): those
  not run yet, with their due time.

The state file also holds, within the
[maximum lifetime](#maximum-lifetime), the data of the rules (the events
each threshold rule counts, its suppressions) and the alerts raised, with
their events, so that a restart gets them back:

- What was memorized longer ago is dropped at startup and the next save.
- A rule's data is only restored if the rule still counts the same events:
  when its `match`, `exclude`, `exclude_if` or `group_by` changed, it starts
  from zero (`-v` says so). Changing `count`, `window`, `suppress` or
  `actions` keeps it.
- The data of a rule removed or disabled is dropped.

When positions are saved:

- A position is recorded only once its event has been processed.
- The file is written every 5 seconds and when wolverine stops.
- After a crash, at most the last few seconds are read again.

A corrupt state file stops wolverine at startup: delete it to start over
from `start_at`.

The `-state FILE` option overrides `state_file`, for example to keep a
separate state for a test run. `-state none` disables it for one run.

### Maximum lifetime

```yaml
max_lifetime: 24h
```

To evaluate the rules, wolverine keeps data in memory:

- the events a threshold rule counts, per `group_by` value;
- the suppressions: when the last alert of each group was raised;
- the alerts raised, with their rule and events.

None of this is kept longer than `max_lifetime`, measured on the clock from
the moment it was memorized. Every tenth of the lifetime (at least every
second, at most every minute), what is older is flushed, even if no new
event comes. A flushed event no longer counts toward a threshold, and a
flushed suppression no longer silences its group.

- **Default:** `24h`. The `-max-lifetime` option overrides it, e.g.
  `-max-lifetime 2h`.
- **Rules:** the `window` and `suppress` of every enabled rule must not
  exceed the lifetime, or wolverine refuses to start.
- **Event time:** windows still use the event timestamps. The lifetime only
  adds a limit on the clock: an event leaves the window when it is too old
  for it, or when it has been memorized for `max_lifetime`, whichever comes
  first.
- **Restart:** all of it is saved in the [state file](#state-file), if
  there is one, and restored at startup with the time it was memorized, so
  its lifetime spans restarts: the events counted before a restart still
  count toward the threshold, and a suppression still applies.

`-v -v` logs what is flushed.

## Web server, API and dashboard

```yaml
http:
  listen: 127.0.0.1:8080
  token_env: WOLVERINE_HTTP_TOKEN   # optional
```

With `http.listen` (or `-http 127.0.0.1:8080`), wolverine serves a REST API
and a dashboard at `http://127.0.0.1:8080/`. Without it, there is no web
server.

- **Token:** with `token_env`, the API requires
  `Authorization: Bearer <token>`, the value of that environment variable.
  The dashboard asks for it and keeps it in the browser. Without a token,
  anyone who can reach the port sees the alerts and the log lines in them:
  wolverine warns when it listens on another address than localhost without
  a token.
- **HTTPS:** wolverine serves plain HTTP. To expose it, put it behind a
  reverse proxy that handles TLS (nginx, Caddy...).
- **Sources read once:** when all sources have been read (`follow: false`),
  wolverine keeps serving until it is stopped (Ctrl-C), so the results of a
  replayed log can be explored.

### Counters

Wolverine counts, per source and per rule:

| Counter | Meaning |
|---|---|
| `lines` | lines (or journal entries, S3 lines) read, empty ones included |
| `events` | lines the source's regexp parsed |
| `unparsed` | lines the regexp did not parse (still processed, with their raw text) |
| `excluded` | events dropped by the source's `exclude` or `exclude_if` |
| `matches` | events a rule matched: counted toward its threshold |
| `alerts` | alerts a rule raised |

- **Time:** counters are kept by minute of processing (the clock), not by
  the timestamp of the log lines. A replayed old log is counted when it is
  read.
- **Retention:** the minutes older than `max_lifetime` are dropped. The
  totals since the start are kept apart. Counters are not saved in the state
  file: they restart from zero with wolverine.

### REST API

Every endpoint is a `GET` and returns JSON. Times are given as RFC 3339
(`2026-11-13T10:00:00Z`), Unix seconds, `now`, or relative to now (`-15m`,
`now-1h`). Errors are `{"error": "..."}` with a 4xx status.

| Endpoint | Returns |
|---|---|
| `/api/v1/info` | the sources and enabled rules, the start time, `max_lifetime` |
| `/api/v1/stats` | totals since the start |
| `/api/v1/stats?from=-1h&to=now` | totals of an interval (`to` defaults to now) |
| `/api/v1/stats/series?from=-6h&step=5m` | counters by time bucket |
| `/api/v1/alerts?from=-1h&rule=ssh-failed-logins-per-ip&limit=50` | alerts, newest first, with their action logs |
| `/api/v1/alerts/ID` | one alert, with all its events and its action log |
| `/api/v1/alerts/watch` | new alerts and what their actions do, in real time (server-sent events) |
| `/healthz` | `ok` (no token needed) |

**`/stats`** gives `totals`, `sources` (by id) and `rules` (by id).

- An interval counts the minutes that start in `[from, to)`: `from` is
  rounded down to the minute.
- `available_since` is the start of the oldest minute kept. An interval that
  starts before it only has partial counts.

```console
$ curl -s 'localhost:8080/api/v1/stats?from=-1h'
{"from":"…","to":"…","since_start":false,"available_since":"…",
 "totals":{"lines":5120,"events":5087,"unparsed":33,"excluded":12,"matches":341,"alerts":4},
 "sources":{"ssh":{"lines":5120,"events":5087,"unparsed":33,"excluded":12}},
 "rules":{"ssh-failed-logins-per-ip":{"matches":341,"alerts":4}}}
```

**`/stats/series`** gives `buckets`: one per `step`, each with its `start`
and the same `totals`, `sources` and `rules`.

- Empty buckets are included.
- `from` defaults to `-1h`. `from` is rounded down to the step.
- `step` is a multiple of a minute, e.g. `1m` or `1h`. By default it gives
  about 120 buckets. A series has at most 2000 buckets.

**`/alerts`** gives the alerts kept within `max_lifetime`, newest first:
`{"total": N, "alerts": [...]}`.

| Parameter | Meaning |
|---|---|
| `from`, `to` | on when the alert was raised (`Raised`), like the counters |
| `rule`, `severity` | only those; several values separated by commas |
| `undo=pending` | only the alerts with an undo not run yet, whatever their age |
| `limit` | at most that many alerts (default 100, at most 10000); `total` counts them all |
| `events` | `last` (default): the last event of each alert; `all`; `none` |

An alert has two times: `Raised`, when wolverine raised it, and
`Timestamp`, the time of its last event as read from the log (older for a
log read late, such as files downloaded from S3).

An alert whose undo is not run yet has `Undo`: the action undone
(`Action`), the undo actions left (`Actions`), when they run (`Due`), and
the failed attempts (`Attempts`). These alerts are kept in the state file
with their undos, so they are still listed after a restart. If the undo
runs after more than `max_lifetime`, the alert is no longer kept, but
`undo=pending` still lists it, without `Raised` or action log.

Each alert has its **action log**, `Actions`: what happened to its actions,
in order, undo actions included. An entry has:

- `Time`, `Action` (the action id) and `Status`;
- `UndoOf`: for an undo action, the action it undoes;
- `Due`: when a planned undo runs, or when a failed one is tried again;
- `Duration`, in nanoseconds, of an action that ran;
- `Error` and `Detail`, if any.

| Status | Meaning |
|---|---|
| `ok` | the action ran and succeeded |
| `failed` | the action ran and failed (see `Error`); a failed undo action has the `Due` time of its next try, if any |
| `dropped` | not run: the queue of the actions was full |
| `planned` | the undo action runs at `Due` |
| `postponed` | the same thing was done again for a later alert: the undo runs after that one instead, at `Due` (see `Detail`) |
| `skipped` | the undo action will not run, as it is no longer configured |

```json
"Actions": [
  {"Time": "…T10:00:05Z", "Action": "waf-block", "Status": "ok", "Duration": 5000000},
  {"Time": "…T10:00:05Z", "Action": "waf-unblock", "UndoOf": "waf-block", "Status": "planned", "Due": "…T11:00:05Z"},
  {"Time": "…T10:00:05Z", "Action": "notify", "Status": "failed", "Error": "POST …: connection refused"},
  {"Time": "…T11:00:05Z", "Action": "waf-unblock", "UndoOf": "waf-block", "Status": "ok", "Duration": 4000000}
]
```

The action logs are kept with the alerts, within `max_lifetime`, and in the
state file. The undo of an alert that is no longer kept still runs, but is
not logged.

**`/alerts/ID`** gives one alert, with all its events (`events` as above
changes this), or a 404 if it is not kept (anymore) and has no undo
pending.

**`/alerts/watch`** streams the alerts as they are raised, and the entries
added to their action logs, as
[server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html).
It takes the `rule`, `severity` and `events` parameters of `/alerts`.

```console
$ curl -sN -H "Authorization: Bearer $TOKEN" 'localhost:8080/api/v1/alerts/watch?events=none'
retry: 3000
: connected

event: alert
id: 5b4c5279956def3f29b4c65a1c45e559
data: {"ID":"5b4c…","RuleID":"ssh-failed-logins-per-ip","Severity":"high","Message":"…","Metadata":{…},"Actions":[]}

event: action
data: {"AlertID":"5b4c…","RuleID":"ssh-failed-logins-per-ip","Time":"…","Action":"block-ip","Status":"ok","Duration":120000000}
```

- **Alerts and actions:** an `alert` event comes before the `action` events
  of that alert. An `action` event is an entry of the action log, with the
  `AlertID` and `RuleID` of its alert.

- **Heartbeat:** a `: heartbeat` comment comes every 15 seconds, so proxies
  keep the connection open.
- **End of stream:** the stream ends when wolverine stops, or if the client
  reads too slowly. Reconnect, and fetch `/alerts` for what was missed.
- **Limit:** at most 64 clients are served at once.

### Dashboard

The dashboard at `/` shows, for the range selected (5 minutes to 24
hours), refreshed every 10 s to 1 min:

- **Stat panels:** the six counters over the range and since the start.
- **Charts:** log lines (parsed and unparsed), alerts by rule, rule matches,
  and lines by source. Hover a chart, or focus it and use the arrow keys,
  for the values.
- **Tables:** the counters of each source and rule.
- **Alerts:** the alerts raised in the range, plus the older ones whose
  undo is still planned (what they did, such as a blocked address, is still
  in effect), then the new ones as they are raised. Each shows the latest
  status of its actions (undo actions included), updated live. Select one
  for its last log line, its event time and its action log.

It follows the system's light or dark mode; the Theme button switches it.
The dashboard is built into the binary and loads nothing from the Internet.

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
  action/                 dispatcher, undo scheduler, email, ssh, webhook, awswaf
  awsconf/                AWS credentials and region (aws-s3, aws-waf-ipset)
  state/                  state file (positions, rule data, alerts, undos)
  stats/                  counters by minute
  web/                    web server: REST API, dashboard (web/ui)
  verbose/                -v / -v -v logging
```
