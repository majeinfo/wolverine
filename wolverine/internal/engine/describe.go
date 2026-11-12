package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/pathtemplate"
	"wolverine/internal/verbose"
)

// describe logs the configuration in verbose mode. It is called once the
// configuration has been validated.
func describe(cfg *config.Config) {
	if verbose.Level < 1 {
		return
	}
	if len(cfg.Files) > 1 {
		for _, f := range cfg.Files[1:] {
			verbose.Infof("included configuration file: %s", f)
		}
	} else {
		verbose.Infof("no included configuration file")
	}
	for _, s := range cfg.Sources {
		if s.Disabled {
			verbose.Infof("source %s: disabled", s.ID)
			continue
		}
		startAt := s.StartAt
		if startAt == "" {
			startAt = "beginning"
		}
		target := s.Path
		if pathtemplate.HasMacros(s.Path) {
			if tmpl, err := pathtemplate.Parse(s.Path); err == nil {
				if now, err := tmpl.Expand(time.Now().In(location(s))); err == nil {
					target = fmt.Sprintf("%s (now %s)", s.Path, now)
				}
			}
		}
		if s.Directory != "" {
			target = fmt.Sprintf("%s (files matching %s)", s.Directory, s.FilenameRegexp)
		}
		if s.Type == "aws-s3" {
			target = "queue " + s.QueueURL
			if s.KeyRegexp != "" {
				target += fmt.Sprintf(" (keys matching %s)", s.KeyRegexp)
			}
		}
		if s.Type == "systemd-service" {
			target = "unit " + systemdUnitName(s.Unit)
		}
		verbose.Infof("source %s: %s %s (follow: %v, start at %s)", s.ID, s.Type, target, s.Follow, startAt)
		if s.Regexp != "" {
			verbose.Infof("source %s: regexp groups: %s", s.ID, strings.Join(regexpGroups(s.Regexp), ", "))
			verbose.Debugf("source %s: regexp: %s", s.ID, s.Regexp)
		}
		if s.Type == "logfile" {
			formats := s.TimestampFormats
			if len(formats) == 0 {
				formats = defaultTimestampFormats
			}
			verbose.Debugf("source %s: timestamp formats: %s, timezone: %s",
				s.ID, strings.Join(formats, ", "), or(s.Timezone, "local"))
		}
		verbose.Debugf("source %s: category: %s", s.ID, or(s.Category, "system"))
		if len(s.Exclude) > 0 {
			verbose.Infof("source %s: exclude: %s", s.ID, strings.Join(s.Exclude, ", "))
		}
		if s.ExcludeIf != "" {
			verbose.Infof("source %s: exclude_if: %s", s.ID, s.ExcludeIf)
		}
	}

	verbose.Infof("processors: sshd, exclude")

	for _, l := range cfg.ExcludeLists {
		desc := ""
		if l.Description != "" {
			desc = " (" + l.Description + ")"
		}
		verbose.Infof("exclude list %s%s: %s in %s", l.ID, desc, or(l.Field, "SourceIP"), or(strings.Join(l.Entries, ", "), "nothing"))
	}

	for _, r := range cfg.Rules {
		if r.Disabled {
			verbose.Infof("rule %s: disabled", r.ID)
			continue
		}
		verbose.Infof("rule %s: %s, %d events per %s within %s (suppress: %s), exclude: %s, actions: %s",
			r.ID, r.Type, r.Count, r.GroupBy, r.Window, r.Suppress,
			or(strings.Join(r.Exclude, ", "), "none"), or(strings.Join(r.Actions, ", "), "none"))
		verbose.Debugf("rule %s: match %+v", r.ID, r.Match)
	}

	for _, a := range cfg.Actions {
		state := ""
		if a.Disabled {
			state = " (disabled)"
		}
		verbose.Infof("action %s: %s %s%s", a.ID, a.Type, actionTarget(a), state)
	}

	verbose.Infof("state file: %s", or(cfg.StateFile, "none (sources start from start_at on every run)"))
}

// regexpGroups returns the names of the groups of a source's regexp.
func regexpGroups(expr string) []string {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil // reported when the source is built
	}
	var groups []string
	for _, g := range re.SubexpNames() {
		if g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

// actionTarget tells where an action goes, without revealing secrets.
func actionTarget(a config.Action) string {
	switch a.Type {
	case "email":
		return fmt.Sprintf("to %s via %s:%d", strings.Join(a.To, ", "), a.SMTP.Host, a.SMTP.Port)
	case "ssh":
		return "on " + a.SSH.Host
	case "webhook":
		if a.Webhook.URLEnv != "" {
			return "to the URL in $" + a.Webhook.URLEnv
		}
		if u, err := url.Parse(a.Webhook.URL); err == nil {
			return "to " + u.Scheme + "://" + u.Host + "/..."
		}
	}
	return ""
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// systemdUnitName returns the full unit name of a service: "sshd" becomes
// "sshd.service"; names that already have a suffix are kept.
func systemdUnitName(unit string) string {
	if strings.Contains(unit, ".") {
		return unit
	}
	return unit + ".service"
}

// location returns the time zone of a source's dates.
func location(s config.Source) *time.Location {
	if s.Timezone != "" {
		if loc, err := time.LoadLocation(s.Timezone); err == nil {
			return loc
		}
	}
	return time.Local
}
