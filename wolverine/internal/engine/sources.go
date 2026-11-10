package engine

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/pathtemplate"
	"wolverine/internal/source/syslog"
)

var defaultTimestampFormats = []string{"rfc3164", "rfc3339"}

// buildSources creates the enabled sources described in the configuration.
func buildSources(cfgs []config.Source) ([]*input, error) {
	var inputs []*input
	seen := map[string]bool{}
	for i, c := range cfgs {
		if c.ID == "" {
			return nil, fmt.Errorf("source #%d: missing id", i+1)
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("source %q: duplicate id", c.ID)
		}
		seen[c.ID] = true
		if c.Disabled {
			continue
		}

		in, err := buildSource(c)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", c.ID, err)
		}
		in.typ = c.Type
		inputs = append(inputs, in)
	}
	if len(inputs) == 0 {
		return nil, errors.New("no source enabled")
	}
	return inputs, nil
}

func buildSource(c config.Source) (*input, error) {
	switch c.Type {
	case "logfile":
		if c.Unit != "" {
			return nil, errors.New("unit does not apply to a logfile source")
		}

		return buildLogfile(c)
	case "systemd-service":
		switch {
		case c.Path != "" || c.Directory != "" || c.FilenameRegexp != "":
			return nil, errors.New("path, directory and filename_regexp do not apply to a systemd-service source")
		case len(c.TimestampFormats) > 0:
			return nil, errors.New("timestamp_formats does not apply to a systemd-service source (the journal timestamps are used)")
		case c.Timezone != "":
			return nil, errors.New("timezone does not apply to a systemd-service source")
		}
		return buildSystemdService(c)
	case "":
		return nil, fmt.Errorf("missing type")
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
}

func buildLogfile(c config.Source) (*input, error) {
	src := &syslog.Files{ID: c.ID, Path: c.Path, Dir: c.Directory, Follow: c.Follow}
	switch {
	case c.Path != "" && (c.Directory != "" || c.FilenameRegexp != ""):
		return nil, errors.New("set either path, or directory and filename_regexp")
	case pathtemplate.HasMacros(c.Path):
		if pathtemplate.HasMacros(filepath.Dir(c.Path)) {
			return nil, errors.New("path: macros are only allowed in the file name, not in the directory")
		}
		tmpl, err := pathtemplate.Parse(c.Path)
		if err != nil {
			return nil, fmt.Errorf("path: %w", err)
		}
		src.Path, src.Template = "", tmpl
	case c.Path != "":
	case c.Directory == "" && c.FilenameRegexp == "":
		return nil, errors.New("path is required (or directory and filename_regexp)")
	case c.Directory == "":
		return nil, errors.New("filename_regexp requires directory")
	case c.FilenameRegexp == "":
		return nil, errors.New("directory requires filename_regexp")
	default:
		re, err := regexp.Compile(c.FilenameRegexp)
		if err != nil {
			return nil, fmt.Errorf("filename_regexp: %w", err)
		}
		src.Pattern = re
	}

	startAtEnd, err := startAt(c)
	if err != nil {
		return nil, err
	}

	if c.Regexp == "" {
		return nil, fmt.Errorf("regexp is required")
	}
	re, err := compileRegexp(c.Regexp)
	if err != nil {
		return nil, err
	}

	formats := c.TimestampFormats
	if len(formats) == 0 {
		formats = defaultTimestampFormats
	}
	for _, f := range formats {
		if _, err := syslog.TimestampLayout(f); err != nil {
			return nil, fmt.Errorf("timestamp_formats: %w", err)
		}
	}

	src.StartAtEnd = startAtEnd

	loc := time.Local
	if c.Timezone != "" {
		if loc, err = time.LoadLocation(c.Timezone); err != nil {
			return nil, fmt.Errorf("timezone: %w", err)
		}
	}

	src.Location = loc

	return &input{
		source: src,
		parser: &syslog.Parser{
			Regexp:           re,
			Category:         category(c),
			TimestampFormats: formats,
			Location:         loc,
		},
	}, nil
}

// startAt tells whether the source must skip the existing lines.
func startAt(c config.Source) (bool, error) {
	switch c.StartAt {
	case "", "beginning":
		return false, nil
	case "end":
		if !c.Follow {
			return false, errors.New("start_at: end requires follow: true")
		}
		return true, nil
	default:
		return false, fmt.Errorf("start_at %q: beginning or end", c.StartAt)
	}
}

// compileRegexp compiles the regexp of a source; an empty one gives nil.
func compileRegexp(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("regexp: %w", err)
	}
	return re, nil
}

func category(c config.Source) string {
	if c.Category == "" {
		return "system"
	}
	return c.Category
}
