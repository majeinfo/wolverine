//go:build !nosystemd

package engine

import (
	"errors"
	"strings"

	"wolverine/internal/config"
	"wolverine/internal/source/systemd"
)

func buildSystemdService(c config.Source) (*input, error) {
	if c.Unit == "" {
		return nil, errors.New("unit is required")
	}
	if strings.ContainsAny(c.Unit, "=/ \t\n") {
		return nil, errors.New("unit: invalid unit name")
	}
	startAtEnd, err := startAt(c)
	if err != nil {
		return nil, err
	}
	re, err := compileRegexp(c.Regexp)
	if err != nil {
		return nil, err
	}
	return &input{
		source: &systemd.Journal{
			ID:         c.ID,
			Unit:       systemdUnitName(c.Unit),
			Follow:     c.Follow,
			StartAtEnd: startAtEnd,
		},
		parser: &systemd.Parser{Regexp: re, Category: category(c)},
	}, nil
}
