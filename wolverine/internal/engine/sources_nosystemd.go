//go:build nosystemd

package engine

import (
	"errors"

	"wolverine/internal/config"
)

func buildSystemdService(c config.Source) (*input, error) {
	return nil, errors.New("this wolverine was built without systemd support (nosystemd tag)")
}
