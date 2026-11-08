package parser

import (
	"wolverine/internal/event"
	"wolverine/internal/source"
)

type Parser interface {
	Name() string

	Parse(record *source.Record) (
		*event.Event,
		error,
	)
}
