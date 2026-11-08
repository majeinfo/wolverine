package processor

import (
	"context"

	"wolverine/internal/event"
)

type Processor interface {
	Name() string

	Process(
		ctx context.Context,
		ev *event.Event,
	) (*event.Event, error)
}
