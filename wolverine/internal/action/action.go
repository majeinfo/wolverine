package action

import (
	"context"

	"wolverine/internal/event"
)

type Action interface {
	Name() string

	Execute(
		ctx context.Context,
		alert *event.Alert,
	) error
}
