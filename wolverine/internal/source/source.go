package source

import (
	"context"
	"encoding/json"
	"time"
)

type Record struct {
	Data      []byte
	Timestamp time.Time
	Source    string
	// Fields holds the structured data of sources that provide some, such
	// as the systemd journal (MESSAGE, _HOSTNAME, _PID...). Data is then the
	// message.
	Fields map[string]string
	// Position is where the source is just after this record, for sources
	// that implement Resumer. It is saved in the state file once the record
	// has been processed, and given back to Resume on the next run. It must
	// be encodable as JSON.
	Position any
}

type Source interface {
	Name() string

	Open(ctx context.Context) error

	Read(ctx context.Context) (
		*Record,
		error,
	)

	Close() error
}

// Resumer is implemented by the sources that can continue where a previous
// run stopped.
type Resumer interface {
	// Resume is called before Open with the Position of the last record
	// processed by the previous run. Open then starts after that record
	// instead of applying its start_at setting.
	Resume(position json.RawMessage) error
	// Position is called after Open, before the first Read. It returns
	// where the source starts, or nil if there is nothing to save. Saving it
	// matters for start_at: end: without it, a restart would start at the
	// end again and skip what was written while wolverine was stopped.
	Position() (any, error)
}
