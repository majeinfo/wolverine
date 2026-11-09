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
	// that implement Resumer. It is saved in the state file under
	// PositionKey once the record has been processed, and given back to
	// Resume on the next run. It must be encodable as JSON. Sources reading
	// several streams (log files) use one key per stream; the others use "".
	Position    any
	PositionKey string
	// Forget lists position keys that no longer exist (e.g. a log file
	// rotated away).
	Forget []string
	// A record with nil Data carries no line: it only updates the positions
	// (Forget, or Position under PositionKey).
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
	// Resume is called before Open with the positions saved by the previous
	// run, by key. Open then starts after the last record processed instead
	// of applying its start_at setting.
	Resume(positions map[string]json.RawMessage) error
	// Positions is called after Open, before the first Read. It returns
	// where the source starts, by key; the saved positions are replaced with
	// them. Saving them matters for start_at: end: without it, a restart
	// would start at the end again and skip what was written while
	// wolverine was stopped.
	Positions() (map[string]any, error)
}
