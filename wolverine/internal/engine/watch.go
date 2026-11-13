package engine

import (
	"sync"

	"wolverine/internal/event"
)

// watchBuffer is the number of notices a watcher may lag behind before it
// is disconnected.
const watchBuffer = 256

// Notice is what watchers receive: an alert raised (Action nil), or a run
// added to the action log of an alert (Action not nil).
type Notice struct {
	Alert  *event.Alert
	Action *event.ActionRun
}

// hub sends the notices to the watchers.
type hub struct {
	mu     sync.Mutex
	subs   map[chan Notice]struct{}
	closed bool
}

// subscribe returns a channel that receives the notices from now on. It is
// closed when the engine stops, when the watcher lags too far behind, or by
// the cancel function.
func (h *hub) subscribe() (<-chan Notice, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Notice, watchBuffer)
	if h.closed {
		close(ch)
		return ch, func() {}
	}
	if h.subs == nil {
		h.subs = map[chan Notice]struct{}{}
	}
	h.subs[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
	}
}

func (h *hub) publish(n Notice) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- n:
		default:
			// Too slow: better disconnect it than block detection.
			delete(h.subs, ch)
			close(ch)
		}
	}
}

// close disconnects every watcher; later ones get a closed channel.
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.subs {
		close(ch)
	}
	h.subs = nil
}
