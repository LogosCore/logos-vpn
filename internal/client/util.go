package client

import (
	"errors"
	"io"

	"github.com/google/uuid"
)

// uuidBytes is a task's id, as the items carry it.
func uuidBytes(s string) ([]byte, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return id[:], nil
}

// isEOF: the machine's end closed for writing (a FIN), not reset.
func isEOF(err error) bool { return errors.Is(err, io.EOF) }

// replayWindow takes each of a sequence's numbers once, as a frame sent
// again repeats them: the latest, and the 64 before it.
type replayWindow struct {
	started bool
	last    uint64
	seen    uint64
}

func (w *replayWindow) take(seq uint64) bool {
	switch {
	case !w.started:
		w.started, w.last, w.seen = true, seq, 1
		return true
	case seq > w.last:
		if shift := seq - w.last; shift < 64 {
			w.seen <<= shift
		} else {
			w.seen = 0
		}
		w.last, w.seen = seq, w.seen|1
		return true
	case w.last-seq >= 64:
		return false
	}
	bit := uint64(1) << (w.last - seq)
	if w.seen&bit != 0 {
		return false
	}
	w.seen |= bit
	return true
}
