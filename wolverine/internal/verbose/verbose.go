// Package verbose controls the amount of diagnostic messages written to the
// standard logger: -v shows what wolverine is doing (configuration, sources,
// rules, actions, file rotations), -v -v adds debugging details (rule
// counters, every unparsed line, action runs).
package verbose

import (
	"log"
	"strconv"
)

// Level is 0 (quiet), 1 (info) or 2 (debug).
var Level int

// Infof logs at level 1 and above.
func Infof(format string, args ...any) {
	if Level >= 1 {
		log.Printf(format, args...)
	}
}

// Debugf logs at level 2 and above.
func Debugf(format string, args ...any) {
	if Level >= 2 {
		log.Printf("debug: "+format, args...)
	}
}

// Flag is a flag.Value that raises Level by Step each time the flag is given,
// so that "-v -v" means level 2. "-v=N" sets the level to N.
type Flag struct {
	Step int
}

func (f Flag) String() string { return strconv.Itoa(Level) }

func (f Flag) IsBoolFlag() bool { return true }

func (f Flag) Set(s string) error {
	switch s {
	case "true":
		Level += f.Step
	case "false":
		Level = 0
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		Level = n
	}
	return nil
}
