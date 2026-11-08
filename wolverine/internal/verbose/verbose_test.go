package verbose

import (
	"flag"
	"testing"
)

func TestFlag(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{nil, 0},
		{[]string{"-v"}, 1},
		{[]string{"-v", "-v"}, 2},
		{[]string{"-vv"}, 2},
		{[]string{"-v=3"}, 3},
		{[]string{"-v", "-v=false"}, 0},
	}
	for _, tt := range tests {
		Level = 0
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.Var(Flag{Step: 1}, "v", "")
		fs.Var(Flag{Step: 2}, "vv", "")
		if err := fs.Parse(tt.args); err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		if Level != tt.want {
			t.Errorf("%v: level %d, want %d", tt.args, Level, tt.want)
		}
	}
	Level = 0
}
