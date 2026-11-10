// Package pathtemplate expands file names containing date macros, such as
// /var/log/app.log.${year}-${month}-${day-1}.
//
// A macro is ${expression}, evaluated with govaluate. The variables are the
// components of the current date: year, month, day, hour, minute, second.
//
// A macro written "name", "name-N" or "name+N" (N an integer) shifts the
// date: ${day-1} means yesterday. All the shifts of a template are applied
// together, then every macro is rendered from the shifted date. On March 1,
// "${year}-${month}-${day-1}" gives "2026-02-28", not "2026-03-00". These
// macros are rendered with 4 digits for the year and 2 for the others.
//
// Any other expression (${year%100}, ${hour - hour%6}...) is computed from
// the shifted date. The arithmetic is done on floats (${hour/6*6} is the
// hour); the result is rounded down to an integer and rendered with at
// least 2 digits.
package pathtemplate

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
)

// Variables are the variables available in the macros.
var Variables = []string{"year", "month", "day", "hour", "minute", "second"}

// Template is a parsed path template.
type Template struct {
	text   string
	parts  []part
	shifts map[string]int // variable -> shift, for the shift macros
}

type part struct {
	literal string
	src     string // the macro's expression, for error messages
	expr    *govaluate.EvaluableExpression
	shift   string // variable shifted by this macro, if it is a shift
}

// HasMacros tells whether s contains a macro.
func HasMacros(s string) bool { return strings.Contains(s, "${") }

// Parse parses a template. It checks that every macro is a valid
// expression using known variables, and evaluates it once.
func Parse(text string) (*Template, error) {
	t := &Template{text: text, shifts: map[string]int{}}
	rest := text
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			if rest != "" {
				t.parts = append(t.parts, part{literal: rest})
			}
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{literal: rest[:i]})
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("unclosed macro %q", rest[i:])
		}
		src := strings.TrimSpace(rest[i+2 : i+j])
		rest = rest[i+j+1:]
		p, err := t.parseMacro(src)
		if err != nil {
			return nil, fmt.Errorf("macro ${%s}: %w", src, err)
		}
		t.parts = append(t.parts, p)
	}
	// Catches expressions that do not give a number.
	if _, err := t.Expand(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Template) parseMacro(src string) (part, error) {
	if src == "" {
		return part{}, errors.New("empty expression")
	}
	expr, err := govaluate.NewEvaluableExpression(src)
	if err != nil {
		return part{}, err
	}
	for _, v := range expr.Vars() {
		if !isVariable(v) {
			return part{}, fmt.Errorf("unknown variable %q (available: %s)", v, strings.Join(Variables, ", "))
		}
	}
	p := part{src: src, expr: expr}
	if name, n, ok := shiftOf(expr.Tokens()); ok {
		if prev, seen := t.shifts[name]; seen && prev != n {
			return part{}, fmt.Errorf("%s is shifted by %d elsewhere in the path, and by %d here", name, prev, n)
		}
		t.shifts[name] = n
		p.shift = name
	}
	return p, nil
}

func isVariable(name string) bool {
	for _, v := range Variables {
		if v == name {
			return true
		}
	}
	return false
}

// shiftOf recognizes the expressions "name", "name+N" and "name-N" where N
// is an integer, and returns the variable and its shift.
func shiftOf(tokens []govaluate.ExpressionToken) (string, int, bool) {
	if len(tokens) == 0 || tokens[0].Kind != govaluate.VARIABLE {
		return "", 0, false
	}
	name, _ := tokens[0].Value.(string)
	if len(tokens) == 1 {
		return name, 0, true
	}
	if len(tokens) != 3 || tokens[1].Kind != govaluate.MODIFIER || tokens[2].Kind != govaluate.NUMERIC {
		return "", 0, false
	}
	n, ok := tokens[2].Value.(float64)
	if !ok || n != math.Trunc(n) {
		return "", 0, false
	}
	switch tokens[1].Value {
	case "+":
		return name, int(n), true
	case "-":
		return name, -int(n), true
	}
	return "", 0, false
}

func (t *Template) String() string { return t.text }

// Expand returns the path for the date now, in now's location.
func (t *Template) Expand(now time.Time) (string, error) {
	d := t.shifted(now)
	vars := map[string]any{
		"year":   float64(d.Year()),
		"month":  float64(d.Month()),
		"day":    float64(d.Day()),
		"hour":   float64(d.Hour()),
		"minute": float64(d.Minute()),
		"second": float64(d.Second()),
	}
	var b strings.Builder
	for _, p := range t.parts {
		switch {
		case p.expr == nil:
			b.WriteString(p.literal)
		case p.shift == "year":
			fmt.Fprintf(&b, "%04d", int(vars["year"].(float64)))
		case p.shift != "":
			fmt.Fprintf(&b, "%02d", int(vars[p.shift].(float64)))
		default:
			v, err := p.expr.Evaluate(vars)
			if err != nil {
				return "", fmt.Errorf("macro ${%s}: %w", p.src, err)
			}
			f, ok := v.(float64)
			if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
				return "", fmt.Errorf("macro ${%s}: %v is not a number", p.src, v)
			}
			fmt.Fprintf(&b, "%02d", int64(math.Floor(f)))
		}
	}
	return b.String(), nil
}

// shifted applies the shifts of the template to now: years and months
// first (the day is kept within the resulting month: March 31 minus one
// month is February 28), then days, then hours, minutes and seconds.
func (t *Template) shifted(now time.Time) time.Time {
	sh := t.shifts
	loc := now.Location()
	first := time.Date(now.Year()+sh["year"], now.Month()+time.Month(sh["month"]), 1, 0, 0, 0, 0, loc)
	lastDay := first.AddDate(0, 1, -1).Day()
	d := time.Date(first.Year(), first.Month(), min(now.Day(), lastDay), now.Hour(), now.Minute(), now.Second(), 0, loc)
	d = d.AddDate(0, 0, sh["day"])
	return d.Add(time.Duration(sh["hour"])*time.Hour + time.Duration(sh["minute"])*time.Minute + time.Duration(sh["second"])*time.Second)
}

// Shifts describes the shifts of the template, for information.
func (t *Template) Shifts() string {
	var s []string
	for _, v := range Variables {
		if n := t.shifts[v]; n != 0 {
			s = append(s, fmt.Sprintf("%s%+d", v, n))
		}
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}
