package filter

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"

	"wolverine/internal/event"
)

// commonVariables are the variables of every condition: the Event fields,
// named like the regexp groups that set them.
var commonVariables = map[string]struct {
	typ   *cel.Type
	value func(*event.Event) any
}{
	"timestamp": {cel.TimestampType, func(ev *event.Event) any { return ev.Timestamp }},
	"source":    {cel.StringType, func(ev *event.Event) any { return ev.Source }},
	"category":  {cel.StringType, func(ev *event.Event) any { return ev.Category }},
	"severity":  {cel.StringType, func(ev *event.Event) any { return ev.Severity }},
	"hostname":  {cel.StringType, func(ev *event.Event) any { return ev.Hostname }},
	"service":   {cel.StringType, func(ev *event.Event) any { return ev.Service }},
	"source_ip": {cel.StringType, func(ev *event.Event) any { return ev.SourceIP }},
	"dest_ip":   {cel.StringType, func(ev *event.Event) any { return ev.DestIP }},
	"username":  {cel.StringType, func(ev *event.Event) any { return ev.Username }},
	"action":    {cel.StringType, func(ev *event.Event) any { return ev.Action }},
	"status":    {cel.StringType, func(ev *event.Event) any { return ev.Status }},
	"message":   {cel.StringType, func(ev *event.Event) any { return ev.Message }},
	"raw":       {cel.StringType, func(ev *event.Event) any { return ev.Raw }},
	"fields": {cel.MapType(cel.StringType, cel.DynType), func(ev *event.Event) any {
		if ev.Fields == nil {
			return map[string]any{}
		}
		return ev.Fields
	}},
}

// CommonVariables returns the names of the variables every condition has.
func CommonVariables() []string {
	var names []string
	for n := range commonVariables {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reserved are the words CEL does not accept as variable names.
var reserved = []string{
	"true", "false", "null", "in", "as", "break", "const", "continue", "else",
	"for", "function", "if", "import", "let", "loop", "package", "namespace",
	"return", "var", "void", "while",
}

// Condition is a CEL expression evaluated on an event: a source drops the
// events for which its exclude_if condition is true.
type Condition struct {
	Text string
	// Groups are the regexp groups available as variables: their value is
	// the string in Event.Fields, or "" when the group did not match.
	Groups []string
	prog   cel.Program
	// errors counts the events the condition could not be evaluated on.
	errors atomic.Int64
}

// CompileCondition compiles a boolean CEL expression. Its variables are the
// common ones (CommonVariables) and groups, the names of the source's regexp
// groups that are not common variables. in_list(address, "list id") tells
// whether an address is in an exclude list.
func CompileCondition(text string, groups []string, lists map[string]*List) (*Condition, error) {
	c := &Condition{Text: text}
	opts := []cel.EnvOption{
		ext.Strings(),
		cel.OptionalTypes(),
		cel.Function("in_list",
			cel.Overload("in_list_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(addr, list ref.Val) ref.Val {
					l, ok := lists[string(list.(types.String))]
					if !ok {
						return types.NewErr("in_list: unknown exclude list %q", list)
					}
					a, err := netip.ParseAddr(string(addr.(types.String)))
					return types.Bool(err == nil && l.Contains(a))
				}))),
	}
	for name, v := range commonVariables {
		opts = append(opts, cel.Variable(name, v.typ))
	}
	for _, g := range groups {
		if _, common := commonVariables[g]; common || !identifier.MatchString(g) || slices.Contains(reserved, g) || slices.Contains(c.Groups, g) {
			continue // only in fields
		}
		c.Groups = append(c.Groups, g)
		opts = append(opts, cel.Variable(g, cel.StringType))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, err
	}

	checked, iss := env.Compile(text)
	if iss.Err() != nil {
		return nil, errors.New(strings.TrimSpace(iss.Err().Error()))
	}
	if !checked.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("the expression must be true or false, not a %s", checked.OutputType())
	}
	// The lists must be known when wolverine starts, not when an event
	// reaches the call.
	for _, call := range celast.MatchDescendants(celast.NavigateAST(checked.NativeRep()), celast.FunctionMatcher("in_list")) {
		arg := call.AsCall().Args()[1]
		name, ok := arg.AsLiteral().(types.String)
		if arg.Kind() != celast.LiteralKind || !ok {
			return nil, errors.New(`in_list: the exclude list must be given by its id in quotes, e.g. in_list(source_ip, "trusted")`)
		}
		if _, ok := lists[string(name)]; !ok {
			return nil, fmt.Errorf("in_list: unknown exclude list %q", string(name))
		}
	}

	if c.prog, err = env.Program(checked, cel.EvalOptions(cel.OptOptimize)); err != nil {
		return nil, err
	}
	return c, nil
}

// Match evaluates the condition on an event.
func (c *Condition) Match(ev *event.Event) (bool, error) {
	out, _, err := c.prog.Eval(activation{c, ev})
	if err != nil {
		return false, err
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("the expression returned %v, not true or false", out)
	}
	return bool(b), nil
}

// activation gives the variables of an event, computed when the expression
// uses them.
type activation struct {
	c  *Condition
	ev *event.Event
}

func (a activation) ResolveName(name string) (any, bool) {
	if v, ok := commonVariables[name]; ok {
		return v.value(a.ev), true
	}
	if slices.Contains(a.c.Groups, name) {
		v, ok := a.ev.Fields[name]
		if !ok {
			return "", true
		}
		if s, ok := v.(string); ok {
			return s, true
		}
		return fmt.Sprint(v), true
	}
	return nil, false
}

func (activation) Parent() interpreter.Activation { return nil }
