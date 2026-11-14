package config

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The variables section of a configuration file names values reused in the
// rest of the file, written ${name}:
//
//	variables:
//	  ssh_regexp: '^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)'
//	  threshold: 5
//	  admins: [192.0.2.10, 192.0.2.11]
//
//	rules:
//	  - id: brute-force
//	    count: ${threshold}              # the value alone: keeps its type (a number)
//	    exclude: ${admins}               # a list, too
//	    description: more than ${threshold} failures   # inside text: its text
//
// The variables of the main file can be used in every file; those of an
// included file only in that file, and they cannot redefine those of the
// main file. A variable may use other variables. $${ gives a literal ${.
// The date macros of a path (${year}, ${day-1}, ${hour - hour%6}...) are not
// variables: they are left as they are, and their names cannot be
// variable names.

const variablesKey = "variables"

var (
	identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// refRe finds the references: ${...}, or $${...} (escaped).
	refRe   = regexp.MustCompile(`\$?\$\{([^{}]*)\}`)
	wholeRe = regexp.MustCompile(`^\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}$`)
)

// dateVariables are the names of the date macros of the paths (see package
// pathtemplate).
var dateVariables = []string{"year", "month", "day", "hour", "minute", "second"}

// variables are the variables of a file, with those of the main file as
// parent.
type variables struct {
	file     string
	parent   *variables
	defs     map[string]*yaml.Node // as written
	resolved map[string]*yaml.Node // with their own references replaced
	active   map[string]bool       // being resolved, to detect cycles
}

// takeVariables removes the variables section from a document and returns
// its variables.
func takeVariables(doc *yaml.Node, file string, parent *variables) (*variables, error) {
	v := &variables{file: file, parent: parent, defs: map[string]*yaml.Node{}, resolved: map[string]*yaml.Node{}, active: map[string]bool{}}
	root := top(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return v, nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != variablesKey {
			continue
		}
		section := root.Content[i+1]
		root.Content = slices.Delete(root.Content, i, i+2)
		if section.Kind == yaml.ScalarNode && section.Tag == "!!null" {
			return v, nil // "variables:" alone
		}
		if section.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: line %d: variables: a mapping of names to values", file, section.Line)
		}
		for j := 0; j+1 < len(section.Content); j += 2 {
			k := section.Content[j]
			name := k.Value
			switch {
			case !identRe.MatchString(name):
				return nil, fmt.Errorf("%s: line %d: variable %q: a name is made of letters, digits and _, and does not start with a digit", file, k.Line, name)
			case slices.Contains(dateVariables, name):
				return nil, fmt.Errorf("%s: line %d: variable %q: reserved for the date macros of the paths", file, k.Line, name)
			case v.defs[name] != nil:
				return nil, fmt.Errorf("%s: line %d: variable %q defined twice", file, k.Line, name)
			case parent != nil && parent.defs[name] != nil:
				return nil, fmt.Errorf("%s: line %d: variable %q is already defined in the main configuration file %s", file, k.Line, name, parent.file)
			}
			v.defs[name] = section.Content[j+1]
		}
		return v, nil
	}
	return v, nil
}

// top returns the root node of a document (nil if empty).
func top(doc *yaml.Node) *yaml.Node {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	return doc.Content[0]
}

// lookup returns the variables defining name (this file's or the main
// file's), or nil.
func (v *variables) lookup(name string) *variables {
	for s := v; s != nil; s = s.parent {
		if s.defs[name] != nil {
			return s
		}
	}
	return nil
}

// value returns the value of a variable, its own references replaced.
func (v *variables) value(name string, line int) (*yaml.Node, error) {
	owner := v.lookup(name)
	if owner == nil {
		return nil, fmt.Errorf("line %d: undefined variable ${%s}", line, name)
	}
	if n := owner.resolved[name]; n != nil {
		return n, nil
	}
	if owner.active[name] {
		return nil, fmt.Errorf("line %d: variable %s refers to itself", line, name)
	}
	owner.active[name] = true
	defer delete(owner.active, name)
	n := clone(owner.defs[name])
	n, err := owner.replace(n)
	if err != nil {
		return nil, err
	}
	owner.resolved[name] = n
	return n, nil
}

// replace replaces the references in the values of n (not in the keys of
// its mappings) and returns it, or its replacement.
func (v *variables) replace(n *yaml.Node) (*yaml.Node, error) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			r, err := v.replace(c)
			if err != nil {
				return nil, err
			}
			n.Content[i] = r
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			r, err := v.replace(n.Content[i])
			if err != nil {
				return nil, err
			}
			n.Content[i] = r
		}
	case yaml.ScalarNode:
		return v.scalar(n)
	}
	return n, nil
}

// scalar replaces the references of a scalar. A reference alone is replaced
// by the variable's value, whatever its type; inside text, by its text.
func (v *variables) scalar(n *yaml.Node) (*yaml.Node, error) {
	if !strings.Contains(n.Value, "${") {
		return n, nil
	}
	if m := wholeRe.FindStringSubmatch(n.Value); m != nil && v.lookup(m[1]) != nil {
		val, err := v.value(m[1], n.Line)
		if err != nil {
			return nil, err
		}
		c := clone(val)
		c.Line, c.Column = n.Line, n.Column // errors point at the use
		return c, nil
	}
	var err error
	text := refRe.ReplaceAllStringFunc(n.Value, func(ref string) string {
		if err != nil {
			return ref
		}
		if strings.HasPrefix(ref, "$$") {
			return ref[1:] // escaped
		}
		name := strings.TrimSpace(ref[2 : len(ref)-1])
		if !identRe.MatchString(name) || (slices.Contains(dateVariables, name) && v.lookup(name) == nil) {
			return ref // a date macro of a path
		}
		val, e := v.value(name, n.Line)
		if e != nil {
			err = e
			return ref
		}
		if val.Kind != yaml.ScalarNode {
			err = fmt.Errorf("line %d: variable %s is a list or a mapping: it can only be used alone, as a whole value", n.Line, name)
			return ref
		}
		return val.Value
	})
	if err != nil {
		return nil, err
	}
	c := *n
	c.Value = text
	if c.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0 {
		c.Tag = "" // resolved again from the text: "${n}0" may give a number
	}
	return &c, nil
}

func clone(n *yaml.Node) *yaml.Node {
	c := *n
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, x := range n.Content {
			c.Content[i] = clone(x)
		}
	}
	return &c
}

// checkKnown reports the keys of the mappings of n that are not fields of
// type t, as yaml.Decoder.KnownFields does (which a yaml.Node cannot do).
func checkKnown(n *yaml.Node, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	switch {
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
		fields := map[string]reflect.Type{}
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			fields[name] = f.Type
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value == "<<" { // merge key
				if err := checkKnown(n.Content[i+1], t); err != nil {
					return err
				}
				continue
			}
			ft, ok := fields[k.Value]
			if !ok {
				return fmt.Errorf("line %d: field %s not found in type %s", k.Line, k.Value, t)
			}
			if err := checkKnown(n.Content[i+1], ft); err != nil {
				return err
			}
		}
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		for _, c := range n.Content {
			if err := checkKnown(c, t.Elem()); err != nil {
				return err
			}
		}
	case t.Kind() == reflect.Map && n.Kind == yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			if err := checkKnown(n.Content[i], t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
