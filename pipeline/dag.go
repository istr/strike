// pipeline/dag.go
package pipeline

import (
	"fmt"
	"strings"
)

type DAG struct {
	Steps   map[string]*Step
	edges   map[string][]string // step → []dependencies
	reverse map[string][]string // dep → []dependents
	Order   []string
}

func Build(p *Pipeline) (*DAG, error) {
	d := &DAG{
		Steps:   make(map[string]*Step),
		edges:   make(map[string][]string),
		reverse: make(map[string][]string),
	}

	for i := range p.Steps {
		s := &p.Steps[i]
		if _, exists := d.Steps[string(s.Name)]; exists {
			return nil, fmt.Errorf("doppelter step-name: %q", s.Name)
		}
		d.Steps[string(s.Name)] = s
	}

	for _, s := range p.Steps {
		name := string(s.Name)
		for _, inp := range s.Inputs {
			from := string(inp.From)
			if _, ok := d.Steps[from]; !ok {
				return nil, fmt.Errorf("step %q: input %q referenziert unbekannten step %q",
					name, inp.Name, from)
			}
			d.edges[name] = append(d.edges[name], from)
			d.reverse[from] = append(d.reverse[from], name)
		}
	}

	order, err := kahnSort(d)
	if err != nil {
		return nil, err
	}
	d.Order = order
	return d, nil
}

func kahnSort(d *DAG) ([]string, error) {
	// inDegree[step] = Anzahl der Abhängigkeiten die step noch braucht
	inDegree := make(map[string]int, len(d.Steps))
	for name := range d.Steps {
		inDegree[name] = len(d.edges[name])
	}

	// Wurzeln: Steps ohne Abhängigkeiten
	queue := []string{}
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		order = append(order, node)

		// Abhängige dieses Nodes freischalten
		for _, dependent := range d.reverse[node] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(order) != len(d.Steps) {
		return nil, fmt.Errorf("zyklische abhängigkeit im pipeline-graph")
	}
	return order, nil
}

// Tree gibt den DAG als Baumstruktur aus
func (d *DAG) Tree() string {
	var sb strings.Builder

	// Wurzeln: Steps ohne Abhängigkeiten
	roots := []string{}
	for name := range d.Steps {
		if len(d.edges[name]) == 0 {
			roots = append(roots, name)
		}
	}

	for i, root := range roots {
		last := i == len(roots)-1
		prefix := ""
		connector := "├── "
		if last {
			connector = "└── "
		}
		sb.WriteString(connector + root + "\n")
		d.treeNode(&sb, root, prefix, last)
	}

	return sb.String()
}

func (d *DAG) treeNode(sb *strings.Builder, node, prefix string, lastParent bool) {
	dependents := d.reverse[node]
	childPrefix := prefix
	if lastParent {
		childPrefix += "    "
	} else {
		childPrefix += "│   "
	}

	for i, dep := range dependents {
		last := i == len(dependents)-1
		connector := "├── "
		if last {
			connector = "└── "
		}
		// Abhängigkeiten anzeigen wenn mehr als eine
		deps := d.edges[dep]
		annotation := ""
		if len(deps) > 1 {
			annotation = " (" + strings.Join(deps, ", ") + ")"
		}
		sb.WriteString(childPrefix + connector + dep + annotation + "\n")
		d.treeNode(sb, dep, childPrefix, last)
	}
}
