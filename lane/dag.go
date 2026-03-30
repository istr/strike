package lane

import (
	"fmt"
	"strings"
)

type DAG struct {
	Steps   map[string]*Step
	edges   map[string][]string // step -> []dependencies
	reverse map[string][]string // dep -> []dependents
	Order   []string
}

func Build(p *Lane) (*DAG, error) {
	d := &DAG{
		Steps:   make(map[string]*Step),
		edges:   make(map[string][]string),
		reverse: make(map[string][]string),
	}

	for i := range p.Steps {
		s := &p.Steps[i]
		if _, exists := d.Steps[string(s.Name)]; exists {
			return nil, fmt.Errorf("duplicate step name: %q", s.Name)
		}
		d.Steps[string(s.Name)] = s
	}

	for _, s := range p.Steps {
		name := string(s.Name)

		// image_from creates an implicit DAG edge
		if s.ImageFrom != nil {
			from := s.ImageFrom.Step
			if _, ok := d.Steps[from]; !ok {
				return nil, fmt.Errorf("step %q: image_from references unknown step %q",
					name, from)
			}
			// Validate that the referenced output exists and is oci-tar
			fromStep := d.Steps[from]
			found := false
			for _, out := range fromStep.Outputs {
				if out.Name == s.ImageFrom.Output {
					if out.Type != "oci-tar" {
						return nil, fmt.Errorf("step %q: image_from output %q in step %q is %q, not oci-tar",
							name, out.Name, from, out.Type)
					}
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("step %q: image_from output %q not found in step %q",
					name, s.ImageFrom.Output, from)
			}
			d.edges[name] = append(d.edges[name], from)
			d.reverse[from] = append(d.reverse[from], name)
		}

		for _, inp := range s.Inputs {
			from := string(inp.From)
			if _, ok := d.Steps[from]; !ok {
				return nil, fmt.Errorf("step %q: input %q references unknown step %q",
					name, inp.Name, from)
			}
			d.edges[name] = append(d.edges[name], from)
			d.reverse[from] = append(d.reverse[from], name)
		}

		// pack.files create DAG edges via "stepname/outputname" references
		if s.Pack != nil {
			for _, f := range s.Pack.Files {
				parts := strings.SplitN(f.From, "/", 2)
				if len(parts) != 2 {
					return nil, fmt.Errorf("step %q: pack file from %q: expected stepname/outputname",
						name, f.From)
				}
				fromStep, ok := d.Steps[parts[0]]
				if !ok {
					return nil, fmt.Errorf("step %q: pack file from %q: unknown step %q",
						name, f.From, parts[0])
				}
				found := false
				for _, out := range fromStep.Outputs {
					if out.Name == parts[1] {
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("step %q: pack file from %q: output %q not found in step %q",
						name, f.From, parts[1], parts[0])
				}
				d.edges[name] = append(d.edges[name], parts[0])
				d.reverse[parts[0]] = append(d.reverse[parts[0]], name)
			}
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
	inDegree := make(map[string]int, len(d.Steps))
	for name := range d.Steps {
		inDegree[name] = len(d.edges[name])
	}

	// Roots: steps without dependencies
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

		// Unlock dependents of this node
		for _, dependent := range d.reverse[node] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(order) != len(d.Steps) {
		return nil, fmt.Errorf("cyclic dependency in lane graph")
	}
	return order, nil
}

// Tree renders the DAG as a tree structure.
func (d *DAG) Tree() string {
	var sb strings.Builder

	// Roots: steps without dependencies
	roots := []string{}
	for name := range d.Steps {
		if len(d.edges[name]) == 0 {
			roots = append(roots, name)
		}
	}

	for i, root := range roots {
		last := i == len(roots)-1
		prefix := ""
		connector := "+-- "
		if last {
			connector = "`-- "
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
		childPrefix += "|   "
	}

	for i, dep := range dependents {
		last := i == len(dependents)-1
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		// Show dependencies when more than one
		deps := d.edges[dep]
		annotation := ""
		if len(deps) > 1 {
			annotation = " (" + strings.Join(deps, ", ") + ")"
		}
		sb.WriteString(childPrefix + connector + dep + annotation + "\n")
		d.treeNode(sb, dep, childPrefix, last)
	}
}
