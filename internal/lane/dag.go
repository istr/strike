// Package lane defines the pipeline schema, DAG construction,
// and execution state for strike lanes.
package lane

import (
	"fmt"
	"path"
	"strings"
)

// parseRef splits a "step_name.output_name" reference into its parts.
func parseRef(ref string) (step, output string, err error) {
	parts := strings.SplitN(ref, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid reference %q: expected step_name.output_name", ref)
	}
	return parts[0], parts[1], nil
}

// InputEdge is a fully resolved step.inputs[i] entry.
// FromStep and FromOutput are guaranteed non-nil by Build.
type InputEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
	LocalName  string // == InputRef.Name
	Mount      string // == InputRef.Mount
}

// PackFileEdge is a fully resolved step.pack.files[i] entry.
type PackFileEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
	Dest       string // == PackFile.Dest
}

// DeployArtifactEdge is a fully resolved step.deploy.artifacts[name] entry.
type DeployArtifactEdge struct {
	FromStep     *Step
	FromOutput   *OutputSpec
	ArtifactName string
}

// ImageFromEdge is a fully resolved step.image_from.
type ImageFromEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
}

// DAG is the directed acyclic graph of step dependencies in a lane.
type DAG struct {
	Steps          map[string]*Step
	InputEdges     map[string][]InputEdge // key: consuming step name
	PackFileEdges  map[string][]PackFileEdge
	DeployEdges    map[string][]DeployArtifactEdge
	ImageFromEdges map[string]ImageFromEdge // one per step, if any
	edges          map[string][]string      // step -> []dependencies
	reverse        map[string][]string      // dep -> []dependents
	Order          []string
}

// Build constructs a DAG from a Lane definition, resolving all inter-step edges.
func Build(p *Lane) (*DAG, error) {
	d := &DAG{
		Steps:          make(map[string]*Step),
		InputEdges:     make(map[string][]InputEdge),
		PackFileEdges:  make(map[string][]PackFileEdge),
		DeployEdges:    make(map[string][]DeployArtifactEdge),
		ImageFromEdges: make(map[string]ImageFromEdge),
		edges:          make(map[string][]string),
		reverse:        make(map[string][]string),
	}

	for i := range p.Steps {
		s := &p.Steps[i]
		if _, exists := d.Steps[string(s.Name)]; exists {
			return nil, fmt.Errorf("duplicate step name: %q", s.Name)
		}
		d.Steps[string(s.Name)] = s
	}

	if err := d.resolveImageFromEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolveInputEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolvePackEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolveDeployEdges(p); err != nil {
		return nil, err
	}

	if err := d.validateProvenancePaths(p); err != nil {
		return nil, err
	}

	order, err := kahnSort(d)
	if err != nil {
		return nil, err
	}
	d.Order = order
	return d, nil
}

func (d *DAG) resolveImageFromEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		if s.ImageFrom == nil {
			continue
		}
		from := s.ImageFrom.Step
		fromStep, ok := d.Steps[from]
		if !ok {
			return fmt.Errorf("step %q: image_from references unknown step %q", name, from)
		}
		out := findOutput(fromStep, s.ImageFrom.Output)
		if out == nil {
			return fmt.Errorf("step %q: image_from output %q not found in step %q",
				name, s.ImageFrom.Output, from)
		}
		if out.Type != "image" {
			return fmt.Errorf("step %q: image_from output %q in step %q is %q, not image",
				name, out.Name, from, out.Type)
		}
		d.ImageFromEdges[name] = ImageFromEdge{FromStep: fromStep, FromOutput: out}
		d.addEdge(name, from)
	}
	return nil
}

func (d *DAG) resolveInputEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		for _, inp := range s.Inputs {
			refStep, refOutput, err := parseRef(inp.From)
			if err != nil {
				return fmt.Errorf("step %q: input %q: %w", name, inp.Name, err)
			}
			fromStep, ok := d.Steps[refStep]
			if !ok {
				return fmt.Errorf("step %q: input %q references unknown step %q", name, inp.Name, refStep)
			}
			out := findOutput(fromStep, refOutput)
			if out == nil {
				return fmt.Errorf("step %q: input %q: output %q not found in step %q",
					name, inp.Name, refOutput, refStep)
			}
			d.InputEdges[name] = append(d.InputEdges[name], InputEdge{
				LocalName:  inp.Name,
				Mount:      inp.Mount,
				FromStep:   fromStep,
				FromOutput: out,
			})
			d.addEdge(name, refStep)
		}
	}
	return nil
}

func (d *DAG) resolvePackEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		if s.Pack == nil {
			continue
		}
		for _, f := range s.Pack.Files {
			if err := d.resolvePackFileEdge(name, f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *DAG) resolvePackFileEdge(name string, f PackFile) error {
	stepName, outputName, err := parseRef(f.From)
	if err != nil {
		return fmt.Errorf("step %q: pack file: %w", name, err)
	}
	fromStep, ok := d.Steps[stepName]
	if !ok {
		return fmt.Errorf("step %q: pack file from %q: unknown step %q", name, f.From, stepName)
	}
	out := findOutput(fromStep, outputName)
	if out == nil {
		return fmt.Errorf("step %q: pack file from %q: output %q not found in step %q",
			name, f.From, outputName, stepName)
	}
	d.PackFileEdges[name] = append(d.PackFileEdges[name], PackFileEdge{
		Dest:       f.Dest,
		FromStep:   fromStep,
		FromOutput: out,
	})
	d.addEdge(name, stepName)
	return nil
}

// findOutput returns a pointer to the OutputSpec with the given name,
// or nil if not found. The returned pointer aliases into s.Outputs,
// so callers must not mutate s after Build returns.
func findOutput(s *Step, name string) *OutputSpec {
	for i := range s.Outputs {
		if s.Outputs[i].Name == name {
			return &s.Outputs[i]
		}
	}
	return nil
}

func (d *DAG) resolveDeployEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		if s.Deploy == nil {
			continue
		}
		for artName, artRef := range s.Deploy.Artifacts {
			stepName, outputName, err := parseRef(artRef.From)
			if err != nil {
				return fmt.Errorf("step %q: deploy artifact %q: %w", name, artName, err)
			}
			fromStep, ok := d.Steps[stepName]
			if !ok {
				return fmt.Errorf("step %q: deploy artifact %q references unknown step %q",
					name, artName, stepName)
			}
			out := findOutput(fromStep, outputName)
			if out == nil {
				return fmt.Errorf("step %q: deploy artifact %q: output %q not found in step %q",
					name, artName, outputName, stepName)
			}
			d.DeployEdges[name] = append(d.DeployEdges[name], DeployArtifactEdge{
				ArtifactName: artName,
				FromStep:     fromStep,
				FromOutput:   out,
			})
			d.addEdge(name, stepName)
		}
	}
	return nil
}

// validateProvenancePaths checks that each step's provenance.path
// (if declared) is absolute, canonical, and lies within an output directory.
func (d *DAG) validateProvenancePaths(p *Lane) error {
	for _, s := range p.Steps {
		if s.Provenance == nil {
			continue
		}
		provPath := s.Provenance.Path
		if !path.IsAbs(provPath) || path.Clean(provPath) != provPath {
			return fmt.Errorf("step %q: provenance.path %q must be absolute and canonical",
				s.Name, provPath)
		}
		found := false
		for _, out := range s.Outputs {
			outDir := path.Dir(out.Path)
			if strings.HasPrefix(provPath, outDir+"/") || provPath == out.Path {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("step %q: provenance.path %q is not within any declared output",
				s.Name, provPath)
		}
	}
	return nil
}

func (d *DAG) addEdge(from, to string) {
	d.edges[from] = append(d.edges[from], to)
	d.reverse[to] = append(d.reverse[to], from)
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
