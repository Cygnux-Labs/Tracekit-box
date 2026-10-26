package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// runYAML is run.yaml, the contributor's own account of a run (runs/README.md). The table takes the agent and the
// task from it; every count comes from the signed record.
type runYAML struct {
	Agent        string    `yaml:"agent"`
	AgentVersion string    `yaml:"agent_version"`
	Image        string    `yaml:"image"`
	Allow        *[]string `yaml:"allow"` // nil: missing; [] is a box that may reach nothing
	Task         string    `yaml:"task"`
	Notes        string    `yaml:"notes"`
}

func parseRunYAML(b []byte) (*runYAML, error) {
	var r runYAML
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("run.yaml is empty")
		}
		return nil, fmt.Errorf("run.yaml: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("run.yaml: more than one YAML document; keep one")
	}
	var problems []string
	field := func(key, v, what string, max int, multiline bool) {
		bad := func(c rune) bool {
			return (unicode.IsControl(c) || unicode.Is(unicode.Cf, c)) && !(multiline && (c == '\n' || c == '\t'))
		}
		switch {
		case strings.TrimSpace(v) == "":
			problems = append(problems, fmt.Sprintf("%s is required: %s", key, what))
		case len(v) > max:
			problems = append(problems, fmt.Sprintf("%s is over %d bytes: %s", key, max, what))
		case strings.ContainsFunc(v, bad) && multiline:
			problems = append(problems, key+" holds a control or format character")
		case strings.ContainsFunc(v, bad):
			problems = append(problems, key+" must be one line of text, with no control or format character")
		}
	}
	word := func(key, v, what string, max int) {
		if strings.ContainsFunc(strings.TrimSpace(v), unicode.IsSpace) {
			problems = append(problems, fmt.Sprintf("%s %q holds a space: %s", key, v, what))
			return
		}
		field(key, v, what, max, false)
	}
	field("agent", r.Agent, "the agent's name", 64, false)
	field("agent_version", r.AgentVersion, "the agent's version", 64, false)
	word("image", r.Image, "the box's image, as given to tkbox run --image", 256)
	if r.Allow == nil {
		problems = append(problems, "allow is required: the --allow entries (presets or hosts), or [] for none")
	} else {
		if len(*r.Allow) > 64 {
			problems = append(problems, "allow has over 64 entries")
		}
		for _, a := range *r.Allow {
			word("an allow entry", a, "a preset or a host, as given to tkbox run --allow", 253)
		}
	}
	field("task", r.Task, "the task in a sentence or two", 500, true)
	field("notes", r.Notes, "what you saw: held calls, refusals, anything that broke", 4000, true)
	if len(problems) > 0 {
		return nil, errors.New("run.yaml: " + strings.Join(problems, "; "))
	}
	return &r, nil
}
