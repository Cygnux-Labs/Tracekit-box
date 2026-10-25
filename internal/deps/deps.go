//go:build tools

// Package deps pins the only third-party modules Box may use (see BRIEF: Go stdlib first), so go.mod keeps them
// while packages adopt them.
package deps

import (
	_ "golang.org/x/sys/unix"
	_ "gopkg.in/yaml.v3"
)
