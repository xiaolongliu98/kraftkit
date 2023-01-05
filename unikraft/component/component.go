// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package component

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"kraftkit.sh/kconfig"
	"kraftkit.sh/log"
	"kraftkit.sh/unikraft"
)

// ComponentConfig is the shared attribute structure provided to all
// microlibraries, whether they are a library, platform, architecture, an
// application itself or the Unikraft core.
type ComponentConfig struct {
	Name          string              `yaml:",omitempty" json:"-"`
	Version       string              `yaml:",omitempty" json:"version,omitempty"`
	Source        string              `yaml:",omitempty" json:"source,omitempty"`
	Configuration kconfig.KeyValueMap `yaml:",omitempty" json:"kconfig,omitempty"`

	Extensions map[string]interface{} `yaml:",inline" json:"-"`

	workdir string
	ctype   unikraft.ComponentType // embed the component type within the config

	// Context should contain all implementation-specific options, using
	// `context.WithValue`
	ctx context.Context
}

// Component is the abstract interface for managing the individual microlibrary
type Component interface {
	// Name returns the component name
	Name() string

	// Source returns the component source
	Source() string

	// Version returns the component version
	Version() string

	// Type returns the component's static constant type
	Type() unikraft.ComponentType

	// Component returns the component's configuration
	Component() ComponentConfig

	// KConfigTree returns the component's KConfig configuration menu tree which
	// returns all possible options for the component
	KConfigTree(...*kconfig.KeyValue) (*kconfig.KConfigFile, error)

	// KConfig returns the component's set of file KConfig which is known when the
	// relevant component packages have been retrieved
	KConfig() (kconfig.KeyValueMap, error)

	// PrintInfo returns human-readable information about the component
	PrintInfo() string
}

// NameAndVersion accepts a component and provids the canonical string
// representation of the component with its name and version
func NameAndVersion(component Component) string {
	return fmt.Sprintf("%s:%s", component.Name(), component.Version())
}

// ParseComponentConfig parse short syntax for Component configuration
func ParseComponentConfig(name string, props interface{}) (ComponentConfig, error) {
	component := ComponentConfig{}

	if len(name) > 0 {
		component.Name = name
	}

	switch entry := props.(type) {
	case string:
		if strings.Contains(entry, "@") {
			split := strings.Split(entry, "@")
			if len(split) == 2 {
				component.Source = split[0]
				component.Version = split[1]
			}
		} else if f, err := os.Stat(entry); err == nil && f.IsDir() {
			component.Source = entry
		} else if u, err := url.Parse(entry); err == nil && u.Scheme != "" && u.Host != "" {
			component.Source = u.Path
		} else {
			component.Version = entry
		}

	// TODO: This is handled by the transformer, do we really need to do this
	// here?
	case map[string]interface{}:
		for key, prop := range entry {
			switch key {
			case "version":
				component.Version = prop.(string)
			case "source":
				prop := prop.(string)
				if strings.Contains(prop, "@") {
					split := strings.Split(prop, "@")
					if len(split) == 2 {
						component.Version = split[1]
						prop = split[0]
					}
				}

				component.Source = prop

			case "kconfig":
				switch tprop := prop.(type) {
				case map[string]interface{}:
					component.Configuration = kconfig.NewKeyValueMapFromMap(tprop)
				case []interface{}:
					component.Configuration = kconfig.NewKeyValueMapFromSlice(tprop...)
				}
			}
		}
	}

	return component, nil
}

func (cc *ComponentConfig) ApplyOptions(opts ...ComponentOption) error {
	for _, opt := range opts {
		if err := opt(cc); err != nil {
			return err
		}
	}

	return nil
}

// Workdir exposes the instantiated component's working directory
func (cc *ComponentConfig) Workdir() string {
	return cc.workdir
}

// SetWorkdir sets the instantiated component's working directory
func (cc *ComponentConfig) SetWorkdir(workdir string) {
	cc.workdir = workdir
}

// SourceDir returns the well-known location of the component given its working
// directory, type and name.
func (cc *ComponentConfig) SourceDir() (string, error) {
	return unikraft.PlaceComponent(
		cc.workdir,
		cc.ctype,
		cc.Name,
	)
}

// IsUnpackedInProject indicates whether the package has been unpacked into a
// project specified by the working directory option
func (cc *ComponentConfig) IsUnpackedInProject() bool {
	local, err := cc.SourceDir()
	if err != nil {
		log.G(cc.ctx).Errorf("could not place component: %v", err)
		return false
	}

	if f, err := os.Stat(local); err == nil && f.IsDir() {
		return true
	}

	return false
}
