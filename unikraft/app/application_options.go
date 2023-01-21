// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package app

import (
	"fmt"
	"os"
	"path/filepath"

	"kraftkit.sh/kconfig"
	"kraftkit.sh/unikraft"
	"kraftkit.sh/unikraft/component"
	"kraftkit.sh/unikraft/core"
	"kraftkit.sh/unikraft/lib"
	"kraftkit.sh/unikraft/target"
	"kraftkit.sh/unikraft/template"
)

// ApplicationOption is a function that operates on an ApplicationConfig
type ApplicationOption func(ao *ApplicationConfig) error

// NewApplicationFromOptions accepts a series of options and returns a rendered
// *ApplicationConfig structure
func NewApplicationFromOptions(aopts ...ApplicationOption) (Application, error) {
	var err error
	ac := &ApplicationConfig{
		configuration: kconfig.KeyValueMap{},
	}

	for _, o := range aopts {
		if err := o(ac); err != nil {
			return nil, fmt.Errorf("could not apply option: %v", err)
		}
	}

	if ac.name != "" {
		ac.configuration.Set(unikraft.UK_NAME, ac.name)
	}

	if ac.outDir == "" {
		if ac.workingDir == "" {
			ac.workingDir, err = os.Getwd()
			if err != nil {
				return nil, err
			}
		}

		ac.outDir = filepath.Join(ac.workingDir, unikraft.BuildDir)
	}

	if len(ac.unikraft.Source()) > 0 {
		if p, err := os.Stat(ac.unikraft.Source()); err == nil && p.IsDir() {
			ac.configuration.Set(unikraft.UK_BASE, ac.unikraft.Source())
		}
	}

	return ac, nil
}

// WithName sets the application component name
func WithName(name string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.name = name
		return nil
	}
}

// WithVersion sets the application version
func WithVersion(version string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.version = version
		return nil
	}
}

// WithWorkingDir sets the application's working directory
func WithWorkingDir(workingDir string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.workingDir = workingDir
		return nil
	}
}

// WithFilename sets the application's file name
func WithFilename(filename string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.filename = filename
		return nil
	}
}

// WithOutDir sets the application's output directory
func WithOutDir(outDir string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.outDir = outDir
		return nil
	}
}

// WithTemplate sets the application's template
func WithTemplate(template template.TemplateConfig) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.template = template
		return nil
	}
}

// WithUnikraft sets the application's core
func WithUnikraft(unikraft core.UnikraftConfig) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.unikraft = unikraft
		return nil
	}
}

// WithLibraries sets the application's library list
func WithLibraries(libraries lib.Libraries) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.libraries = libraries
		return nil
	}
}

// WithTargets sets the application's target list
func WithTargets(targets target.Targets) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.targets = targets
		return nil
	}
}

// WithExtensions sets the application's extension list
func WithExtensions(extensions component.Extensions) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.extensions = extensions
		return nil
	}
}

// WithKraftfiles sets the application's kraft yaml files
func WithKraftfiles(kraftfiles []string) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		ac.kraftfiles = kraftfiles
		return nil
	}
}

// WithConfiguration sets the application's kconfig list
func WithConfiguration(config ...*kconfig.KeyValue) ApplicationOption {
	return func(ac *ApplicationConfig) error {
		if ac.configuration == nil {
			ac.configuration = kconfig.KeyValueMap{}
		}

		ac.configuration.Override(config...)
		return nil
	}
}
