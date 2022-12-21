// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2020 The Compose Specification Authors.
// Copyright 2022 Unikraft GmbH. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package app

import (
	"fmt"
	"path/filepath"

	"kraftkit.sh/schema"
	"kraftkit.sh/unikraft"
	"kraftkit.sh/unikraft/component"
)

// DefaultFileNames defines the kraft file names for auto-discovery (in order
// of preference)
var DefaultFileNames = []string{
	"kraft.yaml",
	"kraft.yml",
	"Kraftfile.yml",
	"Kraftfile.yaml",
	"Kraftfile",
}

// IsWorkdirInitialized provides a quick check to determine if whether one of
// the supported project files (Kraftfiles) is present within a provided working
// directory.
func IsWorkdirInitialized(dir string) bool {
	return len(findFiles(DefaultFileNames, dir)) > 0
}

// NewProjectFromOptions load a kraft project based on command line options
func NewProjectFromOptions(opts ...ProjectOption) (*ApplicationConfig, error) {
	popts, err := NewProjectOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("could not apply project options: %v", err)
	}

	workdir, err := popts.Workdir()
	if err != nil {
		return nil, err
	}

	absWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return nil, err
	}

	if popts.name != "" {
		popts.SetProjectName(popts.name, false)
	} else {
		popts.SetProjectName(filepath.Base(absWorkdir), true)
	}

	if len(popts.kraftfiles) < 1 {
		return nil, fmt.Errorf("no Kraft files specified")
	}

	popts.copts = append(popts.copts,
		component.WithWorkdir(workdir),
	)

	var all []*ApplicationConfig

	for i, file := range popts.kraftfiles {
		iface := file.config
		if iface == nil {
			dict, err := parseConfig(file.content, popts)
			if err != nil {
				return nil, err
			}

			iface = dict
			file.config = dict
			popts.kraftfiles[i] = file
		}

		if !popts.skipValidation {
			if err := schema.Validate(iface); err != nil {
				return nil, err
			}
		}

		iface = groupXFieldsIntoExtensions(iface)

		app, err := NewApplicationFromInterface(iface, popts)
		if err != nil {
			return nil, err
		}

		all = append(all, app)
	}

	app, err := MergeApplicationConfigs(all)
	if err != nil {
		return nil, err
	}

	projectName, _ := popts.GetProjectName()
	if app.ComponentConfig.Name != "" {
		projectName = app.ComponentConfig.Name
	}

	if !popts.skipNormalization {
		projectName = normalizeProjectName(projectName)
	}

	popts.kconfig.OverrideBy(app.unikraft.Configuration)

	for _, library := range app.libraries {
		popts.kconfig.OverrideBy(library.Configuration)
	}

	project, err := NewApplicationFromOptions(
		WithName(projectName),
		WithWorkingDir(popts.workdir),
		WithFilename(app.filename),
		WithOutDir(app.outDir),
		WithUnikraft(app.unikraft),
		WithTemplate(app.template),
		WithLibraries(app.libraries),
		WithTargets(app.targets),
		WithConfiguration(popts.kconfig),
		WithExtensions(app.extensions),
	)
	if err != nil {
		return nil, err
	}

	project.ComponentConfig.Name = projectName

	project.ApplyOptions(append(popts.copts,
		component.WithType(unikraft.ComponentTypeApp),
	)...)

	if !popts.skipNormalization {
		err = normalize(project, popts.resolvePaths)
		if err != nil {
			return nil, err
		}
	}

	return project, nil
}
