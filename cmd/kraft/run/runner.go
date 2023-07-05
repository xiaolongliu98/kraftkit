// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package run

import (
	"context"
	"fmt"

	machineapi "kraftkit.sh/api/machine/v1alpha1"
	"kraftkit.sh/packmanager"
)

// runner is an interface for defining different mechanisms to execute the
// provided unikernel.  Standardizing first the check, Runnable, to determine
// whether the provided input is capable of executing, and Prepare, actually
// performing the preparation of the Machine specification for the controller.
type runner interface {
	// String implements fmt.Stringer and returns the name of the implementing
	// runner.
	fmt.Stringer

	// Runnable checks whether the provided configuration is runnable.
	Runnable(context.Context, *Run, ...string) (bool, error)

	// Prepare the provided configuration into a machine specification ready for
	// execution by the controller.
	Prepare(context.Context, *Run, *machineapi.Machine, ...string) error
}

// runners is the list of built-in runners which are checked sequentially for
// capability.  The first to test positive via Runnable is used with the
// controller.
func runners() []runner {
	r := []runner{
		&runnerLinuxu{},
		&runnerKernel{},
		&runnerProject{},
	}

	for _, pm := range packmanager.PackageManagers() {
		r = append(r, &runnerPackage{
			pm: pm,
		})
	}

	return r
}

// runnersByName is a utility method that returns a map of the available runners
// such that their alias name can be quickly looked up.
func runnersByName() map[string]runner {
	runners := runners()
	ret := make(map[string]runner, len(runners))
	for _, runner := range runners {
		ret[runner.String()] = runner
	}
	return ret
}
