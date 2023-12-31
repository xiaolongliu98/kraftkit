// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package pkg

import (
	"context"
	"fmt"
	"path/filepath"

	"kraftkit.sh/initrd"
	"kraftkit.sh/unikraft"
	"kraftkit.sh/unikraft/app"
)

// initProject sets up the project based on the provided context and
// options.
func (opts *Pkg) initProject(ctx context.Context) error {
	var err error

	popts := []app.ProjectOption{
		app.WithProjectWorkdir(opts.workdir),
	}

	if len(opts.Kraftfile) > 0 {
		popts = append(popts, app.WithProjectKraftfile(opts.Kraftfile))
	} else {
		popts = append(popts, app.WithProjectDefaultKraftfiles())
	}

	// Interpret the project directory
	opts.project, err = app.NewProjectFromOptions(ctx, popts...)
	if err != nil {
		return err
	}

	return nil
}

// buildRootfs generates a rootfs based on the provided
func (opts *Pkg) buildRootfs(ctx context.Context) error {
	if opts.Rootfs == "" {
		if opts.project != nil && opts.project.Rootfs() != "" {
			opts.Rootfs = opts.project.Rootfs()
		} else {
			return nil
		}
	}

	ramfs, err := initrd.New(ctx, opts.Rootfs,
		initrd.WithOutput(filepath.Join(opts.workdir, unikraft.BuildDir, initrd.DefaultInitramfsFileName)),
		initrd.WithCacheDir(filepath.Join(opts.workdir, unikraft.VendorDir, "rootfs-cache")),
	)
	if err != nil {
		return fmt.Errorf("could not prepare initramfs: %w", err)
	}

	opts.Rootfs, err = ramfs.Build(ctx)
	if err != nil {
		return err
	}

	return nil
}
