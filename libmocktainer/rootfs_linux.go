// SPDX-License-Identifier: Apache-2.0
// Copyright 2014 Docker, Inc.
// Copyright 2023 Unikraft GmbH and The KraftKit Authors

package libmocktainer

import (
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"kraftkit.sh/libmocktainer/configs"
)

// prepareRootfs sets up the devices, mount points, and filesystems for use
// inside a new mount namespace. It doesn't set anything as ro. You must call
// finalizeRootfs after this function to finish setting up the rootfs.
// prepareRootfs 为新的挂载命名空间内部使用设置设备、挂载点和文件系统。
// 它不会将任何东西设置为只读。你必须在此函数之后调用 finalizeRootfs，以完成根文件系统的设置。
func prepareRootfs(pipe *os.File, iConfig *initConfig, _ mountFds) (err error) {
	config := iConfig.Config

	// 向父进程发出信号，运行预启动钩子。
	// 这些钩子在挂载点设置完成后运行，但在我们切换到新的根之前，这样旧的根在钩子中仍然可用于任何挂载操作。

	// Signal the parent to run the pre-start hooks.
	// The hooks are run after the mounts are setup, but before we switch to the new
	// root, so that the old root is still available in the hooks for any mount
	// manipulations.
	if err := syncParentHooks(pipe); err != nil {
		return err
	}

	// 这些操作在这里进行而不是在 finalizeRootfs 中的原因是，
	// 如果我们必须在执行 pivot_root(2) 之前设置控制台，那么处理控制台的代码会变得非常棘手。
	// 这是因为 Console API 也必须能够处理 ExecIn 的情况，这意味着 API 必须能够处理在容器内部以及外部的情况。
	// 在这里执行这个操作（尽管这样做使得操作并未完全分离）更为清晰。
	// The reason these operations are done here rather than in finalizeRootfs
	// is because the console-handling code gets quite sticky if we have to set
	// up the console before doing the pivot_root(2). This is because the
	// Console API has to also work with the ExecIn case, which means that the
	// API must be able to deal with being inside as well as outside the
	// container. It's just cleaner to do this here (at the expense of the
	// operation not being perfectly split).

	if err := unix.Chdir(config.Rootfs); err != nil {
		return &os.PathError{Op: "chdir", Path: config.Rootfs, Err: err}
	}

	s := iConfig.SpecState
	s.Pid = unix.Getpid()
	s.Status = specs.StateCreating
	if err := iConfig.Config.Hooks[configs.CreateContainer].RunHooks(s); err != nil {
		return err
	}

	return nil
}

// syncParentHooks sends to the given pipe a JSON payload which indicates that
// the parent should execute pre-start hooks. It then waits for the parent to
// indicate that it is cleared to resume.
func syncParentHooks(pipe *os.File) error {
	// Tell parent.
	if err := writeSync(pipe, procHooks); err != nil {
		return err
	}
	// Wait for parent to give the all-clear.
	return readSync(pipe, procResume)
}
