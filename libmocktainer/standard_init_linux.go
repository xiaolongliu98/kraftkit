// SPDX-License-Identifier: Apache-2.0
// Copyright 2014 Docker, Inc.
// Copyright 2023 Unikraft GmbH and The KraftKit Authors

package libmocktainer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/system"

	"kraftkit.sh/libmocktainer/configs"
	"kraftkit.sh/libmocktainer/unikraft"
)

type linuxStandardInit struct {
	pipe      *os.File
	parentPid int
	fifoFd    int
	logFd     int
	config    *initConfig
}

func (l *linuxStandardInit) getSessionRingParams() (string, uint32, uint32) {
	var newperms uint32 //nolint:gosimple

	// Without user ns we need 'UID' search permissions.
	newperms = 0x80000

	// Create a unique per session container name that we can join in setns;
	// However, other containers can also join it.
	return "_ses." + l.config.ContainerID, 0xffffffff, newperms
}

func (l *linuxStandardInit) Init() error {
	if err := selinux.SetKeyLabel(l.config.ProcessLabel); err != nil {
		return err
	}
	defer selinux.SetKeyLabel("") //nolint: errcheck
	ringname, keepperms, newperms := l.getSessionRingParams()

	/**
	这段代码主要是关于 Linux 系统中的 SELinux 安全模块和会话密钥环（session keyring）的操作。
	首先，`selinux.SetKeyLabel(l.config.ProcessLabel)` 设置了当前进程的 SELinux 标签。
	如果出现错误，函数会直接返回这个错误。然后，使用 `defer` 关键字保证在函数返回时，
	无论因为什么原因返回，都会执行 `selinux.SetKeyLabel("")` 来清除设置的标签。
	接下来，`keys.JoinSessionKeyring(ringname)` 尝试加入一个名为 `ringname` 的会话密钥环。
	如果操作失败，函数会检查错误是否是因为系统不支持密钥环（可能是在旧版本的内核或者 LXC 容器中运行）。
	如果是这种情况，函数会忽略错误并继续执行，因为这个安全特性只是尽力而为的，并不能提供强有力的保护。
	如果错误的原因不是系统不支持密钥环，函数会返回一个包含详细错误信息的新错误。
	如果成功加入了密钥环，函数会尝试修改密钥环的权限。如果这个操作失败，函数会返回一个包含详细错误信息的新错误。
	这段代码的主要目标是尽可能地提高程序的安全性。通过设置 SELinux 标签和使用密钥环，
	可以限制进程的权限，防止它进行一些可能危害系统安全的操作。
	*/
	// Do not inherit the parent's session keyring.
	if sessKeyId, err := keys.JoinSessionKeyring(ringname); err != nil {
		// If keyrings aren't supported then it is likely we are on an
		// older kernel (or inside an LXC container). While we could bail,
		// the security feature we are using here is best-effort (it only
		// really provides marginal protection since VFS credentials are
		// the only significant protection of keyrings).
		//
		// TODO(cyphar): Log this so people know what's going on, once we
		//               have proper logging in 'runc init'.
		if !errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("unable to join session keyring: %w", err)
		}
	} else {
		// Make session keyring searchable. If we've gotten this far we
		// bail on any error -- we don't want to have a keyring with bad
		// permissions.
		if err := keys.ModKeyringPerm(sessKeyId, keepperms, newperms); err != nil {
			return fmt.Errorf("unable to mod keyring permissions: %w", err)
		}
	}

	if err := setupNetwork(l.config); err != nil {
		return err
	}
	if err := setupRoute(l.config.Config); err != nil {
		return err
	}

	// initialises the labeling system
	selinux.GetEnabled()

	// We don't need the mount nor idmap fds after prepareRootfs() nor if it fails.
	// 这段注释的意思是，在调用 prepareRootfs() 函数（准备根文件系统）之后，
	//无论函数是否成功，我们都不再需要挂载文件描述符（mountFds）和 idmap 文件描述符。
	//文件描述符通常是用于操作文件或者其他资源的标识符。
	//这里的挂载文件描述符可能是用于挂载文件系统，而 idmap 文件描述符可能是用于管理用户和组的映射关系。
	err := prepareRootfs(l.pipe, l.config, mountFds{})
	if err != nil {
		return err
	}

	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return fmt.Errorf("unable to apply apparmor profile: %w", err)
	}

	pdeath, err := system.GetParentDeathSignal()
	if err != nil {
		return fmt.Errorf("can't get pdeath signal: %w", err)
	}
	// Tell our parent that we're ready to Execv. This must be done before the
	// Seccomp rules have been applied, because we need to be able to read and
	// write to a socket.
	// 告诉我们的“父进程”（创建当前进程的程序），我们已经准备好执行 Execv 操作。
	// Execv 是一个系统调用，它用于在当前进程中执行一个新的程序。
	// 这个通知必须在应用 Seccomp 规则之前完成，因为我们需要能够读取和写入一个网络套接字。
	// Seccomp 是一种在 Linux 中限制进程可以执行的系统调用的安全机制，一旦应用，可能会阻止我们进行网络操作。
	if err := syncParentReady(l.pipe); err != nil {
		return fmt.Errorf("sync ready: %w", err)
	}
	if err := selinux.SetExecLabel(l.config.ProcessLabel); err != nil {
		return fmt.Errorf("can't set process label: %w", err)
	}
	defer selinux.SetExecLabel("") //nolint: errcheck
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	// finalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	// 在这里，注释是说 finalizeNamespace 函数可能会改变用户或者组的设置，
	//这个操作可能会清除所谓的 "父进程死亡信号"。父进程死亡信号是一种机制，
	//当父进程结束时，子进程会收到一个信号。如果这个信号被清除，子进程可能无法
	//得知其父进程已经结束。因此，在 finalizeNamespace 操作之后，代码需要恢复这个信号。
	if err := pdeath.Restore(); err != nil {
		return fmt.Errorf("can't restore pdeath signal: %w", err)
	}
	// Compare the parent from the initial start of the init process and make
	// sure that it did not change.  if the parent changes that means it died
	// and we were reparented to something else so we should just kill ourself
	// and not cause problems for someone else.
	if unix.Getppid() != l.parentPid {
		return unix.Kill(unix.Getpid(), unix.SIGKILL)
	}
	// Check for the arg before waiting to make sure it exists and it is
	// returned as a create time error.
	name, err := exec.LookPath(l.config.Args[0])
	if err != nil {
		return err
	}

	// Close the pipe to signal that we have completed our init.
	logrus.Debugf("init: closing the pipe to signal completion")
	_ = l.pipe.Close()

	// Close the log pipe fd so the parent's ForwardLogs can exit.
	if err := unix.Close(l.logFd); err != nil {
		return &os.PathError{Op: "close log pipe", Path: "fd " + strconv.Itoa(l.logFd), Err: err}
	}

	// Wait for the FIFO to be opened on the other side before exec-ing the
	// user process. We open it through /proc/self/fd/$fd, because the fd that
	// was given to us was an O_PATH fd to the fifo itself. Linux allows us to
	// re-open an O_PATH fd through /proc.
	//这段注释的意思是，代码在执行用户进程之前，要等待 FIFO（First In First Out，
	//先进先出的通信方式）在另一侧被打开。这个 FIFO 可能是用于进程间通信的一种方式。
	//这里通过 /proc/self/fd/$fd 来打开 FIFO，这是因为给到这段代码的文件描述符是一个
	//O_PATH 文件描述符，它指向 FIFO 本身。在 Linux 系统中，我们可以通过 /proc
	//文件系统来重新打开一个 O_PATH 文件描述符。
	fifoPath := "/proc/self/fd/" + strconv.Itoa(l.fifoFd)
	fd, err := unix.Open(fifoPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open exec fifo", Path: fifoPath, Err: err}
	}
	if _, err := unix.Write(fd, []byte("0")); err != nil {
		return &os.PathError{Op: "write exec fifo", Path: fifoPath, Err: err}
	}

	// -- BEGIN Unikraft

	var isUnikernel bool
	for _, lbl := range l.config.Config.Labels {
		if lbl == "org.unikraft.kernel=" { // injected by `runu create`
			isUnikernel = true
			break
		}
	}

	if isUnikernel {
		// This must happen in the Start phase of the OCI startup flow, right
		// before exec(), because the setup of the container's network interfaces
		// typically happens between the Create and the Start phases (e.g. CNI).
		//这段注释的意思是，某个操作必须在 OCI的启动流程的 Start 阶段进行，也就是在执行 exec()
		//系统调用（启动新程序）之前。这是因为容器的网络接口通常会在 Create
		//阶段（创建容器）和 Start 阶段（启动容器）之间进行设置。
		//这里提到的 CNI 是 Container Network Interface，
		//容器网络接口，是一种用于配置和管理容器的网络接口的插件。
		qemuNetArgs, err := unikraft.SetupQemuNet()
		if err != nil {
			return fmt.Errorf("setting up qemu network: %w", err)
		}
		l.config.Args = append(l.config.Args, qemuNetArgs...)
	}

	// -- END Unikraft

	// Close the O_PATH fifofd fd before exec because the kernel resets
	// dumpable in the wrong order. This has been fixed in newer kernels, but
	// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
	// N.B. the core issue itself (passing dirfds to the host filesystem) has
	// since been resolved.
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	//这段注释是在讨论一个特定的安全问题，CVE-2016-9962，这是一个在某些版本的 Linux 内核中存在的漏洞。
	//在这个漏洞中，如果在错误的顺序中重置 dumpable
	//（这是一个标志，用于控制是否允许将进程的内存转储到文件），可能会导致安全问题。
	//为了防止这个问题，代码在执行 exec（启动新程序）之前关闭了 O_PATH 的 fifofd 文件描述符。
	//虽然在新版的内核中已经修复了这个问题，但为了防止在旧版内核上重新出现这个问题，代码仍然执行了这个步骤。
	//最后，注释提到核心问题（将目录文件描述符传递给主机文件系统）已经得到解决。
	//目录文件描述符是一种特殊类型的文件描述符，它代表了一个目录。在早期的版本中，
	//将这种描述符传递给主机可能会导致安全问题，但现在这个问题已经解决了。
	_ = unix.Close(l.fifoFd)

	s := l.config.SpecState
	s.Pid = unix.Getpid()
	s.Status = specs.StateCreated
	if err := l.config.Config.Hooks[configs.StartContainer].RunHooks(s); err != nil {
		return err
	}

	// runc中封装的syscall.Exec()函数，在循环中不断执行
	return system.Exec(name, l.config.Args[0:], os.Environ())
}
