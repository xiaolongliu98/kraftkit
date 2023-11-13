// SPDX-License-Identifier: Apache-2.0
// Copyright 2014 Docker, Inc.
// Copyright 2023 Unikraft GmbH and The KraftKit Authors

package libmocktainer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/opencontainers/runc/libcontainer/logs"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"kraftkit.sh/libmocktainer/configs"
)

type parentProcess interface {
	// pid returns the pid for the running process.
	pid() int

	// start starts the process execution.
	start() error

	// send a SIGKILL to the process and wait for the exit.
	terminate() error

	// wait waits on the process returning the process state.
	wait() (*os.ProcessState, error)

	// startTime returns the process start time.
	startTime() (uint64, error)
	signal(os.Signal) error
	externalDescriptors() []string
	setExternalDescriptors(fds []string)
	forwardChildLogs() chan error
}

type filePair struct {
	parent *os.File
	child  *os.File
}

type initProcess struct {
	cmd             *exec.Cmd
	messageSockPair filePair
	logFilePair     filePair
	config          *initConfig
	container       *Container
	fds             []string
	process         *Process
	bootstrapData   io.Reader
}

func (p *initProcess) pid() int {
	return p.cmd.Process.Pid
}

func (p *initProcess) externalDescriptors() []string {
	return p.fds
}

// getChildPid receives the final child's pid over the provided pipe.
func (p *initProcess) getChildPid() (int, error) {
	var pid pid
	if err := json.NewDecoder(p.messageSockPair.parent).Decode(&pid); err != nil {
		_ = p.cmd.Wait()
		return -1, err
	}

	// Clean up the zombie parent process
	// On Unix systems FindProcess always succeeds.
	firstChildProcess, _ := os.FindProcess(pid.PidFirstChild)

	// Ignore the error in case the child has already been reaped for any reason
	_, _ = firstChildProcess.Wait()

	return pid.Pid, nil
}

func (p *initProcess) waitForChildExit(childPid int) error {
	status, err := p.cmd.Process.Wait()
	if err != nil {
		_ = p.cmd.Wait()
		return err
	}
	if !status.Success() {
		_ = p.cmd.Wait()
		return &exec.ExitError{ProcessState: status}
	}

	process, err := os.FindProcess(childPid)
	if err != nil {
		return err
	}
	p.cmd.Process = process
	p.process.ops = p
	return nil
}

func (p *initProcess) start() (retErr error) {
	defer p.messageSockPair.parent.Close() //nolint: errcheck
	err := p.cmd.Start()
	p.process.ops = p
	// close the write-side of the pipes (controlled by child)
	_ = p.messageSockPair.child.Close()
	_ = p.logFilePair.child.Close()
	if err != nil {
		p.process.ops = nil
		return fmt.Errorf("unable to start init: %w", err)
	}

	waitInit := initWaiter(p.messageSockPair.parent)
	defer func() {
		if retErr != nil {
			// [Receive] error from the child
			werr := <-waitInit
			if werr != nil {
				logrus.WithError(werr).Warn()
			}

			// Terminate the process to ensure we can remove cgroups.
			if err := ignoreTerminateErrors(p.terminate()); err != nil {
				logrus.WithError(err).Warn("unable to terminate initProcess")
			}
		}
	}()

	// [Send] bootstrap data to the child, bootstrapData contains namespaces config
	if _, err := io.Copy(p.messageSockPair.parent, p.bootstrapData); err != nil {
		return fmt.Errorf("can't copy bootstrap data to pipe: %w", err)
	}
	// [Receive] error from the child
	err = <-waitInit
	if err != nil {
		return err
	}

	// [Receive] final child's PID from the child
	childPid, err := p.getChildPid()
	if err != nil {
		return fmt.Errorf("can't get final child's PID from pipe: %w", err)
	}

	// Save the standard descriptor names before the container process
	// can potentially move them (e.g., via dup2()).  If we don't do this now,
	// we won't know at checkpoint time which file descriptor to look up.
	fds, err := getPipeFds(childPid)
	if err != nil {
		return fmt.Errorf("error getting pipe fds for pid %d: %w", childPid, err)
	}
	p.setExternalDescriptors(fds)

	// [Receive] wait for the child's runc-init1:stage to exit
	// Wait for our first child to exit
	if err := p.waitForChildExit(childPid); err != nil {
		return fmt.Errorf("error waiting for our first child to exit: %w", err)
	}

	if err := p.createNetworkInterfaces(); err != nil {
		return fmt.Errorf("error creating network interfaces: %w", err)
	}
	if err := p.updateSpecState(); err != nil {
		return fmt.Errorf("error updating spec state: %w", err)
	}

	// [Send] 在这里发送了initConfig到了runc-init2:stage，里面包含了args启动参数
	if err := p.sendConfig(); err != nil {
		return fmt.Errorf("error sending config to init process: %w", err)
	}

	var seenProcReady bool

	// [Blocked]
	// [Receive] procReady from the child
	ierr := parseSync(p.messageSockPair.parent, func(sync *syncT) error {
		switch sync.Type {
		case procReady:
			seenProcReady = true

			// generate a timestamp indicating when the container was started
			p.container.created = time.Now().UTC()
			p.container.state = &createdState{
				c: p.container,
			}

			// NOTE: If the procRun state has been synced and the
			// runc-create process has been killed for some reason,
			// the runc-init[2:stage] process will be leaky. And
			// the runc command also fails to parse root directory
			// because the container doesn't have state.json.
			//
			// In order to cleanup the runc-init[2:stage] by
			// runc-delete/stop, we should store the status before
			// procRun sync.

			// 注意：如果procRun状态已经同步，并且出于某种原因runc-create进程被杀死，
			// 那么runc-init[2:stage]进程将会出现泄漏。同时，
			// runc命令也会因为容器缺少state.json而无法解析根目录。

			// 为了能够通过runc-delete/stop命令清理runc-init[2:stage]，
			// 我们应该在procRun同步之前存储状态。
			state, uerr := p.container.updateState(p)
			if uerr != nil {
				return fmt.Errorf("unable to store init state: %w", uerr)
			}
			p.container.initProcessStartTime = state.InitProcessStartTime

			// [Send] procRun to the child
			// Sync with child.
			if err := writeSync(p.messageSockPair.parent, procRun); err != nil {
				return err
			}

		case procHooks:
			if len(p.config.Config.Hooks) != 0 {
				s, err := p.container.currentOCIState()
				if err != nil {
					return err
				}
				// initProcessStartTime hasn't been set yet.
				s.Pid = p.cmd.Process.Pid
				s.Status = specs.StateCreating
				hooks := p.config.Config.Hooks

				if err := hooks[configs.Prestart].RunHooks(s); err != nil {
					return err
				}
				if err := hooks[configs.CreateRuntime].RunHooks(s); err != nil {
					return err
				}
			}
			// [Send] procHooksDone to the child
			// Sync with child.
			if err := writeSync(p.messageSockPair.parent, procResume); err != nil {
				return err
			}
		default:
			return errors.New("invalid JSON payload from child")
		}
		return nil
	})

	// [Send] shutdown to the child
	if err := unix.Shutdown(int(p.messageSockPair.parent.Fd()), unix.SHUT_WR); err != nil && ierr == nil {
		return &os.PathError{Op: "shutdown", Path: "(init pipe)", Err: err}
	}
	if !seenProcReady && ierr == nil {
		ierr = errors.New("procReady not received")
	}
	if ierr != nil {
		return fmt.Errorf("error during container init: %w", ierr)
	}
	return nil
}

func (p *initProcess) wait() (*os.ProcessState, error) {
	err := p.cmd.Wait()
	return p.cmd.ProcessState, err
}

func (p *initProcess) terminate() error {
	if p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	if _, werr := p.wait(); err == nil {
		err = werr
	}
	return err
}

func (p *initProcess) startTime() (uint64, error) {
	stat, err := system.Stat(p.pid())
	return stat.StartTime, err
}

func (p *initProcess) updateSpecState() error {
	s, err := p.container.currentOCIState()
	if err != nil {
		return err
	}

	p.config.SpecState = s
	return nil
}

func (p *initProcess) sendConfig() error {
	// send the config to the container's init process, we don't use JSON Encode
	// here because there might be a problem in JSON decoder in some cases, see:
	// https://github.com/docker/docker/issues/14203#issuecomment-174177790
	return utils.WriteJSON(p.messageSockPair.parent, p.config)
}

func (p *initProcess) createNetworkInterfaces() error {
	for _, config := range p.config.Config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		n := &network{
			Network: *config,
		}
		if err := strategy.create(n, p.pid()); err != nil {
			return err
		}
		p.config.Networks = append(p.config.Networks, n)
	}
	return nil
}

func (p *initProcess) signal(sig os.Signal) error {
	s, ok := sig.(unix.Signal)
	if !ok {
		return errors.New("os: unsupported signal type")
	}
	return unix.Kill(p.pid(), s)
}

func (p *initProcess) setExternalDescriptors(newFds []string) {
	p.fds = newFds
}

func (p *initProcess) forwardChildLogs() chan error {
	return logs.ForwardLogs(p.logFilePair.parent)
}

/*
*
这个 getPipeFds 函数的目的是获取一个进程的前三个文件描述符（通常是标准输入、标准输出和标准错误）的路径。
在 Linux 系统中，进程的文件描述符（FDs）可以通过 /proc/[pid]/fd 目录来访问。
这段代码假设文件描述符 0、1 和 2 分别对应于标准输入、输出和错误。

函数接受一个进程ID（pid），并返回一个字符串切片，其中包含前三个文件描述符的目标路径。
*/
func getPipeFds(pid int) ([]string, error) {

	fds := make([]string, 3)

	dirPath := filepath.Join("/proc", strconv.Itoa(pid), "/fd")
	for i := 0; i < 3; i++ {
		// XXX: This breaks if the path is not a valid symlink (which can
		//      happen in certain particularly unlucky mount namespace setups).
		f := filepath.Join(dirPath, strconv.Itoa(i))
		target, err := os.Readlink(f)
		if err != nil {
			// Ignore permission errors, for rootless containers and other
			// non-dumpable processes. if we can't get the fd for a particular
			// file, there's not much we can do.
			if os.IsPermission(err) {
				continue
			}
			return fds, err
		}
		fds[i] = target
	}
	return fds, nil
}

// initWaiter returns a channel to wait on for making sure
// runc init has finished the initial setup.
func initWaiter(r io.Reader) chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)

		inited := make([]byte, 1)
		n, err := r.Read(inited)
		if err == nil {
			if n < 1 {
				err = errors.New("short read")
			} else if inited[0] != 0 {
				err = fmt.Errorf("unexpected %d != 0", inited[0])
			} else {
				ch <- nil
				return
			}
		}
		ch <- fmt.Errorf("waiting for init preliminary setup: %w", err)
	}()

	return ch
}
