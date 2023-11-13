// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package main

import (
	"os"

	_ "github.com/opencontainers/runc/libcontainer/nsenter"

	libcontainer "kraftkit.sh/libmocktainer"
)

/*
*
这段代码是 Go 语言程序的 `init` 函数。在 Go 语言中，`init` 函数会在程序的 `main` 函数之前自动执行。
你可以在任何包中定义多个 `init` 函数，它们都会在 `main` 函数开始之前按照它们的定义顺序执行。

这段代码首先检查命令行参数 `os.Args`。如果参数的数量超过 1 且第二个参数（索引为 1）是 "init"，
那么就会调用 `libcontainer.Init()`。这是 runc（一个用于创建和运行容器的工具）的初始化过程的一部分。

这个初始化过程在 `main` 函数之前，但是在 `libcontainer/nsenter` 的 `nsexec()` 之后执行。
`libcontainer/nsenter` 是一个用于管理 Linux 命名空间的库，而 `nsexec()` 是这个库中用于执行命名空间切换的函数。

总结一下，这段代码的作用是，在 runc 的主程序开始之前，但在执行命名空间切换之后，
如果命令行参数包含 "init"，就进行一些初始化操作。
*/
// args: runu init ...
func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		// This is the golang entry point for runc init, executed
		// before main() but after libcontainer/nsenter's nsexec().
		libcontainer.Init()
	}
}
