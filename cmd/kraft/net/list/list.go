// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file expect in compliance with the License.
package list

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	networkapi "kraftkit.sh/api/network/v1alpha1"
	"kraftkit.sh/cmdfactory"
	"kraftkit.sh/internal/tableprinter"
	"kraftkit.sh/iostreams"
	"kraftkit.sh/log"
	"kraftkit.sh/machine/network"
)

type List struct {
	Long   bool `long:"long" short:"l" usage:"Show more information"`
	driver string
}

func New() *cobra.Command {
	cmd, err := cmdfactory.New(&List{}, cobra.Command{
		Short:   "List machine networks",
		Use:     "ls [FLAGS]",
		Aliases: []string{"list"},
		Args:    cobra.NoArgs,
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "net",
		},
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *List) Pre(cmd *cobra.Command, _ []string) error {
	opts.driver = cmd.Flag("driver").Value.String()
	return nil
}

func (opts *List) Run(cmd *cobra.Command, args []string) error {
	var err error

	ctx := cmd.Context()

	strategy, ok := network.Strategies()[opts.driver]
	if !ok {
		return fmt.Errorf("unsupported network driver strategy: %s", opts.driver)
	}

	controller, err := strategy.NewNetworkV1alpha1(ctx)
	if err != nil {
		return err
	}

	networks, err := controller.List(ctx, &networkapi.NetworkList{})
	if err != nil {
		return err
	}

	type netTable struct {
		id      string
		name    string
		network string
		driver  string
		status  networkapi.NetworkState
	}

	var items []netTable

	for _, network := range networks.Items {
		addr := &net.IPNet{
			IP:   net.ParseIP(network.Spec.Gateway),
			Mask: net.IPMask(net.ParseIP(network.Spec.Netmask)),
		}
		items = append(items, netTable{
			id:      string(network.UID),
			name:    network.Name,
			network: addr.String(),
			driver:  opts.driver,
			status:  network.Status.State,
		})

	}

	err = iostreams.G(ctx).StartPager()
	if err != nil {
		log.G(ctx).Errorf("error starting pager: %v", err)
	}

	defer iostreams.G(ctx).StopPager()

	cs := iostreams.G(ctx).ColorScheme()
	table := tableprinter.NewTablePrinter(ctx)

	// Header row
	if opts.Long {
		table.AddField("MACHINE ID", nil, cs.Bold)
	}
	table.AddField("NAME", nil, cs.Bold)
	table.AddField("NETWORK", nil, cs.Bold)
	table.AddField("DRIVER", nil, cs.Bold)
	table.AddField("STATUS", nil, cs.Bold)
	table.EndRow()

	for _, item := range items {
		if opts.Long {
			table.AddField(item.id, nil, nil)
		}
		table.AddField(item.name, nil, nil)
		table.AddField(item.network, nil, nil)
		table.AddField(item.driver, nil, nil)
		table.AddField(item.status.String(), nil, nil)
		table.EndRow()
	}

	return table.Render()
}
