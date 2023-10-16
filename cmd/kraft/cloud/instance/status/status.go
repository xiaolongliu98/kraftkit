// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package status

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	kraftcloud "sdk.kraft.cloud"
	kcinstance "sdk.kraft.cloud/instance"

	"kraftkit.sh/cmd/kraft/cloud/utils"
	"kraftkit.sh/cmdfactory"
	"kraftkit.sh/config"
	"kraftkit.sh/log"
)

type Status struct {
	Output string `long:"output" short:"o" usage:"Set output format" default:"table"`

	metro string
}

func New() *cobra.Command {
	cmd, err := cmdfactory.New(&Status{}, cobra.Command{
		Short:   "Retrieve the status of an instance",
		Use:     "status [FLAGS] UUID",
		Args:    cobra.ExactArgs(1),
		Aliases: []string{"info"},
		Example: heredoc.Doc(`
			# Retrieve information about a kraftcloud instance
			$ kraft cloud instance status fd1684ea-7970-4994-92d6-61dcc7905f2b
	`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "kraftcloud-instance",
		},
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *Status) Pre(cmd *cobra.Command, _ []string) error {
	opts.metro = cmd.Flag("metro").Value.String()
	if opts.metro == "" {
		opts.metro = os.Getenv("KRAFTCLOUD_METRO")
	}
	if opts.metro == "" {
		return fmt.Errorf("kraftcloud metro is unset")
	}
	log.G(cmd.Context()).WithField("metro", opts.metro).Debug("using")
	return nil
}

func (opts *Status) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	auth, err := config.GetKraftCloudLoginFromContext(ctx)
	if err != nil {
		return fmt.Errorf("could not retrieve credentials: %w", err)
	}

	client := kcinstance.NewInstancesClient(
		kraftcloud.WithToken(auth.Token),
	)

	instance, err := client.WithMetro(opts.metro).Status(ctx, args[0])
	if err != nil {
		return fmt.Errorf("could not create instance: %w", err)
	}

	return utils.PrintInstances(ctx, opts.Output, *instance)
}
