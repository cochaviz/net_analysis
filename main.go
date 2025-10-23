package main

import (
	"cochaviz/net_analysis/cmd"

	"github.com/spf13/cobra"
)

// Execute runs the CLI root command.
func main() {
	err := cmd.RootCmd.Execute()

	if err != nil {
		cobra.CheckErr(err)
	}
}
