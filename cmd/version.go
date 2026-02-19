package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xMlex/go-audit-shipper/internal/model"
)

func init() {
	versionCmd.AddCommand(versionInfoCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(model.Version)
	},
}

var versionInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print the version info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", model.Version)
		fmt.Printf("BuildDate: %s\n", model.BuildDate)
		fmt.Printf("ShortCommit: %s\n", model.ShortCommit)
		fmt.Printf("Commit: %s\n", model.Commit)
	},
}
