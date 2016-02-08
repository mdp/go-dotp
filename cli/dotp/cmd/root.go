package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// PublicID we are working with
var PublicID string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "dotp",
	Short: "A command line interface for dOTP",
	Long:  `dOTP tools program, useful for debugging and working with dOTP`,
}

//Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&PublicID, "pubid", "", "PublicID of the recipient")
}
