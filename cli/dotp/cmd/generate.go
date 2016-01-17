package cmd

import (
	"errors"
	"fmt"

	"github.com/mdp/go-dotp"
	"github.com/spf13/cobra"
)

var seed string

// generateCmd respresents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a Cli library for Go that empowers applications. This
application is a tool to generate the needed files to quickly create a Cobra
application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("Must provide a seed to build a keypair from")
		}
		publicKey, _ := dotp.DeriveKeyPair(seed)
		recPubID := dotp.GetPublicID(&publicKey)
		fmt.Printf("\nPublicID: %s\n", recPubID)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(generateCmd)
}
