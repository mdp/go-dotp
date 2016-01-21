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
	Short: "Generate a PublicID base on a seed",
	Long: `Generate a PublicID based on a seed. If the seed is in the form of a dAuth
	backup key, add the flag --dauth`,
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
