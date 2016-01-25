package cmd

import (
	"errors"
	"fmt"
	"strings"

	b58 "github.com/btcsuite/btcutil/base58"
	"github.com/mdp/go-dotp"
	"github.com/spf13/cobra"
)

var seed string
var dAuth bool

// generateCmd respresents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a KeyPair based on a seed",
	Long: `Generate a KeyPair based on a seed. If the seed is in the form of a dAuth
	backup key, add the flag --dauth`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("Must provide a seed to build a keypair from")
		}
		seed = args[0]
		if dAuth {
			seed = strings.Replace(seed, " ", "", -1)
			seed = strings.ToUpper(seed)
		}
		publicKey, privateKey := dotp.DeriveKeyPair(seed)
		recPubID := dotp.GetPublicID(&publicKey)
		fmt.Printf("\nPublicID: %s\n", recPubID)
		fmt.Printf("\nPrivateKey: %s\n", b58.Encode(privateKey[:]))
		return nil
	},
}

func init() {
	RootCmd.AddCommand(generateCmd)
	generateCmd.Flags().BoolVarP(&dAuth, "dauth", "d", false, "Create a KeyPair from a dAuth backup seed")
}
