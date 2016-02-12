package cmd

import (
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
		var publicKey *[32]byte
		var secretKey *[32]byte
		if len(args) >= 1 {
			seed = args[0]
			if dAuth {
				seed = strings.Replace(seed, " ", "", -1)
				seed = strings.ToUpper(seed)
			}
			fmt.Printf("Creating key with a seed string '%s'\n", seed)
			publicKey, secretKey = dotp.DeriveKeyPair(seed)
		} else {
			publicKey, secretKey, _ = dotp.GenerateKeyPair()
		}
		recPubID := dotp.GetPublicID(publicKey)
		fmt.Printf("PublicID: %s\n", recPubID)
		fmt.Printf("PrivateKey: %s\n", b58.Encode(secretKey[:]))
		return nil
	},
}

func init() {
	RootCmd.AddCommand(generateCmd)
	generateCmd.Flags().BoolVarP(&dAuth, "dauth", "d", false, "Create a KeyPair from a dAuth backup seed")
}
