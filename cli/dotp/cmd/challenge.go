package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/mdp/go-dotp"
	"github.com/mdp/qrterminal"
	"github.com/spf13/cobra"
)

// challengeCmd respresents the challenge command
var challengeCmd = &cobra.Command{
	Use:   "challenge",
	Short: "Create a challenge for a recipients public ID",
	Long: `This allows you to create challenges for a users public ID, which could be useful
	for debugging.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(PublicID) < 1 {
			return errors.New("Must provide the PublicID of the recipient")
		}
		_, privateKey := dotp.DeriveKeyPair(ServerSeed)
		challenge, _ := dotp.CreateChallenge(&privateKey, PublicID)
		challenge.Encrypt([]byte(args[0]), rand.Reader)
		fmt.Printf("%v\n\n", challenge.Serialize())
		qrterminal.Generate(challenge.Serialize(), qrterminal.L, os.Stdout)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(challengeCmd)
}
