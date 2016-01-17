package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mdp/go-dotp"
	"github.com/mdp/qrterminal"
	"github.com/spf13/cobra"
)

// challengeCmd respresents the challenge command
var challengeCmd = &cobra.Command{
	Use:   "challenge",
	Short: "Create a challenge for a recipients public ID",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a Cli library for Go that empowers applications. This
application is a tool to generate the needed files to quickly create a Cobra
application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(ServerSeed) < 1 {
			return errors.New("Must provide a server seed")
		}
		if len(PublicID) < 1 {
			return errors.New("Must provide the PublicID of the recipient")
		}
		_, privateKey := dotp.DeriveKeyPair(ServerSeed)
		challenge, _ := dotp.CreateChallenge(&privateKey, PublicID)
		challenge.Encrypt([]byte(args[0]), time.Now().Unix()+int64(ExpiresIn), rand.Reader)
		fmt.Printf("%v\n\n", challenge.Serialize())
		qrterminal.Generate(challenge.Serialize(), qrterminal.L, os.Stdout)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(challengeCmd)
}
