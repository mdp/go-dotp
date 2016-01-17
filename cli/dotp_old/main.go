package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/codegangsta/cli"
	dotp "github.com/mdp/go-dotp"
	"github.com/mdp/qrterminal"
)

func main() {
	_, privateKey := dotp.DeriveKeyPair("TEST")
	recipientPubKey, _ := dotp.DeriveKeyPair("ClientSecret")
	recPubID := dotp.GetPublicID(&recipientPubKey)
	app := cli.NewApp()
	app.Name = "dotp"
	app.Action = func(c *cli.Context) {
		challenge, _ := dotp.CreateChallenge(&privateKey, recPubID)
		challenge.Encrypt([]byte("OTP"), time.Now().Unix()+3000, rand.Reader)
		fmt.Printf("%v\n\n", challenge.Serialize())
		qrterminal.Generate(challenge.Serialize(), qrterminal.L, os.Stdout)
	}
	app.Run(os.Args)
}
