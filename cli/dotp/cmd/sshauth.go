package cmd

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mdp/go-dotp"
	"github.com/mdp/qrterminal"
	"github.com/spf13/cobra"
)

var forceDOTP bool

const base32 = "023456789abcdefghjkmnpqrstuvwxyz"
const base10 = "0123456789"

func randString(n int, numericOnly bool) string {
	charset := []byte(base32)
	if numericOnly {
		charset = []byte(base10)
	}
	b := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range b {
		r, _ := rand.Int(rand.Reader, charsetLen)
		b[i] = charset[r.Uint64()]
	}
	return string(b)
}

// sshauthCmd respresents the sshauth command
var sshauthCmd = &cobra.Command{
	Use:   "sshauth",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a Cli library for Go that empowers applications. This
application is a tool to generate the needed files to quickly create a Cobra
application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		otp := randString(6, true)
		if len(ServerSeed) < 1 {
			return errors.New("Must provide a server seed")
		}
		if len(PublicID) < 1 {
			return errors.New("Must provide the PublicID of the recipient")
		}
		_, privateKey := dotp.DeriveKeyPair(ServerSeed)
		challenge, _ := dotp.CreateChallenge(&privateKey, PublicID)
		challenge.Encrypt([]byte(otp), time.Now().Unix()+int64(ExpiresIn), rand.Reader)
		fmt.Printf("%v\n\n", challenge.Serialize())
		qrterminal.Generate(challenge.Serialize(), qrterminal.L, os.Stdout)
		auth(otp)
		return nil
	},
}

func auth(otp string) {
	fmt.Printf("OTP: %v\n", otp)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter OTP: ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSuffix(text, "\n")
	if otp == text {
		fmt.Println("Successful Auth\n")
		giveShell()
	}
}

func giveShell() {
	cmd := exec.Command(os.Getenv("SHELL"))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	RootCmd.AddCommand(sshauthCmd)

	sshauthCmd.Flags().BoolVarP(&forceDOTP, "force", "f", false, "Enforce dOTP auth, users without dotp public keys will not be able to continue")

}
