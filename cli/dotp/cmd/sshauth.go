package cmd

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"

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
	Short: "TwoFactor auth for SSH",
	Long: `This allows you to quickly implement two factor authentication in ssh.
	Use the ForceCommand in sshd_config to run this program upon login. User will
	then be presented with a QR Code challenge to authenticate. Assumes the user has
	a dotp public ID and that it is written to '$HOME/.dotp_id'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		otp := randString(6, true)
		publicID, err := getPublicID()
		if err != nil {
			return err
		}
		_, privateKey, err := dotp.RandomKeyPair(rand.Reader)
		if err != nil {
			return err
		}
		challenge, err := dotp.CreateChallenge(privateKey, publicID)
		if err != nil {
			return err
		}
		challenge.Encrypt([]byte(otp), rand.Reader)
		fmt.Printf("Challenge: (%s)", challenge.Serialize())
		qrterminal.Generate(challenge.Serialize(), qrterminal.L, os.Stdout)
		auth(otp, publicID)
		return nil
	},
}

func getPublicID() (string, error) {
	home := os.Getenv("HOME")
	publicIDbytes, err := ioutil.ReadFile(home + "/.dotp_id")
	if err != nil {
		return "", err
	}
	publicID := strings.TrimSpace(string(publicIDbytes))
	return publicID, nil
}

func auth(otp string, publicID string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Challenge for (%s) | Response: ", publicID[0:6])
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
