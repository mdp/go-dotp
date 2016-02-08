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
var alphanumeric bool
var otpLen int

const base32 = "023456789abcdefghjkmnpqrstuvwxyz"
const base10 = "0123456789"

func randString(n int, alphaCharset bool) string {
	charset := []byte(base10)
	if alphaCharset {
		charset = []byte(base32)
	}
	b := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range b {
		r, _ := rand.Int(rand.Reader, charsetLen)
		b[i] = charset[r.Uint64()]
	}
	return strings.ToUpper(string(b))
}

// sshauthCmd respresents the sshauth command
var sshauthCmd = &cobra.Command{
	Use:   "sshauth",
	Short: "TwoFactor auth for SSH",
	Long: `This allows you to quickly implement two factor authentication in ssh.
	Use the ForceCommand in sshd_config to run this program upon login. User will
	then be presented with a QR Code challenge to authenticate. Assumes the user has
	a dotp public ID and that it is available at '$HOME/.dotp_id'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		otp := randString(otpLen, alphanumeric)
		publicID, err := getPublicID()
		if err != nil {
			if forceDOTP {
				fmt.Println("User doesn't have a public ID listed in `$HOME/.dotp_id`")
				fmt.Println("Not allowed to continue login without a dOTP Public ID")
				return nil
			}
			giveShell()
			return nil
		}
		_, privateKey, err := dotp.RandomKeyPair(rand.Reader)
		if err != nil {
			return err
		}
		challenge, err := dotp.CreateChallenge(privateKey, publicID)
		if err != nil {
			return err
		}
		challenge.Encrypt([]byte(otp))
		fmt.Printf("\nChallenge: `%s`\n", challenge.Serialize())
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
	fmt.Print("Response: ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSuffix(text, "\n")
	text = strings.Replace(text, " ", "", -1)
	text = strings.ToUpper(text)
	if otp == text {
		fmt.Print("Successful Auth\n\n")
		giveShell()
	} else {
		fmt.Print("Incorrect response. Have a great day!\n\n")
	}
}

func giveShell() {
	cmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(cmd) == 0 {
		cmd = os.Getenv("SHELL")
	}
	proc := exec.Command(cmd)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	err := proc.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	RootCmd.AddCommand(sshauthCmd)

	sshauthCmd.Flags().BoolVarP(&forceDOTP, "force", "f", false, "Enforce dOTP auth, users without dotp public keys will not be able to login")
	sshauthCmd.Flags().BoolVarP(&alphanumeric, "alphanumeric", "a", false, "Use an alphanumeric passcode instead of numeric")
	sshauthCmd.Flags().IntVarP(&otpLen, "length", "l", 8, "OTP passcode length")

}
