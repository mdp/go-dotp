package dotp

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"strings"

	b58 "github.com/btcsuite/btcutil/base58"
	"github.com/mdp/sodiumbox"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Challenge - our Challenge containing the OTP
type Challenge struct {
	OTP     string
	Name    string
	Crypted sodiumbox.Message
}

// DeriveKeyPair takes a utf8 string, returns the [32]byte pub and secret keys
func DeriveKeyPair(input string) (pubKey, privateKey *[32]byte) {
	privateKey = new([32]byte)
	pubKey = new([32]byte)
	privateKeySlice := sha512.Sum512([]byte(input))
	copy(privateKey[:], privateKeySlice[0:32])
	curve25519.ScalarBaseMult(pubKey, privateKey)
	return
}

// GenerateKeyPair return a new randomly generated keypair
func GenerateKeyPair() (pubKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// GetPublicID create the public id from the pubkey
func GetPublicID(publicKey *[32]byte) string {
	address := make([]byte, 0, 33)
	publicKeyHash := sha512.Sum512(publicKey[:])
	address = append(address, publicKey[:]...)
	address = append(address, publicKeyHash[0])
	return b58.Encode(address)
}

//GetPublicKeyFromPublicID is what it is
func GetPublicKeyFromPublicID(publicID string) (*[32]byte, error) {
	publicID = strings.TrimSpace(publicID)
	publicKeyDecoded := b58.Decode(publicID)
	if len(publicKeyDecoded) != 33 {
		return nil, errors.New("Bad PublicID: Incorrect length")
	}
	publicKey := *new([32]byte)
	copy(publicKey[:], publicKeyDecoded[0:32])
	publicKeyHash := sha512.Sum512(publicKey[:])
	if publicKeyHash[0] != publicKeyDecoded[32] {
		return nil, errors.New("Bad public ID")
	}
	return &publicKey, nil
}

// Serialize the challenge into a base32 uppercase string
func (c *Challenge) Serialize() string {
	challenge := make([]byte, 0, 1+1+len(c.Crypted.Box))
	challenge = append(challenge, byte(0))                //Version
	challenge = append(challenge, c.Crypted.PublicKey[0]) //First byte of recipient key
	challenge = append(challenge, c.Crypted.Box...)       //Ciphertext
	// Base32 to UpperCase, with "=" replaced by "-"
	// This allows us to use the smaller AlphaNumeric encoding on the QR Code
	// vs the more wasteful 8bit string set. Would be better to just use binary
	// encoding, but it's limited by reader support
	return strings.Replace(strings.ToUpper(base32.StdEncoding.EncodeToString(challenge)), "=", "-", -1)
}

// Solve allows you to check if a answer matches the OTP
func (c *Challenge) Solve(answer string) bool {
	return c.OTP == answer
}

// CreateChallenge is what it is
func CreateChallenge(otp, name, recipientPubID string) (*Challenge, error) {
	publicKey, err := GetPublicKeyFromPublicID(recipientPubID)
	if err != nil {
		return nil, err
	}
	msg, err := sodiumbox.Seal([]byte(name+"|"+otp), publicKey)
	if err != nil {
		return nil, err
	}
	return &Challenge{
		OTP:     otp,
		Name:    name,
		Crypted: *msg,
	}, nil
}
