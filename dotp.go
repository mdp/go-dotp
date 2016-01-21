package dotp

import (
	"crypto/sha512"
	"errors"
	"io"
	"strings"

	b58 "github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Challenge - our Challenge containing the OTP
type Challenge struct {
	recipientPublicKey [32]byte
	serverPrivateKey   [32]byte
	serverPublicKey    [32]byte
	otp                []byte
	box                []byte
}

// RandomKeyPair creates a crypto secure random keypair
func RandomKeyPair(r io.Reader) (pubKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(r)
}

// DeriveKeyPair takes a utf8 string, returns base64 32byte string
func DeriveKeyPair(input string) (pubKey, privateKey [32]byte) {
	privateKey = *new([32]byte)
	pubKey = *new([32]byte)
	privateKeySlice := sha512.Sum512([]byte(input))
	copy(privateKey[:], privateKeySlice[0:32])
	curve25519.ScalarBaseMult(&pubKey, &privateKey)
	return
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
	publicKey := new([32]byte)
	copy(publicKey[:], publicKeyDecoded[0:32])
	publicKeyHash := sha512.Sum512(publicKey[:])
	if publicKeyHash[0] != publicKeyDecoded[32] {
		return nil, errors.New("Bad public ID")
	}
	return publicKey, nil
}

// Encrypt the OTP into the challenge
func (c *Challenge) Encrypt(otp []byte, rand io.Reader) error {
	c.otp = otp
	nonce := new([24]byte) //0 nonce
	c.box = box.Seal(nil, c.otp, nonce, &c.recipientPublicKey, &c.serverPrivateKey)
	return nil
}

// Serialize the challenge into a base58 string
func (c *Challenge) Serialize() string {
	challenge := make([]byte, 0, 1+1+32+len(c.box))
	challenge = append(challenge, byte(0))                 //Version
	challenge = append(challenge, c.recipientPublicKey[0]) //First byte of recipient key
	challenge = append(challenge, c.serverPublicKey[:]...) //Public Key for the server
	challenge = append(challenge, c.box...)                //Ciphertext
	return b58.Encode(challenge)
}

// CreateChallenge is what it is
func CreateChallenge(serverPrivateKey *[32]byte, recipientPubID string) (*Challenge, error) {
	serverPublicKey := new([32]byte)
	curve25519.ScalarBaseMult(serverPublicKey, serverPrivateKey)
	publicKey, err := GetPublicKeyFromPublicID(recipientPubID)
	if err != nil {
		return nil, err
	}
	return &Challenge{
		serverPublicKey:    *serverPublicKey,
		serverPrivateKey:   *serverPrivateKey,
		recipientPublicKey: *publicKey,
	}, nil
}
