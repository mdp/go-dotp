package main

import (
	"crypto/sha512"
	"errors"
	"io"

	b58 "github.com/jbenet/go-base58"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func expiresToBytes(i int64) [5]byte {
	arr := new([5]byte)
	arr[0] = byte(i >> 32)
	arr[1] = byte((i >> 24) & 255)
	arr[2] = byte((i >> 16) & 255)
	arr[3] = byte((i >> 8) & 255)
	arr[4] = byte(i & 255)
	return *arr
}

func bytesToExpires(t [5]byte) (i int64) {
	i = (int64(t[0]) << 32) |
		(int64(t[1]) << 24) |
		(int64(t[2]) << 16) |
		(int64(t[3]) << 8) |
		int64(t[4])
	return i
}

// Challenge - our Challenge containing the OTP
type Challenge struct {
	nonce              [24]byte
	recipientPublicKey [32]byte
	serverPrivateKey   [32]byte
	serverPublicKey    [32]byte
	otp                []byte
	expiresAt          int64
	box                []byte
}

// DeriveKeyPair takes a utf8 string, returns base64 32byte string
func DeriveKeyPair(input string) (pubKey, privateKey [32]byte) {
	privateKey = *new([32]byte)
	pubKey = *new([32]byte)
	hash := sha512.New()
	privateKeySlice := hash.Sum([]byte(input))
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
	publicKeyDecoded := b58.Decode(publicID)
	publicKey := new([32]byte)
	copy(publicKey[:], publicKeyDecoded[0:32])
	publicKeyHash := sha512.Sum512(publicKey[:])
	if publicKeyHash[0] != publicKeyDecoded[32] {
		return nil, errors.New("Bad public ID")
	}
	return publicKey, nil
}

// Encrypt the OTP into the challenge
func (c *Challenge) Encrypt(otp []byte, expiresAt int64, rand io.Reader) error {
	c.otp = otp
	c.expiresAt = expiresAt
	c.nonce = *new([24]byte)
	_, err := io.ReadFull(rand, c.nonce[:])
	if err != nil {
		return errors.New("Unable to create nonce from rand")
	}
	c.box = make([]byte, 0, box.Overhead+len(otp))
	c.box = box.Seal(c.box, c.otp, &c.nonce, &c.recipientPublicKey, &c.serverPrivateKey)
	return nil
}

// Serialize the challenge into a base58 string
func (c *Challenge) Serialize() string {
	challenge := make([]byte, 0, 1+5+1+24+32+len(c.box))
	challenge = append(challenge, byte(0)) //Version
	fiveByteTimestamp := expiresToBytes(c.expiresAt)
	challenge = append(challenge, fiveByteTimestamp[:]...) //Timestamp
	challenge = append(challenge, c.recipientPublicKey[0]) //First byte of recipient key
	challenge = append(challenge, c.nonce[:]...)           //Nonce
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
