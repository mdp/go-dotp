package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestDeriveKeyPair(t *testing.T) {
	pubKey, _ := DeriveKeyPair("TEST")
	expectedPubKey := []byte{163, 213, 233, 10, 254, 153, 177, 128, 48, 182, 29, 179, 43, 148, 184, 108, 130, 185, 40, 78, 108, 22, 174, 229, 50, 248, 64, 227, 4, 7, 120, 124}
	if !bytes.Equal(pubKey[:], expectedPubKey) {
		t.Error("Derive key wrong", pubKey, expectedPubKey)
	}
}

func TestCreateChallenge(t *testing.T) {
	recipientPublic, _ := DeriveKeyPair("ClientKey")
	_, serverPrivateKey := DeriveKeyPair("ServerKey")
	recipientPubID := GetPublicID(&recipientPublic)
	challenge, err := CreateChallenge(&serverPrivateKey, recipientPubID)
	if err != nil {
		t.Error("Error creating Challenge: ", err)
	}
	challenge.Encrypt([]byte("MYOTP"), time.Now().Unix(), rand.Reader)
	fmt.Printf("%+v\n", challenge)
	str := challenge.Serialize()
	fmt.Printf("Serialized: %v\n", str)
}
