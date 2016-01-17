package dotp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

type FakeRandReader struct {
}

func (f FakeRandReader) Read(p []byte) (int, error) {
	var j = 0
	for index := range p {
		p[index] = byte(j)
		j++
	}
	return j, nil
}

func TestDeriveKeyPair(t *testing.T) {
	pubKey, _ := DeriveKeyPair("TEST")
	expectedPubKey := []byte{178, 52, 221, 72, 147, 67, 27, 234, 88, 14, 14, 203, 48, 76, 47, 15, 133, 234, 195, 29, 127, 154, 198, 193, 116, 245, 201, 225, 223, 167, 217, 119}
	if !bytes.Equal(pubKey[:], expectedPubKey) {
		t.Error("Derive key wrong", pubKey, expectedPubKey)
	}
}

func TestCreateChallenge(t *testing.T) {
	recipientPublic, _ := DeriveKeyPair("ClientSecret")
	_, serverPrivateKey := DeriveKeyPair("ServerSecret")
	recipientPubID := GetPublicID(&recipientPublic)
	challenge, err := CreateChallenge(&serverPrivateKey, recipientPubID)
	if err != nil {
		t.Error("Error creating Challenge: ", err)
	}
	challenge.Encrypt([]byte("MYOTP"), 1452759001, FakeRandReader{})
	assert.Equal(t, challenge.Serialize(), "11KPBbA6tVpE9mLxEiGyQfKKtnnMdZPQrHevRRXKqtZ6AKZ9tFfi9CruaRSiCuqMB8g4zNc5mkkMxHRzYEwZUZfKUErUu2kca8e4pLABaZBUGVw922")
}
