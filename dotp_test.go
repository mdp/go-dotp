package dotp

import (
	"bytes"
	"testing"

	"github.com/mdp/sodiumbox"
	"github.com/stretchr/testify/assert"
)

func TestDeriveKeyPair(t *testing.T) {
	pubKey, _ := DeriveKeyPair("TEST")
	expectedPubKey := []byte{178, 52, 221, 72, 147, 67, 27, 234, 88, 14, 14, 203, 48, 76, 47, 15, 133, 234, 195, 29, 127, 154, 198, 193, 116, 245, 201, 225, 223, 167, 217, 119}
	if !bytes.Equal(pubKey[:], expectedPubKey) {
		t.Error("Derive key wrong", pubKey, expectedPubKey)
	}
}

func TestCreateChallenge(t *testing.T) {
	recipientPublic, _ := DeriveKeyPair("ClientSecret")
	recipientPubID := GetPublicID(recipientPublic)
	challenge, err := CreateChallenge("MYOTP", recipientPubID)
	if err != nil {
		t.Error("Error creating Challenge: ", err)
	}
	assert.Equal(t, challenge.Crypted.PublicKey, recipientPublic)
	assert.True(t, challenge.Solve("MYOTP"))
}

func TestSerializeChallenge(t *testing.T) {
	recipientPublic, _ := DeriveKeyPair("ClientSecret")
	challenge := Challenge{
		Crypted: sodiumbox.Message{
			PublicKey: recipientPublic,
			Box:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		},
	}
	assert.Equal(t, challenge.Serialize(), "16D6DymgNNL5TAyV")
}
