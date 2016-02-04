package dotp

import (
	"bytes"
	"testing"

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
	_, serverPrivateKey := DeriveKeyPair("ServerSecret")
	recipientPubID := GetPublicID(&recipientPublic)
	challenge, err := CreateChallenge(&serverPrivateKey, recipientPubID)
	if err != nil {
		t.Error("Error creating Challenge: ", err)
	}
	challenge.Encrypt([]byte("MYOTP"))
	assert.Equal(t, challenge.Serialize(), "12iuH5TcctjU4mjwoq9CVwLLJPToDZkkKCeCiNshmBFwZfJtvuMSFGpv2cV9zoUnXjnT49bASiw")
}
