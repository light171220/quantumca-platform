package pq

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
)

type MultiPQCPrivateKey struct {
	PrimaryAlgorithm   string
	SecondaryAlgorithm string
	TertiaryAlgorithm  string
	PrimaryKey         interface{}
	SecondaryKey       interface{}
	TertiaryKey        interface{}
	CombinedKeyID      []byte
}

type MultiPQCPublicKey struct {
	PrimaryAlgorithm   string
	SecondaryAlgorithm string
	TertiaryAlgorithm  string
	PrimaryKey         interface{}
	SecondaryKey       interface{}
	TertiaryKey        interface{}
	CombinedKeyID      []byte
}

type MultiPQCSignature struct {
	PrimarySignature   []byte   `asn1:"tag:0"`
	SecondarySignature []byte   `asn1:"tag:1"`
	TertiarySignature  []byte   `asn1:"tag:2"`
	Algorithms         []string `asn1:"tag:3"`
	CombinedHash       []byte   `asn1:"tag:4"`
}

type MultiPQCKeyInfo struct {
	Algorithms []string `json:"algorithms"`
	KeyData    [][]byte `json:"key_data"`
	CombinedID []byte   `json:"combined_id"`
}

func (m *MultiPQCPrivateKey) Public() crypto.PublicKey {
	multiPQCPublic, err := m.GetPublicKey()
	if err != nil {
		return nil
	}
	return multiPQCPublic
}

func (m *MultiPQCPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	multiSig, err := m.SignMessage(digest)
	if err != nil {
		return nil, fmt.Errorf("multi-PQC signature failed: %w", err)
	}
	
	return asn1.Marshal(*multiSig)
}

func GenerateMultiPQCKeyPair() (*MultiPQCPrivateKey, error) {
	primaryAlg := "dilithium3"
	secondaryAlg := "sphincs-sha256-128s"
	tertiaryAlg := "dilithium5"

	fmt.Printf("Generating multi-PQC key with algorithms: %s, %s, %s\n", primaryAlg, secondaryAlg, tertiaryAlg)

	primaryPriv, err := GenerateKey(primaryAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate primary key (%s): %w", primaryAlg, err)
	}

	secondaryPriv, err := GenerateKey(secondaryAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secondary key (%s): %w", secondaryAlg, err)
	}

	tertiaryPriv, err := GenerateKey(tertiaryAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tertiary key (%s): %w", tertiaryAlg, err)
	}

	primaryPub, err := GetPublicKey(primaryPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary public key: %w", err)
	}

	secondaryPub, err := GetPublicKey(secondaryPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to get secondary public key: %w", err)
	}

	tertiaryPub, err := GetPublicKey(tertiaryPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to get tertiary public key: %w", err)
	}

	combinedID, err := generateCombinedKeyID(primaryPub, secondaryPub, tertiaryPub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate combined key ID: %w", err)
	}

	return &MultiPQCPrivateKey{
		PrimaryAlgorithm:   primaryAlg,
		SecondaryAlgorithm: secondaryAlg,
		TertiaryAlgorithm:  tertiaryAlg,
		PrimaryKey:         primaryPriv,
		SecondaryKey:       secondaryPriv,
		TertiaryKey:        tertiaryPriv,
		CombinedKeyID:      combinedID,
	}, nil
}

func (m *MultiPQCPrivateKey) GetPublicKey() (*MultiPQCPublicKey, error) {
	primaryPub, err := GetPublicKey(m.PrimaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary public key: %w", err)
	}

	secondaryPub, err := GetPublicKey(m.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get secondary public key: %w", err)
	}

	tertiaryPub, err := GetPublicKey(m.TertiaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get tertiary public key: %w", err)
	}

	return &MultiPQCPublicKey{
		PrimaryAlgorithm:   m.PrimaryAlgorithm,
		SecondaryAlgorithm: m.SecondaryAlgorithm,
		TertiaryAlgorithm:  m.TertiaryAlgorithm,
		PrimaryKey:         primaryPub,
		SecondaryKey:       secondaryPub,
		TertiaryKey:        tertiaryPub,
		CombinedKeyID:      m.CombinedKeyID,
	}, nil
}

func (m *MultiPQCPrivateKey) SignMessage(message []byte) (*MultiPQCSignature, error) {
	primarySig, err := Sign(m.PrimaryKey, message)
	if err != nil {
		return nil, fmt.Errorf("primary signature failed: %w", err)
	}

	secondarySig, err := Sign(m.SecondaryKey, message)
	if err != nil {
		return nil, fmt.Errorf("secondary signature failed: %w", err)
	}

	tertiarySig, err := Sign(m.TertiaryKey, message)
	if err != nil {
		return nil, fmt.Errorf("tertiary signature failed: %w", err)
	}

	combinedHash := sha256.Sum256(append(append(primarySig, secondarySig...), tertiarySig...))

	return &MultiPQCSignature{
		PrimarySignature:   primarySig,
		SecondarySignature: secondarySig,
		TertiarySignature:  tertiarySig,
		Algorithms:         []string{m.PrimaryAlgorithm, m.SecondaryAlgorithm, m.TertiaryAlgorithm},
		CombinedHash:       combinedHash[:],
	}, nil
}

func (m *MultiPQCPublicKey) Verify(message []byte, signature *MultiPQCSignature) bool {
	if len(signature.Algorithms) != 3 {
		return false
	}

	if signature.Algorithms[0] != m.PrimaryAlgorithm ||
		signature.Algorithms[1] != m.SecondaryAlgorithm ||
		signature.Algorithms[2] != m.TertiaryAlgorithm {
		return false
	}

	primaryValid := Verify(m.PrimaryKey, message, signature.PrimarySignature)
	if !primaryValid {
		return false
	}

	secondaryValid := Verify(m.SecondaryKey, message, signature.SecondarySignature)
	if !secondaryValid {
		return false
	}

	tertiaryValid := Verify(m.TertiaryKey, message, signature.TertiarySignature)
	if !tertiaryValid {
		return false
	}

	expectedHash := sha256.Sum256(append(append(signature.PrimarySignature, signature.SecondarySignature...), signature.TertiarySignature...))
	
	if len(signature.CombinedHash) != len(expectedHash) {
		return false
	}

	for i := range expectedHash {
		if signature.CombinedHash[i] != expectedHash[i] {
			return false
		}
	}

	return true
}

func generateCombinedKeyID(primary, secondary, tertiary interface{}) ([]byte, error) {
	primaryBytes, err := MarshalPublicKey(primary)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal primary key: %w", err)
	}

	secondaryBytes, err := MarshalPublicKey(secondary)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secondary key: %w", err)
	}

	tertiaryBytes, err := MarshalPublicKey(tertiary)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tertiary key: %w", err)
	}

	combined := append(append(primaryBytes, secondaryBytes...), tertiaryBytes...)
	hash := sha256.Sum256(combined)
	return hash[:20], nil
}

func MarshalMultiPQCPrivateKey(key *MultiPQCPrivateKey) ([]byte, error) {
	primaryBytes, err := MarshalPrivateKey(key.PrimaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal primary private key: %w", err)
	}

	secondaryBytes, err := MarshalPrivateKey(key.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secondary private key: %w", err)
	}

	tertiaryBytes, err := MarshalPrivateKey(key.TertiaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tertiary private key: %w", err)
	}

	keyInfo := MultiPQCKeyInfo{
		Algorithms: []string{key.PrimaryAlgorithm, key.SecondaryAlgorithm, key.TertiaryAlgorithm},
		KeyData:    [][]byte{primaryBytes, secondaryBytes, tertiaryBytes},
		CombinedID: key.CombinedKeyID,
	}

	return asn1.Marshal(keyInfo)
}

func MarshalMultiPQCPublicKey(key *MultiPQCPublicKey) ([]byte, error) {
	primaryBytes, err := MarshalPublicKey(key.PrimaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal primary public key: %w", err)
	}

	secondaryBytes, err := MarshalPublicKey(key.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secondary public key: %w", err)
	}

	tertiaryBytes, err := MarshalPublicKey(key.TertiaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tertiary public key: %w", err)
	}

	keyInfo := MultiPQCKeyInfo{
		Algorithms: []string{key.PrimaryAlgorithm, key.SecondaryAlgorithm, key.TertiaryAlgorithm},
		KeyData:    [][]byte{primaryBytes, secondaryBytes, tertiaryBytes},
		CombinedID: key.CombinedKeyID,
	}

	return asn1.Marshal(keyInfo)
}

func ParseMultiPQCPrivateKey(data []byte) (*MultiPQCPrivateKey, error) {
	var keyInfo MultiPQCKeyInfo
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key info: %w", err)
	}

	if len(keyInfo.Algorithms) != 3 || len(keyInfo.KeyData) != 3 {
		return nil, fmt.Errorf("invalid multi-PQC key structure")
	}

	primaryKey, err := ParsePrivateKey(keyInfo.KeyData[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse primary private key: %w", err)
	}

	secondaryKey, err := ParsePrivateKey(keyInfo.KeyData[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse secondary private key: %w", err)
	}

	tertiaryKey, err := ParsePrivateKey(keyInfo.KeyData[2])
	if err != nil {
		return nil, fmt.Errorf("failed to parse tertiary private key: %w", err)
	}

	return &MultiPQCPrivateKey{
		PrimaryAlgorithm:   keyInfo.Algorithms[0],
		SecondaryAlgorithm: keyInfo.Algorithms[1],
		TertiaryAlgorithm:  keyInfo.Algorithms[2],
		PrimaryKey:         primaryKey,
		SecondaryKey:       secondaryKey,
		TertiaryKey:        tertiaryKey,
		CombinedKeyID:      keyInfo.CombinedID,
	}, nil
}

func ParseMultiPQCPublicKey(data []byte) (*MultiPQCPublicKey, error) {
	var keyInfo MultiPQCKeyInfo
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key info: %w", err)
	}

	if len(keyInfo.Algorithms) != 3 || len(keyInfo.KeyData) != 3 {
		return nil, fmt.Errorf("invalid multi-PQC key structure")
	}

	primaryKey, err := ParsePublicKey(keyInfo.KeyData[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse primary public key: %w", err)
	}

	secondaryKey, err := ParsePublicKey(keyInfo.KeyData[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse secondary public key: %w", err)
	}

	tertiaryKey, err := ParsePublicKey(keyInfo.KeyData[2])
	if err != nil {
		return nil, fmt.Errorf("failed to parse tertiary public key: %w", err)
	}

	return &MultiPQCPublicKey{
		PrimaryAlgorithm:   keyInfo.Algorithms[0],
		SecondaryAlgorithm: keyInfo.Algorithms[1],
		TertiaryAlgorithm:  keyInfo.Algorithms[2],
		PrimaryKey:         primaryKey,
		SecondaryKey:       secondaryKey,
		TertiaryKey:        tertiaryKey,
		CombinedKeyID:      keyInfo.CombinedID,
	}, nil
}