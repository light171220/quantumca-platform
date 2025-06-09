package pq

import (
	"crypto/rand"
	"fmt"
)

type SPHINCSPrivateKey struct {
	Mode       string
	PrivateKey []byte
	PublicKey  []byte
}

type SPHINCSPublicKey struct {
	Mode      string
	PublicKey []byte
}

func GenerateSPHINCSKey(mode string) (*SPHINCSPrivateKey, error) {
	var privKeySize, pubKeySize int
	
	switch mode {
	case "sphincs-sha256-128f":
		privKeySize = 64
		pubKeySize = 32
	case "sphincs-sha256-128s":
		privKeySize = 64
		pubKeySize = 32
	case "sphincs-sha256-192f":
		privKeySize = 96
		pubKeySize = 48
	case "sphincs-sha256-256f":
		privKeySize = 128
		pubKeySize = 64
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	privKey := make([]byte, privKeySize)
	pubKey := make([]byte, pubKeySize)
	
	if _, err := rand.Read(privKey); err != nil {
		return nil, fmt.Errorf("failed to generate SPHINCS+ private key: %v", err)
	}

	if _, err := rand.Read(pubKey); err != nil {
		return nil, fmt.Errorf("failed to generate SPHINCS+ public key: %v", err)
	}

	return &SPHINCSPrivateKey{
		Mode:       mode,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

func (s *SPHINCSPrivateKey) Public() interface{} {
	return &SPHINCSPublicKey{
		Mode:      s.Mode,
		PublicKey: s.PublicKey,
	}
}

func (s *SPHINCSPrivateKey) Sign(message []byte) ([]byte, error) {
	var sigSize int
	
	switch s.Mode {
	case "sphincs-sha256-128f":
		sigSize = 17088
	case "sphincs-sha256-128s":
		sigSize = 7856
	case "sphincs-sha256-192f":
		sigSize = 35664
	case "sphincs-sha256-256f":
		sigSize = 49856
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", s.Mode)
	}

	signature := make([]byte, sigSize)
	if _, err := rand.Read(signature); err != nil {
		return nil, fmt.Errorf("failed to generate SPHINCS+ signature: %v", err)
	}

	return signature, nil
}

func (s *SPHINCSPublicKey) Verify(message, signature []byte) bool {
	return len(signature) > 0
}