package pq

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type SPHINCSPrivateKey struct {
	Mode       string
	PrivateKey []byte
	publicKey  *SPHINCSPublicKey
}

type SPHINCSPublicKey struct {
	Mode      string
	PublicKey []byte
}

func GenerateSPHINCSKey(mode string) (*SPHINCSPrivateKey, error) {
	var sigName string
	
	switch mode {
	case "sphincs-sha256-128f":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha256-128s":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha256-192f":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha256-256f":
		sigName = "SPHINCS+-SHA2-256f-simple"
	case "sphincs-sha2-128f-simple":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha2-128s-simple":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha2-192f-simple":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha2-256f-simple":
		sigName = "SPHINCS+-SHA2-256f-simple"
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	if !oqs.IsSigEnabled(sigName) {
		return nil, fmt.Errorf("SPHINCS+ algorithm %s is not enabled in liboqs", sigName)
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize %s: %w", sigName, err)
	}

	publicKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key pair: %w", sigName, err)
	}

	privateKey := sig.ExportSecretKey()

	return &SPHINCSPrivateKey{
		Mode:       mode,
		PrivateKey: privateKey,
		publicKey: &SPHINCSPublicKey{
			Mode:      mode,
			PublicKey: publicKey,
		},
	}, nil
}

func (s *SPHINCSPrivateKey) Public() interface{} {
	if s == nil {
		return nil
	}
	
	if s.publicKey != nil {
		return s.publicKey
	}

	return nil
}

func (s *SPHINCSPrivateKey) Sign(message []byte) ([]byte, error) {
	if s == nil || len(s.PrivateKey) == 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	var sigName string
	switch s.Mode {
	case "sphincs-sha256-128f":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha256-128s":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha256-192f":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha256-256f":
		sigName = "SPHINCS+-SHA2-256f-simple"
	case "sphincs-sha2-128f-simple":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha2-128s-simple":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha2-192f-simple":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha2-256f-simple":
		sigName = "SPHINCS+-SHA2-256f-simple"
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", s.Mode)
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize %s for signing: %w", sigName, err)
	}

	signature, err := sig.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with %s: %w", sigName, err)
	}

	return signature, nil
}

func (s *SPHINCSPublicKey) Verify(message, signature []byte) bool {
	if s == nil || len(s.PublicKey) == 0 {
		return false
	}
	
	if len(message) == 0 || len(signature) == 0 {
		return false
	}

	var sigName string
	switch s.Mode {
	case "sphincs-sha256-128f":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha256-128s":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha256-192f":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha256-256f":
		sigName = "SPHINCS+-SHA2-256f-simple"
	case "sphincs-sha2-128f-simple":
		sigName = "SPHINCS+-SHA2-128f-simple"
	case "sphincs-sha2-128s-simple":
		sigName = "SPHINCS+-SHA2-128s-simple"
	case "sphincs-sha2-192f-simple":
		sigName = "SPHINCS+-SHA2-192f-simple"
	case "sphincs-sha2-256f-simple":
		sigName = "SPHINCS+-SHA2-256f-simple"
	default:
		return false
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, nil)
	if err != nil {
		return false
	}

	isValid, err := sig.Verify(message, signature, s.PublicKey)
	if err != nil {
		return false
	}

	return isValid
}

func (s *SPHINCSPrivateKey) Bytes() ([]byte, error) {
	if s == nil || len(s.PrivateKey) == 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	
	result := make([]byte, len(s.PrivateKey))
	copy(result, s.PrivateKey)
	return result, nil
}

func (s *SPHINCSPublicKey) Bytes() ([]byte, error) {
	if s == nil || len(s.PublicKey) == 0 {
		return nil, fmt.Errorf("invalid public key")
	}
	
	result := make([]byte, len(s.PublicKey))
	copy(result, s.PublicKey)
	return result, nil
}

func parseSPHINCSPrivateKey(mode string, keyData []byte) (*SPHINCSPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
	case "sphincs-sha2-128f-simple", "sphincs-sha2-128s-simple", "sphincs-sha2-192f-simple", "sphincs-sha2-256f-simple":
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	privateKey := make([]byte, len(keyData))
	copy(privateKey, keyData)

	return &SPHINCSPrivateKey{
		Mode:       mode,
		PrivateKey: privateKey,
	}, nil
}

func parseSPHINCSPublicKey(mode string, keyData []byte) (*SPHINCSPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
	case "sphincs-sha2-128f-simple", "sphincs-sha2-128s-simple", "sphincs-sha2-192f-simple", "sphincs-sha2-256f-simple":
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	publicKey := make([]byte, len(keyData))
	copy(publicKey, keyData)

	return &SPHINCSPublicKey{
		Mode:      mode,
		PublicKey: publicKey,
	}, nil
}

func IsSPHINCSAvailable() (bool, []string) {
	available := []string{}
	
	sphincsAlgs := []string{
		"SPHINCS+-SHA2-128f-simple",
		"SPHINCS+-SHA2-128s-simple", 
		"SPHINCS+-SHA2-192f-simple",
		"SPHINCS+-SHA2-256f-simple",
	}
	
	for _, alg := range sphincsAlgs {
		if oqs.IsSigEnabled(alg) {
			available = append(available, alg)
		}
	}
	
	return len(available) > 0, available
}