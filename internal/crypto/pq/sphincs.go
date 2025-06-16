package pq

import (
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

type SPHINCSPrivateKey struct {
	Mode       string
	PrivateKey sign.PrivateKey
	publicKey  *SPHINCSPublicKey
}

type SPHINCSPublicKey struct {
	Mode      string
	PublicKey sign.PublicKey
}

func GenerateSPHINCSKey(mode string) (*SPHINCSPrivateKey, error) {
	var scheme sign.Scheme
	
	switch mode {
	case "sphincs-sha256-128f":
		scheme = schemes.ByName("SPHINCS+-SHA256-128f-simple")
	case "sphincs-sha256-128s":
		scheme = schemes.ByName("SPHINCS+-SHA256-128s-simple")
	case "sphincs-sha256-192f":
		scheme = schemes.ByName("SPHINCS+-SHA256-192f-simple")
	case "sphincs-sha256-256f":
		scheme = schemes.ByName("SPHINCS+-SHA256-256f-simple")
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get SPHINCS+ scheme for mode: %s", mode)
	}

	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", mode, err)
	}

	return &SPHINCSPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
		publicKey: &SPHINCSPublicKey{
			Mode:      mode,
			PublicKey: pub,
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

	if s.PrivateKey != nil {
		pubKey := s.PrivateKey.Public()
		if signPubKey, ok := pubKey.(sign.PublicKey); ok {
			s.publicKey = &SPHINCSPublicKey{
				Mode:      s.Mode,
				PublicKey: signPubKey,
			}
		}
	}
	
	return s.publicKey
}

func (s *SPHINCSPrivateKey) Sign(message []byte) ([]byte, error) {
	if s == nil || s.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	var scheme sign.Scheme
	switch s.Mode {
	case "sphincs-sha256-128f":
		scheme = schemes.ByName("SPHINCS+-SHA256-128f-simple")
	case "sphincs-sha256-128s":
		scheme = schemes.ByName("SPHINCS+-SHA256-128s-simple")
	case "sphincs-sha256-192f":
		scheme = schemes.ByName("SPHINCS+-SHA256-192f-simple")
	case "sphincs-sha256-256f":
		scheme = schemes.ByName("SPHINCS+-SHA256-256f-simple")
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", s.Mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get SPHINCS+ scheme for mode: %s", s.Mode)
	}

	signature := scheme.Sign(s.PrivateKey, message, &sign.SignatureOpts{})
	return signature, nil
}

func (s *SPHINCSPublicKey) Verify(message, signature []byte) bool {
	if s == nil || s.PublicKey == nil {
		return false
	}
	
	if len(message) == 0 || len(signature) == 0 {
		return false
	}

	var scheme sign.Scheme
	switch s.Mode {
	case "sphincs-sha256-128f":
		scheme = schemes.ByName("SPHINCS+-SHA256-128f-simple")
	case "sphincs-sha256-128s":
		scheme = schemes.ByName("SPHINCS+-SHA256-128s-simple")
	case "sphincs-sha256-192f":
		scheme = schemes.ByName("SPHINCS+-SHA256-192f-simple")
	case "sphincs-sha256-256f":
		scheme = schemes.ByName("SPHINCS+-SHA256-256f-simple")
	default:
		return false
	}

	if scheme == nil {
		return false
	}

	return scheme.Verify(s.PublicKey, message, signature, &sign.SignatureOpts{})
}

func (s *SPHINCSPrivateKey) Bytes() ([]byte, error) {
	if s == nil || s.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	keyBytes, err := s.PrivateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return keyBytes, nil
}

func (s *SPHINCSPublicKey) Bytes() ([]byte, error) {
	if s == nil || s.PublicKey == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	
	keyBytes, err := s.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return keyBytes, nil
}

func parseSPHINCSPrivateKey(mode string, keyData []byte) (*SPHINCSPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme sign.Scheme
	switch mode {
	case "sphincs-sha256-128f":
		scheme = schemes.ByName("SPHINCS+-SHA256-128f-simple")
	case "sphincs-sha256-128s":
		scheme = schemes.ByName("SPHINCS+-SHA256-128s-simple")
	case "sphincs-sha256-192f":
		scheme = schemes.ByName("SPHINCS+-SHA256-192f-simple")
	case "sphincs-sha256-256f":
		scheme = schemes.ByName("SPHINCS+-SHA256-256f-simple")
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get SPHINCS+ scheme for mode: %s", mode)
	}

	priv, err := scheme.UnmarshalBinaryPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s private key: %w", mode, err)
	}

	return &SPHINCSPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
	}, nil
}

func parseSPHINCSPublicKey(mode string, keyData []byte) (*SPHINCSPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme sign.Scheme
	switch mode {
	case "sphincs-sha256-128f":
		scheme = schemes.ByName("SPHINCS+-SHA256-128f-simple")
	case "sphincs-sha256-128s":
		scheme = schemes.ByName("SPHINCS+-SHA256-128s-simple")
	case "sphincs-sha256-192f":
		scheme = schemes.ByName("SPHINCS+-SHA256-192f-simple")
	case "sphincs-sha256-256f":
		scheme = schemes.ByName("SPHINCS+-SHA256-256f-simple")
	default:
		return nil, fmt.Errorf("unsupported SPHINCS+ mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get SPHINCS+ scheme for mode: %s", mode)
	}

	pub, err := scheme.UnmarshalBinaryPublicKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s public key: %w", mode, err)
	}

	return &SPHINCSPublicKey{
		Mode:      mode,
		PublicKey: pub,
	}, nil
}