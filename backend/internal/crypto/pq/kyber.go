package pq

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

type KyberPrivateKey struct {
	Mode       string
	PrivateKey kem.PrivateKey
	publicKey  *KyberPublicKey
}

type KyberPublicKey struct {
	Mode      string
	PublicKey kem.PublicKey
}

func GenerateKyberKey(mode string) (*KyberPrivateKey, error) {
	var scheme kem.Scheme
	
	switch mode {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", mode)
	}

	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", mode, err)
	}

	return &KyberPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
		publicKey: &KyberPublicKey{
			Mode:      mode,
			PublicKey: pub,
		},
	}, nil
}

func (k *KyberPrivateKey) Public() interface{} {
	if k == nil {
		return nil
	}
	
	if k.publicKey != nil {
		return k.publicKey
	}

	if k.PrivateKey != nil {
		k.publicKey = &KyberPublicKey{
			Mode:      k.Mode,
			PublicKey: k.PrivateKey.Public(),
		}
	}
	
	return k.publicKey
}

func (k *KyberPrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k == nil || k.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	scheme := k.PrivateKey.Scheme()
	return scheme.Decapsulate(k.PrivateKey, ciphertext)
}

func (k *KyberPublicKey) Encapsulate() ([]byte, []byte, error) {
	if k == nil || k.PublicKey == nil {
		return nil, nil, fmt.Errorf("invalid public key")
	}
	
	scheme := k.PublicKey.Scheme()
	return scheme.Encapsulate(k.PublicKey)
}

func (k *KyberPrivateKey) Bytes() ([]byte, error) {
	if k == nil || k.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	return k.PrivateKey.MarshalBinary()
}

func (k *KyberPublicKey) Bytes() ([]byte, error) {
	if k == nil || k.PublicKey == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	
	return k.PublicKey.MarshalBinary()
}

func parseKyberPrivateKey(mode string, keyData []byte) (*KyberPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme kem.Scheme
	
	switch mode {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", mode)
	}

	priv, err := scheme.UnmarshalBinaryPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s private key: %w", mode, err)
	}

	return &KyberPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
	}, nil
}

func parseKyberPublicKey(mode string, keyData []byte) (*KyberPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme kem.Scheme
	
	switch mode {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", mode)
	}

	pub, err := scheme.UnmarshalBinaryPublicKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s public key: %w", mode, err)
	}

	return &KyberPublicKey{
		Mode:      mode,
		PublicKey: pub,
	}, nil
}