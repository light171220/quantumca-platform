package pq

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

type KyberPrivateKey struct {
	Mode       string
	PrivateKey interface{}
}

type KyberPublicKey struct {
	Mode      string
	PublicKey interface{}
}

func GenerateKyberKey(mode string) (*KyberPrivateKey, error) {
	switch mode {
	case "kyber512":
		pub, priv, err := kyber512.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber512 key: %v", err)
		}
		return &KyberPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "kyber768":
		pub, priv, err := kyber768.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber768 key: %v", err)
		}
		return &KyberPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "kyber1024":
		pub, priv, err := kyber1024.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber1024 key: %v", err)
		}
		return &KyberPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", mode)
	}
}

func (k *KyberPrivateKey) Public() interface{} {
	switch k.Mode {
	case "kyber512":
		priv := k.PrivateKey.(*kyber512.PrivateKey)
		return &KyberPublicKey{
			Mode:      k.Mode,
			PublicKey: priv.Public().(*kyber512.PublicKey),
		}
	case "kyber768":
		priv := k.PrivateKey.(*kyber768.PrivateKey)
		return &KyberPublicKey{
			Mode:      k.Mode,
			PublicKey: priv.Public().(*kyber768.PublicKey),
		}
	case "kyber1024":
		priv := k.PrivateKey.(*kyber1024.PrivateKey)
		return &KyberPublicKey{
			Mode:      k.Mode,
			PublicKey: priv.Public().(*kyber1024.PublicKey),
		}
	}
	return nil
}

func (k *KyberPrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	switch k.Mode {
	case "kyber512":
		priv := k.PrivateKey.(*kyber512.PrivateKey)
		return kyber512.Decapsulate(priv, ciphertext)
	case "kyber768":
		priv := k.PrivateKey.(*kyber768.PrivateKey)
		return kyber768.Decapsulate(priv, ciphertext)
	case "kyber1024":
		priv := k.PrivateKey.(*kyber1024.PrivateKey)
		return kyber1024.Decapsulate(priv, ciphertext)
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", k.Mode)
	}
}

func (k *KyberPublicKey) Encapsulate() ([]byte, []byte, error) {
	switch k.Mode {
	case "kyber512":
		pub := k.PublicKey.(*kyber512.PublicKey)
		return kyber512.Encapsulate(pub, rand.Reader)
	case "kyber768":
		pub := k.PublicKey.(*kyber768.PublicKey)
		return kyber768.Encapsulate(pub, rand.Reader)
	case "kyber1024":
		pub := k.PublicKey.(*kyber1024.PublicKey)
		return kyber1024.Encapsulate(pub, rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unsupported Kyber mode: %s", k.Mode)
	}
}512.PublicKey; Priv *kyber512.PrivateKey })
		return kyber512.Decapsulate(keypair.Priv, ciphertext), nil
	case "kyber768":
		keypair := k.PrivateKey.(*struct{ Pub *kyber768.PublicKey; Priv *kyber768.PrivateKey })
		return kyber768.Decapsulate(keypair.Priv, ciphertext), nil
	case "kyber1024":
		keypair := k.PrivateKey.(*struct{ Pub *kyber1024.PublicKey; Priv *kyber1024.PrivateKey })
		return kyber1024.Decapsulate(keypair.Priv, ciphertext), nil
	default:
		return nil, fmt.Errorf("unsupported Kyber mode: %s", k.Mode)
	}
}

func (k *KyberPublicKey) Encapsulate() ([]byte, []byte, error) {
	switch k.Mode {
	case "kyber512":
		pub := k.PublicKey.(*kyber512.PublicKey)
		ciphertext, sharedSecret := kyber512.Encapsulate(pub, rand.Reader)
		return ciphertext, sharedSecret, nil
	case "kyber768":
		pub := k.PublicKey.(*kyber768.PublicKey)
		ciphertext, sharedSecret := kyber768.Encapsulate(pub, rand.Reader)
		return ciphertext, sharedSecret, nil
	case "kyber1024":
		pub := k.PublicKey.(*kyber1024.PublicKey)
		ciphertext, sharedSecret := kyber1024.Encapsulate(pub, rand.Reader)
		return ciphertext, sharedSecret, nil
	default:
		return nil, nil, fmt.Errorf("unsupported Kyber mode: %s", k.Mode)
	}
}