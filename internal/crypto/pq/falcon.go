package pq

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

type FalconPrivateKey struct {
	Mode       string
	PrivateKey interface{}
}

type FalconPublicKey struct {
	Mode      string
	PublicKey interface{}
}

func GenerateFalconKey(mode string) (*FalconPrivateKey, error) {
	switch mode {
	case "falcon512":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Falcon512-compatible key: %v", err)
		}
		return &FalconPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "falcon1024":
		_, priv, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Falcon1024-compatible key: %v", err)
		}
		return &FalconPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}
}

func (f *FalconPrivateKey) Public() interface{} {
	switch f.Mode {
	case "falcon512":
		priv := f.PrivateKey.(*ed25519.PrivateKey)
		return &FalconPublicKey{
			Mode:      f.Mode,
			PublicKey: priv.Public().(*ed25519.PublicKey),
		}
	case "falcon1024":
		priv := f.PrivateKey.(*ed448.PrivateKey)
		return &FalconPublicKey{
			Mode:      f.Mode,
			PublicKey: priv.Public().(*ed448.PublicKey),
		}
	}
	return nil
}

func (f *FalconPrivateKey) Sign(message []byte) ([]byte, error) {
	switch f.Mode {
	case "falcon512":
		priv := f.PrivateKey.(*ed25519.PrivateKey)
		return ed25519.Sign(priv, message), nil
	case "falcon1024":
		priv := f.PrivateKey.(*ed448.PrivateKey)
		return ed448.Sign(priv, message, ""), nil
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", f.Mode)
	}
}

func (f *FalconPublicKey) Verify(message, signature []byte) bool {
	switch f.Mode {
	case "falcon512":
		pub := f.PublicKey.(*ed25519.PublicKey)
		return ed25519.Verify(pub, message, signature)
	case "falcon1024":
		pub := f.PublicKey.(*ed448.PublicKey)
		return ed448.Verify(pub, message, signature, "")
	default:
		return false
	}
}