package pq

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

type DilithiumPrivateKey struct {
	Mode       string
	PrivateKey interface{}
}

type DilithiumPublicKey struct {
	Mode      string
	PublicKey interface{}
}

func GenerateDilithiumKey(mode string) (*DilithiumPrivateKey, error) {
	switch mode {
	case "dilithium2":
		_, priv, err := mode2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium2 key: %v", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "dilithium3":
		_, priv, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium3 key: %v", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "dilithium5":
		_, priv, err := mode5.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium5 key: %v", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", mode)
	}
}

func (d *DilithiumPrivateKey) Public() interface{} {
	switch d.Mode {
	case "dilithium2":
		priv := d.PrivateKey.(*mode2.PrivateKey)
		return &DilithiumPublicKey{
			Mode:      d.Mode,
			PublicKey: priv.Public().(*mode2.PublicKey),
		}
	case "dilithium3":
		priv := d.PrivateKey.(*mode3.PrivateKey)
		return &DilithiumPublicKey{
			Mode:      d.Mode,
			PublicKey: priv.Public().(*mode3.PublicKey),
		}
	case "dilithium5":
		priv := d.PrivateKey.(*mode5.PrivateKey)
		return &DilithiumPublicKey{
			Mode:      d.Mode,
			PublicKey: priv.Public().(*mode5.PublicKey),
		}
	}
	return nil
}

func (d *DilithiumPrivateKey) Sign(message []byte) ([]byte, error) {
	switch d.Mode {
	case "dilithium2":
		priv := d.PrivateKey.(*mode2.PrivateKey)
		sig := make([]byte, mode2.SignatureSize)
		mode2.SignTo(priv, message, sig)
		return sig, nil
	case "dilithium3":
		priv := d.PrivateKey.(*mode3.PrivateKey)
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(priv, message, sig)
		return sig, nil
	case "dilithium5":
		priv := d.PrivateKey.(*mode5.PrivateKey)
		sig := make([]byte, mode5.SignatureSize)
		mode5.SignTo(priv, message, sig)
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", d.Mode)
	}
}

func (d *DilithiumPublicKey) Verify(message, signature []byte) bool {
	switch d.Mode {
	case "dilithium2":
		pub := d.PublicKey.(*mode2.PublicKey)
		return mode2.Verify(pub, message, signature)
	case "dilithium3":
		pub := d.PublicKey.(*mode3.PublicKey)
		return mode3.Verify(pub, message, signature)
	case "dilithium5":
		pub := d.PublicKey.(*mode5.PublicKey)
		return mode5.Verify(pub, message, signature)
	default:
		return false
	}
}