package pq

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

type DilithiumPrivateKey struct {
	Mode       string
	PrivateKey interface{}
	publicKey  *DilithiumPublicKey
}

type DilithiumPublicKey struct {
	Mode      string
	PublicKey interface{}
}

func (d *DilithiumPrivateKey) Public() crypto.PublicKey {
	if d == nil {
		return nil
	}
	
	if d.publicKey != nil {
		return d.publicKey
	}

	switch d.Mode {
	case "dilithium2":
		if priv, ok := d.PrivateKey.(*mode2.PrivateKey); ok {
			d.publicKey = &DilithiumPublicKey{
				Mode:      d.Mode,
				PublicKey: priv.Public().(*mode2.PublicKey),
			}
		}
	case "dilithium3":
		if priv, ok := d.PrivateKey.(*mode3.PrivateKey); ok {
			d.publicKey = &DilithiumPublicKey{
				Mode:      d.Mode,
				PublicKey: priv.Public().(*mode3.PublicKey),
			}
		}
	case "dilithium5":
		if priv, ok := d.PrivateKey.(*mode5.PrivateKey); ok {
			d.publicKey = &DilithiumPublicKey{
				Mode:      d.Mode,
				PublicKey: priv.Public().(*mode5.PublicKey),
			}
		}
	}
	return d.publicKey
}

func (d *DilithiumPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return d.SignMessage(digest)
}

func GenerateDilithiumKey(mode string) (*DilithiumPrivateKey, error) {
	switch mode {
	case "dilithium2":
		pub, priv, err := mode2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium2 key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
			publicKey: &DilithiumPublicKey{
				Mode:      mode,
				PublicKey: pub,
			},
		}, nil
	case "dilithium3":
		pub, priv, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium3 key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
			publicKey: &DilithiumPublicKey{
				Mode:      mode,
				PublicKey: pub,
			},
		}, nil
	case "dilithium5":
		pub, priv, err := mode5.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium5 key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
			publicKey: &DilithiumPublicKey{
				Mode:      mode,
				PublicKey: pub,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", mode)
	}
}

func (d *DilithiumPrivateKey) SignMessage(message []byte) ([]byte, error) {
	if d == nil || d.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	switch d.Mode {
	case "dilithium2":
		priv, ok := d.PrivateKey.(*mode2.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type for dilithium2")
		}
		sig := make([]byte, mode2.SignatureSize)
		mode2.SignTo(priv, message, sig)
		return sig, nil
	case "dilithium3":
		priv, ok := d.PrivateKey.(*mode3.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type for dilithium3")
		}
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(priv, message, sig)
		return sig, nil
	case "dilithium5":
		priv, ok := d.PrivateKey.(*mode5.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type for dilithium5")
		}
		sig := make([]byte, mode5.SignatureSize)
		mode5.SignTo(priv, message, sig)
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", d.Mode)
	}
}

func (d *DilithiumPublicKey) Verify(message, signature []byte) bool {
	if d == nil || d.PublicKey == nil {
		return false
	}
	
	if len(message) == 0 || len(signature) == 0 {
		return false
	}

	switch d.Mode {
	case "dilithium2":
		pub, ok := d.PublicKey.(*mode2.PublicKey)
		if !ok {
			return false
		}
		if len(signature) != mode2.SignatureSize {
			return false
		}
		return mode2.Verify(pub, message, signature)
	case "dilithium3":
		pub, ok := d.PublicKey.(*mode3.PublicKey)
		if !ok {
			return false
		}
		if len(signature) != mode3.SignatureSize {
			return false
		}
		return mode3.Verify(pub, message, signature)
	case "dilithium5":
		pub, ok := d.PublicKey.(*mode5.PublicKey)
		if !ok {
			return false
		}
		if len(signature) != mode5.SignatureSize {
			return false
		}
		return mode5.Verify(pub, message, signature)
	default:
		return false
	}
}

func (d *DilithiumPrivateKey) Bytes() ([]byte, error) {
	if d == nil || d.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	switch d.Mode {
	case "dilithium2":
		priv, ok := d.PrivateKey.(*mode2.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type")
		}
		return priv.Bytes(), nil
	case "dilithium3":
		priv, ok := d.PrivateKey.(*mode3.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type")
		}
		return priv.Bytes(), nil
	case "dilithium5":
		priv, ok := d.PrivateKey.(*mode5.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type")
		}
		return priv.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", d.Mode)
	}
}

func (d *DilithiumPublicKey) Bytes() ([]byte, error) {
	if d == nil || d.PublicKey == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	
	switch d.Mode {
	case "dilithium2":
		pub, ok := d.PublicKey.(*mode2.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type")
		}
		return pub.Bytes(), nil
	case "dilithium3":
		pub, ok := d.PublicKey.(*mode3.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type")
		}
		return pub.Bytes(), nil
	case "dilithium5":
		pub, ok := d.PublicKey.(*mode5.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type")
		}
		return pub.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", d.Mode)
	}
}

func parseDilithiumPrivateKey(mode string, keyData []byte) (*DilithiumPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "dilithium2":
		priv := new(mode2.PrivateKey)
		if err := priv.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium2 private key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "dilithium3":
		priv := new(mode3.PrivateKey)
		if err := priv.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium3 private key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	case "dilithium5":
		priv := new(mode5.PrivateKey)
		if err := priv.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium5 private key: %w", err)
		}
		return &DilithiumPrivateKey{
			Mode:       mode,
			PrivateKey: priv,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", mode)
	}
}

func parseDilithiumPublicKey(mode string, keyData []byte) (*DilithiumPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "dilithium2":
		pub := new(mode2.PublicKey)
		if err := pub.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium2 public key: %w", err)
		}
		return &DilithiumPublicKey{
			Mode:      mode,
			PublicKey: pub,
		}, nil
	case "dilithium3":
		pub := new(mode3.PublicKey)
		if err := pub.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium3 public key: %w", err)
		}
		return &DilithiumPublicKey{
			Mode:      mode,
			PublicKey: pub,
		}, nil
	case "dilithium5":
		pub := new(mode5.PublicKey)
		if err := pub.UnmarshalBinary(keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium5 public key: %w", err)
		}
		return &DilithiumPublicKey{
			Mode:      mode,
			PublicKey: pub,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium mode: %s", mode)
	}
}