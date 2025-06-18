package pq

import (
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

type FalconPrivateKey struct {
	Mode       string
	PrivateKey sign.PrivateKey
	publicKey  *FalconPublicKey
}

type FalconPublicKey struct {
	Mode      string
	PublicKey sign.PublicKey
}

func GenerateFalconKey(mode string) (*FalconPrivateKey, error) {
	var scheme sign.Scheme
	
	switch mode {
	case "falcon512":
		scheme = schemes.ByName("Falcon512")
	case "falcon1024":
		scheme = schemes.ByName("Falcon1024")
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get Falcon scheme for mode: %s", mode)
	}

	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", mode, err)
	}

	return &FalconPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
		publicKey: &FalconPublicKey{
			Mode:      mode,
			PublicKey: pub,
		},
	}, nil
}

func (f *FalconPrivateKey) Public() interface{} {
	if f == nil {
		return nil
	}
	
	if f.publicKey != nil {
		return f.publicKey
	}

	if f.PrivateKey != nil {
		pubKey := f.PrivateKey.Public()
		if signPubKey, ok := pubKey.(sign.PublicKey); ok {
			f.publicKey = &FalconPublicKey{
				Mode:      f.Mode,
				PublicKey: signPubKey,
			}
		}
	}
	
	return f.publicKey
}

func (f *FalconPrivateKey) Sign(message []byte) ([]byte, error) {
	if f == nil || f.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	var scheme sign.Scheme
	switch f.Mode {
	case "falcon512":
		scheme = schemes.ByName("Falcon512")
	case "falcon1024":
		scheme = schemes.ByName("Falcon1024")
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", f.Mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get Falcon scheme for mode: %s", f.Mode)
	}

	signature := scheme.Sign(f.PrivateKey, message, &sign.SignatureOpts{})
	return signature, nil
}

func (f *FalconPublicKey) Verify(message, signature []byte) bool {
	if f == nil || f.PublicKey == nil {
		return false
	}
	
	if len(message) == 0 || len(signature) == 0 {
		return false
	}

	var scheme sign.Scheme
	switch f.Mode {
	case "falcon512":
		scheme = schemes.ByName("Falcon512")
	case "falcon1024":
		scheme = schemes.ByName("Falcon1024")
	default:
		return false
	}

	if scheme == nil {
		return false
	}

	return scheme.Verify(f.PublicKey, message, signature, &sign.SignatureOpts{})
}

func (f *FalconPrivateKey) Bytes() ([]byte, error) {
	if f == nil || f.PrivateKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	
	keyBytes, err := f.PrivateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return keyBytes, nil
}

func (f *FalconPublicKey) Bytes() ([]byte, error) {
	if f == nil || f.PublicKey == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	
	keyBytes, err := f.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return keyBytes, nil
}

func parseFalconPrivateKey(mode string, keyData []byte) (*FalconPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme sign.Scheme
	switch mode {
	case "falcon512":
		scheme = schemes.ByName("Falcon512")
	case "falcon1024":
		scheme = schemes.ByName("Falcon1024")
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get Falcon scheme for mode: %s", mode)
	}

	priv, err := scheme.UnmarshalBinaryPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s private key: %w", mode, err)
	}

	return &FalconPrivateKey{
		Mode:       mode,
		PrivateKey: priv,
	}, nil
}

func parseFalconPublicKey(mode string, keyData []byte) (*FalconPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var scheme sign.Scheme
	switch mode {
	case "falcon512":
		scheme = schemes.ByName("Falcon512")
	case "falcon1024":
		scheme = schemes.ByName("Falcon1024")
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	if scheme == nil {
		return nil, fmt.Errorf("failed to get Falcon scheme for mode: %s", mode)
	}

	pub, err := scheme.UnmarshalBinaryPublicKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s public key: %w", mode, err)
	}

	return &FalconPublicKey{
		Mode:      mode,
		PublicKey: pub,
	}, nil
}