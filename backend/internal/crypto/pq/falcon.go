package pq

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type FalconPrivateKey struct {
	Mode       string
	PrivateKey []byte
	publicKey  *FalconPublicKey
}

type FalconPublicKey struct {
	Mode      string
	PublicKey []byte
}

func GenerateFalconKey(mode string) (*FalconPrivateKey, error) {
	var sigName string
	
	switch mode {
	case "falcon512":
		sigName = "Falcon-512"
	case "falcon1024":
		sigName = "Falcon-1024"
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	if !oqs.IsSigEnabled(sigName) {
		return nil, fmt.Errorf("Falcon algorithm %s is not enabled in liboqs", sigName)
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

	return &FalconPrivateKey{
		Mode:       mode,
		PrivateKey: privateKey,
		publicKey: &FalconPublicKey{
			Mode:      mode,
			PublicKey: publicKey,
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

	return nil
}

func (f *FalconPrivateKey) Sign(message []byte) ([]byte, error) {
	if f == nil || len(f.PrivateKey) == 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	var sigName string
	switch f.Mode {
	case "falcon512":
		sigName = "Falcon-512"
	case "falcon1024":
		sigName = "Falcon-1024"
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", f.Mode)
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize %s for signing: %w", sigName, err)
	}

	signature, err := sig.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with %s: %w", sigName, err)
	}

	return signature, nil
}

func (f *FalconPublicKey) Verify(message, signature []byte) bool {
	if f == nil || len(f.PublicKey) == 0 {
		return false
	}
	
	if len(message) == 0 || len(signature) == 0 {
		return false
	}

	var sigName string
	switch f.Mode {
	case "falcon512":
		sigName = "Falcon-512"
	case "falcon1024":
		sigName = "Falcon-1024"
	default:
		return false
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, nil)
	if err != nil {
		return false
	}

	isValid, err := sig.Verify(message, signature, f.PublicKey)
	if err != nil {
		return false
	}

	return isValid
}

func (f *FalconPrivateKey) Bytes() ([]byte, error) {
	if f == nil || len(f.PrivateKey) == 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	
	result := make([]byte, len(f.PrivateKey))
	copy(result, f.PrivateKey)
	return result, nil
}

func (f *FalconPublicKey) Bytes() ([]byte, error) {
	if f == nil || len(f.PublicKey) == 0 {
		return nil, fmt.Errorf("invalid public key")
	}
	
	result := make([]byte, len(f.PublicKey))
	copy(result, f.PublicKey)
	return result, nil
}

func parseFalconPrivateKey(mode string, keyData []byte) (*FalconPrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "falcon512", "falcon1024":
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	privateKey := make([]byte, len(keyData))
	copy(privateKey, keyData)

	return &FalconPrivateKey{
		Mode:       mode,
		PrivateKey: privateKey,
	}, nil
}

func parseFalconPublicKey(mode string, keyData []byte) (*FalconPublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	switch mode {
	case "falcon512", "falcon1024":
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	publicKey := make([]byte, len(keyData))
	copy(publicKey, keyData)

	return &FalconPublicKey{
		Mode:      mode,
		PublicKey: publicKey,
	}, nil
}

func IsFalconAvailable() (bool, []string) {
	available := []string{}
	
	if oqs.IsSigEnabled("Falcon-512") {
		available = append(available, "Falcon-512")
	}
	
	if oqs.IsSigEnabled("Falcon-1024") {
		available = append(available, "Falcon-1024")
	}
	
	return len(available) > 0, available
}

func GetFalconDetails(mode string) (map[string]interface{}, error) {
	var sigName string
	switch mode {
	case "falcon512":
		sigName = "Falcon-512"
	case "falcon1024":
		sigName = "Falcon-1024"
	default:
		return nil, fmt.Errorf("unsupported Falcon mode: %s", mode)
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	err := sig.Init(sigName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize %s: %w", sigName, err)
	}

	details := map[string]interface{}{
		"name":               sig.Details().Name,
		"version":            sig.Details().Version,
		"claimed_nist_level": sig.Details().ClaimedNISTLevel,
		"euf_cma":            sig.Details().IsEUFCMA,
		"public_key_length":  sig.Details().LengthPublicKey,
		"private_key_length": sig.Details().LengthSecretKey,
		"signature_length":   sig.Details().MaxLengthSignature,
	}

	return details, nil
}