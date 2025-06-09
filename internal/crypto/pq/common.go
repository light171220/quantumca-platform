package pq

import (
	"encoding/asn1"
	"fmt"
)

func GenerateKey(algorithm string) (interface{}, error) {
	switch algorithm {
	case "dilithium2", "dilithium3", "dilithium5":
		return GenerateDilithiumKey(algorithm)
	case "falcon512", "falcon1024":
		return GenerateFalconKey(algorithm)
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
		return GenerateSPHINCSKey(algorithm)
	case "kyber512", "kyber768", "kyber1024":
		return GenerateKyberKey(algorithm)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func GetPublicKey(privateKey interface{}) (interface{}, error) {
	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		return key.Public(), nil
	case *FalconPrivateKey:
		return key.Public(), nil
	case *SPHINCSPrivateKey:
		return key.Public(), nil
	case *KyberPrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func MarshalPrivateKey(privateKey interface{}) ([]byte, error) {
	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		return asn1.Marshal(struct {
			Mode string
			Key  []byte
		}{
			Mode: key.Mode,
			Key:  []byte(fmt.Sprintf("%v", key.PrivateKey)),
		})
	case *FalconPrivateKey:
		return asn1.Marshal(struct {
			Mode string
			Key  []byte
		}{
			Mode: key.Mode,
			Key:  key.PrivateKey.Bytes(),
		})
	case *SPHINCSPrivateKey:
		return asn1.Marshal(struct {
			Mode string
			Key  []byte
		}{
			Mode: key.Mode,
			Key:  key.PrivateKey,
		})
	case *KyberPrivateKey:
		return asn1.Marshal(struct {
			Mode string
			Key  []byte
		}{
			Mode: key.Mode,
			Key:  []byte(fmt.Sprintf("%v", key.PrivateKey)),
		})
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func ParsePrivateKey(data []byte) (interface{}, error) {
	var keyData struct {
		Mode string
		Key  []byte
	}
	
	if _, err := asn1.Unmarshal(data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	switch keyData.Mode {
	case "dilithium2", "dilithium3", "dilithium5":
		return &DilithiumPrivateKey{
			Mode:       keyData.Mode,
			PrivateKey: keyData.Key,
		}, nil
	case "falcon512", "falcon1024":
		return &FalconPrivateKey{
			Mode: keyData.Mode,
		}, nil
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
		return &SPHINCSPrivateKey{
			Mode:       keyData.Mode,
			PrivateKey: keyData.Key,
		}, nil
	case "kyber512", "kyber768", "kyber1024":
		return &KyberPrivateKey{
			Mode:       keyData.Mode,
			PrivateKey: keyData.Key,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyData.Mode)
	}
}