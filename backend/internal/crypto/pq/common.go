package pq

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iterations = 100000
	saltSize         = 32
	keySize          = 32
)

type PrivateKeyInfo struct {
	Algorithm string
	Mode      string
	KeyData   []byte
}

type PublicKeyInfo struct {
	Algorithm string
	Mode      string
	KeyData   []byte
}

type EncryptedPrivateKeyInfo struct {
	Algorithm  string
	Mode       string
	Salt       []byte
	IV         []byte
	Iterations int
	KeyData    []byte
}

func GenerateKey(algorithm string) (interface{}, error) {
	if algorithm == "" {
		return nil, fmt.Errorf("algorithm cannot be empty")
	}
	
	switch algorithm {
	case "dilithium2", "dilithium3", "dilithium5":
		return GenerateDilithiumKey(algorithm)
	case "falcon512", "falcon1024":
		return GenerateFalconKey(algorithm)
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
		return GenerateSPHINCSKey(algorithm)
	case "kyber512", "kyber768", "kyber1024":
		return GenerateKyberKey(algorithm)
	case "multi-pqc":
		return GenerateMultiPQCKeyPair()
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func GetPublicKey(privateKey interface{}) (interface{}, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	
	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		return key.Public(), nil
	case *FalconPrivateKey:
		return key.Public(), nil
	case *SPHINCSPrivateKey:
		return key.Public(), nil
	case *KyberPrivateKey:
		return key.Public(), nil
	case *MultiPQCPrivateKey:
		return key.GetPublicKey()
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

func GetAlgorithmName(key interface{}) (string, error) {
	algorithm := getAlgorithmFromKey(key)
	if algorithm == "" {
		return "", fmt.Errorf("unknown algorithm for key type %T", key)
	}
	return algorithm, nil
}

func MarshalPrivateKey(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	
	var keyInfo PrivateKeyInfo

	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PrivateKeyInfo{
			Algorithm: "dilithium",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *FalconPrivateKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PrivateKeyInfo{
			Algorithm: "falcon",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *SPHINCSPrivateKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PrivateKeyInfo{
			Algorithm: "sphincs",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *KyberPrivateKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PrivateKeyInfo{
			Algorithm: "kyber",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *MultiPQCPrivateKey:
		return MarshalMultiPQCPrivateKey(key)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	return asn1.Marshal(keyInfo)
}

func MarshalPrivateKeyEncrypted(privateKey interface{}, password string) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	
	plaintext, err := MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	derivedKey := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keySize, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	var algorithm, mode string
	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		algorithm, mode = "dilithium", key.Mode
	case *FalconPrivateKey:
		algorithm, mode = "falcon", key.Mode
	case *SPHINCSPrivateKey:
		algorithm, mode = "sphincs", key.Mode
	case *KyberPrivateKey:
		algorithm, mode = "kyber", key.Mode
	case *MultiPQCPrivateKey:
		algorithm, mode = "multi-pqc", "composite"
	}

	encKeyInfo := EncryptedPrivateKeyInfo{
		Algorithm:  algorithm,
		Mode:       mode,
		Salt:       salt,
		IV:         iv,
		Iterations: pbkdf2Iterations,
		KeyData:    ciphertext,
	}

	return asn1.Marshal(encKeyInfo)
}

func MarshalPublicKey(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	
	var keyInfo PublicKeyInfo

	switch key := publicKey.(type) {
	case *DilithiumPublicKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PublicKeyInfo{
			Algorithm: "dilithium",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *FalconPublicKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PublicKeyInfo{
			Algorithm: "falcon",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *SPHINCSPublicKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PublicKeyInfo{
			Algorithm: "sphincs",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *KyberPublicKey:
		keyData, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bytes: %w", err)
		}
		keyInfo = PublicKeyInfo{
			Algorithm: "kyber",
			Mode:      key.Mode,
			KeyData:   keyData,
		}
	case *MultiPQCPublicKey:
		return MarshalMultiPQCPublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	return asn1.Marshal(keyInfo)
}

func ParsePrivateKey(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var keyInfo PrivateKeyInfo
	
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	switch keyInfo.Algorithm {
	case "dilithium":
		return parseDilithiumPrivateKey(keyInfo.Mode, keyInfo.KeyData)
	case "falcon":
		return parseFalconPrivateKey(keyInfo.Mode, keyInfo.KeyData)
	case "sphincs":
		return parseSPHINCSPrivateKey(keyInfo.Mode, keyInfo.KeyData)
	case "kyber":
		return parseKyberPrivateKey(keyInfo.Mode, keyInfo.KeyData)
	case "multi-pqc":
		return ParseMultiPQCPrivateKey(data)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyInfo.Algorithm)
	}
}

func ParsePrivateKeyEncrypted(data []byte, password string) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	
	var encKeyInfo EncryptedPrivateKeyInfo
	
	if _, err := asn1.Unmarshal(data, &encKeyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted private key: %w", err)
	}

	iterations := encKeyInfo.Iterations
	if iterations <= 0 {
		iterations = pbkdf2Iterations
	}

	derivedKey := pbkdf2.Key([]byte(password), encKeyInfo.Salt, iterations, keySize, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, encKeyInfo.IV, encKeyInfo.KeyData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key (invalid password?): %w", err)
	}

	defer SecureZero(plaintext)
	defer SecureZero(derivedKey)

	return ParsePrivateKey(plaintext)
}

func ParsePublicKey(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty key data")
	}
	
	var keyInfo PublicKeyInfo
	
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	switch keyInfo.Algorithm {
	case "dilithium":
		return parseDilithiumPublicKey(keyInfo.Mode, keyInfo.KeyData)
	case "falcon":
		return parseFalconPublicKey(keyInfo.Mode, keyInfo.KeyData)
	case "sphincs":
		return parseSPHINCSPublicKey(keyInfo.Mode, keyInfo.KeyData)
	case "kyber":
		return parseKyberPublicKey(keyInfo.Mode, keyInfo.KeyData)
	case "multi-pqc":
		return ParseMultiPQCPublicKey(data)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyInfo.Algorithm)
	}
}

func GetKeySize(algorithm string) (privateKeySize, publicKeySize int, err error) {
	switch algorithm {
	case "dilithium2":
		return 2560, 1312, nil
	case "dilithium3":
		return 4000, 1952, nil
	case "dilithium5":
		return 4864, 2592, nil
	case "kyber512":
		return 1632, 800, nil
	case "kyber768":
		return 2400, 1184, nil
	case "kyber1024":
		return 3168, 1568, nil
	case "falcon512":
		return 1281, 897, nil
	case "falcon1024":
		return 2305, 1793, nil
	case "sphincs-sha256-128f":
		return 64, 32, nil
	case "sphincs-sha256-128s":
		return 64, 32, nil
	case "sphincs-sha256-192f":
		return 96, 48, nil
	case "sphincs-sha256-256f":
		return 128, 64, nil
	case "multi-pqc":
		return 10000, 5000, nil
	default:
		return 0, 0, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func IsSignatureAlgorithm(algorithm string) bool {
	switch algorithm {
	case "dilithium2", "dilithium3", "dilithium5":
		return true
	case "falcon512", "falcon1024":
		return true
	case "sphincs-sha256-128f", "sphincs-sha256-128s", "sphincs-sha256-192f", "sphincs-sha256-256f":
		return true
	case "multi-pqc":
		return true
	default:
		return false
	}
}

func IsKEMAlgorithm(algorithm string) bool {
	switch algorithm {
	case "kyber512", "kyber768", "kyber1024":
		return true
	default:
		return false
	}
}

func GetAlgorithmOID(algorithm string) (asn1.ObjectIdentifier, error) {
	oids := map[string]asn1.ObjectIdentifier{
		"dilithium2":            {2, 16, 840, 1, 101, 3, 4, 3, 17},
		"dilithium3":            {2, 16, 840, 1, 101, 3, 4, 3, 18},
		"dilithium5":            {2, 16, 840, 1, 101, 3, 4, 3, 19},
		"falcon512":             {1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 3},
		"falcon1024":            {1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 4},
		"sphincs-sha256-128f":   {1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 1},
		"sphincs-sha256-128s":   {1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 2},
		"sphincs-sha256-192f":   {1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 1},
		"sphincs-sha256-256f":   {1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 1},
		"kyber512":              {1, 3, 6, 1, 4, 1, 2, 267, 5, 3, 1},
		"kyber768":              {1, 3, 6, 1, 4, 1, 2, 267, 5, 3, 2},
		"kyber1024":             {1, 3, 6, 1, 4, 1, 2, 267, 5, 3, 3},
		"multi-pqc":             {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1},
	}

	oid, exists := oids[algorithm]
	if !exists {
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
	return oid, nil
}

func Sign(privateKey interface{}, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}
	
	switch key := privateKey.(type) {
	case *DilithiumPrivateKey:
		return key.SignMessage(message)
	case *SPHINCSPrivateKey:
		return key.Sign(message)
	case *MultiPQCPrivateKey:
		signature, err := key.SignMessage(message)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(*signature)
	default:
		return nil, fmt.Errorf("unsupported private key type for signing: %T", privateKey)
	}
}

func Verify(publicKey interface{}, message, signature []byte) bool {
	if publicKey == nil || len(message) == 0 || len(signature) == 0 {
		return false
	}
	
	switch key := publicKey.(type) {
	case *DilithiumPublicKey:
		return key.Verify(message, signature)
	case *SPHINCSPublicKey:
		return key.Verify(message, signature)
	case *MultiPQCPublicKey:
		var multiSig MultiPQCSignature
		if _, err := asn1.Unmarshal(signature, &multiSig); err != nil {
			return false
		}
		return key.Verify(message, &multiSig)
	default:
		return false
	}
}

func Encapsulate(publicKey interface{}) (ciphertext, sharedSecret []byte, err error) {
	if publicKey == nil {
		return nil, nil, fmt.Errorf("public key cannot be nil")
	}
	
	switch key := publicKey.(type) {
	case *KyberPublicKey:
		return key.Encapsulate()
	default:
		return nil, nil, fmt.Errorf("unsupported public key type for encapsulation: %T", publicKey)
	}
}

func Decapsulate(privateKey interface{}, ciphertext []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}
	
	switch key := privateKey.(type) {
	case *KyberPrivateKey:
		return key.Decapsulate(ciphertext)
	default:
		return nil, fmt.Errorf("unsupported private key type for decapsulation: %T", privateKey)
	}
}

func SecureZero(data []byte) {
	if len(data) > 0 {
		for i := range data {
			data[i] = 0
		}
	}
}

func ValidateKeyPair(privateKey, publicKey interface{}) error {
	if privateKey == nil || publicKey == nil {
		return fmt.Errorf("keys cannot be nil")
	}
	
	testMessage := []byte("QuantumCA key validation test message")
	
	algorithm := getAlgorithmFromKey(privateKey)
	if algorithm == "" {
		return fmt.Errorf("unknown algorithm")
	}
	
	if IsSignatureAlgorithm(algorithm) {
		signature, err := Sign(privateKey, testMessage)
		if err != nil {
			return fmt.Errorf("failed to sign test message: %w", err)
		}
		
		if !Verify(publicKey, testMessage, signature) {
			return fmt.Errorf("signature verification failed")
		}
	}
	
	if IsKEMAlgorithm(algorithm) {
		ciphertext, sharedSecret1, err := Encapsulate(publicKey)
		if err != nil {
			return fmt.Errorf("failed to encapsulate: %w", err)
		}
		
		sharedSecret2, err := Decapsulate(privateKey, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to decapsulate: %w", err)
		}
		
		if subtle.ConstantTimeCompare(sharedSecret1, sharedSecret2) != 1 {
			return fmt.Errorf("shared secret mismatch")
		}
	}
	
	return nil
}

func getAlgorithmFromKey(key interface{}) string {
	switch k := key.(type) {
	case *DilithiumPrivateKey:
		return k.Mode
	case *DilithiumPublicKey:
		return k.Mode
	case *FalconPrivateKey:
		return k.Mode
	case *FalconPublicKey:
		return k.Mode
	case *SPHINCSPrivateKey:
		return k.Mode
	case *SPHINCSPublicKey:
		return k.Mode
	case *KyberPrivateKey:
		return k.Mode
	case *KyberPublicKey:
		return k.Mode
	case *MultiPQCPrivateKey:
		return "multi-pqc"
	case *MultiPQCPublicKey:
		return "multi-pqc"
	default:
		return ""
	}
}

func IsMultiPQCKey(key interface{}) bool {
	switch key.(type) {
	case *MultiPQCPrivateKey, *MultiPQCPublicKey:
		return true
	default:
		return false
	}
}

func GetMultiPQCAlgorithms(key interface{}) ([]string, error) {
	switch k := key.(type) {
	case *MultiPQCPrivateKey:
		return []string{k.PrimaryAlgorithm, k.SecondaryAlgorithm, k.TertiaryAlgorithm}, nil
	case *MultiPQCPublicKey:
		return []string{k.PrimaryAlgorithm, k.SecondaryAlgorithm, k.TertiaryAlgorithm}, nil
	default:
		return nil, fmt.Errorf("not a multi-PQC key")
	}
}