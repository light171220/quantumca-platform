package keymanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type EncryptedKeyStore struct {
	storePath string
	masterKey []byte
	salt      []byte
}

type EncryptedKeyMetadata struct {
	Algorithm    string    `json:"algorithm"`
	KeyType      string    `json:"key_type"`
	Salt         []byte    `json:"salt"`
	IV           []byte    `json:"iv"`
	Iterations   int       `json:"iterations"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	KeyID        string    `json:"key_id"`
}

type EncryptedKeyData struct {
	Metadata       EncryptedKeyMetadata `json:"metadata"`
	EncryptedKey   []byte               `json:"encrypted_key"`
	IntegrityHash  []byte               `json:"integrity_hash"`
}

type MasterKeyConfig struct {
	Salt       []byte    `json:"salt"`
	Algorithm  string    `json:"algorithm"`
	Iterations int       `json:"iterations"`
	CreatedAt  time.Time `json:"created_at"`
}

func NewEncryptedKeyStore(storePath string, masterPassword string) (*EncryptedKeyStore, error) {
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	eks := &EncryptedKeyStore{
		storePath: storePath,
	}

	if err := eks.initializeMasterKey(masterPassword); err != nil {
		return nil, fmt.Errorf("failed to initialize master key: %w", err)
	}

	return eks, nil
}

func (eks *EncryptedKeyStore) initializeMasterKey(masterPassword string) error {
	configPath := filepath.Join(eks.storePath, ".master_config")
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return eks.createNewMasterKey(masterPassword, configPath)
	}
	
	return eks.loadExistingMasterKey(masterPassword, configPath)
}

func (eks *EncryptedKeyStore) createNewMasterKey(masterPassword string, configPath string) error {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	config := MasterKeyConfig{
		Salt:       salt,
		Algorithm:  "scrypt",
		Iterations: 32768,
		CreatedAt:  time.Now(),
	}

	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal master key config: %w", err)
	}

	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to write master key config: %w", err)
	}

	masterKey, err := scrypt.Key([]byte(masterPassword), salt, config.Iterations, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("failed to derive master key: %w", err)
	}

	eks.masterKey = masterKey
	eks.salt = salt
	
	return nil
}

func (eks *EncryptedKeyStore) loadExistingMasterKey(masterPassword string, configPath string) error {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read master key config: %w", err)
	}

	var config MasterKeyConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("failed to unmarshal master key config: %w", err)
	}

	var masterKey []byte
	switch config.Algorithm {
	case "scrypt":
		masterKey, err = scrypt.Key([]byte(masterPassword), config.Salt, config.Iterations, 8, 1, 32)
	case "pbkdf2":
		masterKey = pbkdf2.Key([]byte(masterPassword), config.Salt, config.Iterations, 32, sha256.New)
	default:
		return fmt.Errorf("unsupported key derivation algorithm: %s", config.Algorithm)
	}

	if err != nil {
		return fmt.Errorf("failed to derive master key: %w", err)
	}

	eks.masterKey = masterKey
	eks.salt = config.Salt
	
	return nil
}

func (eks *EncryptedKeyStore) StoreKey(keyID string, keyData []byte, keyType string, algorithm string) error {
	if len(keyData) == 0 {
		return fmt.Errorf("key data cannot be empty")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	iterations := 100000
	derivedKey := pbkdf2.Key(eks.masterKey, salt, iterations, 32, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	encryptedKey := gcm.Seal(nil, iv, keyData, nil)

	integrityHash := sha256.Sum256(append(encryptedKey, salt...))

	metadata := EncryptedKeyMetadata{
		Algorithm:    algorithm,
		KeyType:      keyType,
		Salt:         salt,
		IV:           iv,
		Iterations:   iterations,
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
		KeyID:        keyID,
	}

	encryptedData := EncryptedKeyData{
		Metadata:      metadata,
		EncryptedKey:  encryptedKey,
		IntegrityHash: integrityHash[:],
	}

	jsonData, err := json.Marshal(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	keyFile := filepath.Join(eks.storePath, keyID+".encrypted")
	if err := os.WriteFile(keyFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted key file: %w", err)
	}

	secureZero(derivedKey)
	secureZero(keyData)

	return nil
}

func (eks *EncryptedKeyStore) LoadKey(keyID string) ([]byte, *EncryptedKeyMetadata, error) {
	keyFile := filepath.Join(eks.storePath, keyID+".encrypted")
	
	jsonData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read encrypted key file: %w", err)
	}

	var encryptedData EncryptedKeyData
	if err := json.Unmarshal(jsonData, &encryptedData); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	integrityCheck := sha256.Sum256(append(encryptedData.EncryptedKey, encryptedData.Metadata.Salt...))
	if !constantTimeCompare(integrityCheck[:], encryptedData.IntegrityHash) {
		return nil, nil, fmt.Errorf("integrity check failed - key may be corrupted")
	}

	derivedKey := pbkdf2.Key(eks.masterKey, encryptedData.Metadata.Salt, encryptedData.Metadata.Iterations, 32, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	keyData, err := gcm.Open(nil, encryptedData.Metadata.IV, encryptedData.EncryptedKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	encryptedData.Metadata.LastAccessed = time.Now()
	
	updatedData, _ := json.Marshal(encryptedData)
	os.WriteFile(keyFile, updatedData, 0600)

	secureZero(derivedKey)

	return keyData, &encryptedData.Metadata, nil
}

func (eks *EncryptedKeyStore) StoreCertificate(keyID string, certData []byte) error {
	if len(certData) == 0 {
		return fmt.Errorf("certificate data cannot be empty")
	}
	
	certFile := filepath.Join(eks.storePath, keyID+".cert")
	return os.WriteFile(certFile, certData, 0644)
}

func (eks *EncryptedKeyStore) LoadCertificate(keyID string) ([]byte, error) {
	certFile := filepath.Join(eks.storePath, keyID+".cert")
	return os.ReadFile(certFile)
}

func (eks *EncryptedKeyStore) DeleteKey(keyID string) error {
	keyFile := filepath.Join(eks.storePath, keyID+".encrypted")
	certFile := filepath.Join(eks.storePath, keyID+".cert")
	
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("key not found: %s", keyID)
	}

	if err := secureDelete(keyFile); err != nil {
		return fmt.Errorf("failed to securely delete key file: %w", err)
	}

	if _, err := os.Stat(certFile); err == nil {
		os.Remove(certFile)
	}

	return nil
}

func (eks *EncryptedKeyStore) ListKeys() ([]string, error) {
	files, err := os.ReadDir(eks.storePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key store directory: %w", err)
	}

	var keyIDs []string
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".encrypted" {
			keyID := file.Name()[:len(file.Name())-10]
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

func (eks *EncryptedKeyStore) GetKeyMetadata(keyID string) (*EncryptedKeyMetadata, error) {
	keyFile := filepath.Join(eks.storePath, keyID+".encrypted")
	
	jsonData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file: %w", err)
	}

	var encryptedData EncryptedKeyData
	if err := json.Unmarshal(jsonData, &encryptedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	return &encryptedData.Metadata, nil
}

func (eks *EncryptedKeyStore) RotateMasterKey(newPassword string) error {
	configPath := filepath.Join(eks.storePath, ".master_config")
	
	newSalt := make([]byte, 32)
	if _, err := rand.Read(newSalt); err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	newMasterKey, err := scrypt.Key([]byte(newPassword), newSalt, 32768, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("failed to derive new master key: %w", err)
	}

	keyIDs, err := eks.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys for rotation: %w", err)
	}

	for _, keyID := range keyIDs {
		keyData, metadata, err := eks.LoadKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to load key %s for rotation: %w", keyID, err)
		}

		oldMasterKey := eks.masterKey
		oldSalt := eks.salt
		
		eks.masterKey = newMasterKey
		eks.salt = newSalt
		
		if err := eks.StoreKey(keyID, keyData, metadata.KeyType, metadata.Algorithm); err != nil {
			eks.masterKey = oldMasterKey
			eks.salt = oldSalt
			secureZero(keyData)
			return fmt.Errorf("failed to re-encrypt key %s: %w", keyID, err)
		}
		
		secureZero(keyData)
	}

	config := MasterKeyConfig{
		Salt:       newSalt,
		Algorithm:  "scrypt",
		Iterations: 32768,
		CreatedAt:  time.Now(),
	}

	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal new master key config: %w", err)
	}

	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to write new master key config: %w", err)
	}

	secureZero(eks.masterKey)
	eks.masterKey = newMasterKey
	eks.salt = newSalt

	return nil
}

func (eks *EncryptedKeyStore) ValidateIntegrity() error {
	keyIDs, err := eks.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	for _, keyID := range keyIDs {
		_, _, err := eks.LoadKey(keyID)
		if err != nil {
			return fmt.Errorf("integrity check failed for key %s: %w", keyID, err)
		}
	}

	return nil
}

func (eks *EncryptedKeyStore) GetStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	
	keyIDs, err := eks.ListKeys()
	if err != nil {
		stats["error"] = err.Error()
		return stats
	}
	
	stats["total_keys"] = len(keyIDs)
	
	keyTypes := make(map[string]int)
	algorithms := make(map[string]int)
	
	for _, keyID := range keyIDs {
		metadata, err := eks.GetKeyMetadata(keyID)
		if err != nil {
			continue
		}
		
		keyTypes[metadata.KeyType]++
		algorithms[metadata.Algorithm]++
	}
	
	stats["key_types"] = keyTypes
	stats["algorithms"] = algorithms
	
	return stats
}

func secureDelete(filename string) error {
	file, err := os.OpenFile(filename, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	size := stat.Size()
	
	for pass := 0; pass < 3; pass++ {
		file.Seek(0, 0)
		
		var pattern byte
		switch pass {
		case 0:
			pattern = 0x00
		case 1:
			pattern = 0xFF
		case 2:
			if _, err := io.CopyN(file, rand.Reader, size); err != nil {
				return err
			}
			continue
		}
		
		data := make([]byte, 4096)
		for i := range data {
			data[i] = pattern
		}
		
		remaining := size
		for remaining > 0 {
			writeSize := int64(len(data))
			if remaining < writeSize {
				writeSize = remaining
			}
			
			if _, err := file.Write(data[:writeSize]); err != nil {
				return err
			}
			remaining -= writeSize
		}
		
		if err := file.Sync(); err != nil {
			return err
		}
	}

	file.Close()
	return os.Remove(filename)
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}

func secureZero(data []byte) {
	if len(data) > 0 {
		for i := range data {
			data[i] = 0
		}
	}
}