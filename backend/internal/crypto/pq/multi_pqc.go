package pq

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"
)

type MultiPQCPrivateKey struct {
	PrimaryAlgorithm   string
	SecondaryAlgorithm string
	TertiaryAlgorithm  string
	PrimaryKey         interface{}
	SecondaryKey       interface{}
	TertiaryKey        interface{}
	CombinedKeyID      []byte
}

type MultiPQCPublicKey struct {
	PrimaryAlgorithm   string
	SecondaryAlgorithm string
	TertiaryAlgorithm  string
	PrimaryKey         interface{}
	SecondaryKey       interface{}
	TertiaryKey        interface{}
	CombinedKeyID      []byte
}

type MultiPQCSignature struct {
	PrimarySignature   []byte   `asn1:"tag:0"`
	SecondarySignature []byte   `asn1:"tag:1"`
	TertiarySignature  []byte   `asn1:"tag:2"`
	Algorithms         []string `asn1:"tag:3"`
	CombinedHash       []byte   `asn1:"tag:4"`
}

type MultiPQCKeyInfo struct {
	Algorithms []string `json:"algorithms"`
	KeyData    [][]byte `json:"key_data"`
	CombinedID []byte   `json:"combined_id"`
}

type signatureResult struct {
	signature []byte
	err       error
	index     int
}

type keyGenResult struct {
	privateKey interface{}
	publicKey  interface{}
	err        error
	index      int
}

type verificationResult struct {
	valid bool
	err   error
	index int
}

var defaultTimeout = 30 * time.Second

func (m *MultiPQCPrivateKey) Public() crypto.PublicKey {
	multiPQCPublic, err := m.GetPublicKey()
	if err != nil {
		return nil
	}
	return multiPQCPublic
}

func (m *MultiPQCPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	multiSig, err := m.SignMessage(digest)
	if err != nil {
		return nil, fmt.Errorf("multi-PQC signature failed: %w", err)
	}
	
	return asn1.Marshal(*multiSig)
}

func GenerateMultiPQCKeyPair() (*MultiPQCPrivateKey, error) {
	return GenerateMultiPQCKeyPairWithTimeout(defaultTimeout)
}

func GenerateMultiPQCKeyPairWithTimeout(timeout time.Duration) (*MultiPQCPrivateKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	algorithms := []string{"dilithium3", "sphincs-sha256-128s", "dilithium5"}
	
	resultChan := make(chan keyGenResult, len(algorithms))
	var wg sync.WaitGroup
	
	for i, alg := range algorithms {
		wg.Add(1)
		go func(index int, algorithm string) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- keyGenResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			privateKey, err := GenerateKey(algorithm)
			if err != nil {
				resultChan <- keyGenResult{err: fmt.Errorf("failed to generate %s key: %w", algorithm, err), index: index}
				return
			}
			
			publicKey, err := GetPublicKey(privateKey)
			if err != nil {
				resultChan <- keyGenResult{err: fmt.Errorf("failed to get %s public key: %w", algorithm, err), index: index}
				return
			}
			
			resultChan <- keyGenResult{privateKey: privateKey, publicKey: publicKey, index: index}
		}(i, alg)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keys := make([]interface{}, len(algorithms))
	pubKeys := make([]interface{}, len(algorithms))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, result.err
		}
		keys[result.index] = result.privateKey
		pubKeys[result.index] = result.publicKey
	}
	
	combinedID, err := generateCombinedKeyID(pubKeys[0], pubKeys[1], pubKeys[2])
	if err != nil {
		return nil, fmt.Errorf("failed to generate combined key ID: %w", err)
	}
	
	return &MultiPQCPrivateKey{
		PrimaryAlgorithm:   algorithms[0],
		SecondaryAlgorithm: algorithms[1],
		TertiaryAlgorithm:  algorithms[2],
		PrimaryKey:         keys[0],
		SecondaryKey:       keys[1],
		TertiaryKey:        keys[2],
		CombinedKeyID:      combinedID,
	}, nil
}

func (m *MultiPQCPrivateKey) GetPublicKey() (*MultiPQCPublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	
	keys := []interface{}{m.PrimaryKey, m.SecondaryKey, m.TertiaryKey}
	resultChan := make(chan keyGenResult, len(keys))
	var wg sync.WaitGroup
	
	for i, key := range keys {
		wg.Add(1)
		go func(index int, privateKey interface{}) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- keyGenResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			publicKey, err := GetPublicKey(privateKey)
			if err != nil {
				resultChan <- keyGenResult{err: err, index: index}
				return
			}
			
			resultChan <- keyGenResult{publicKey: publicKey, index: index}
		}(i, key)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	pubKeys := make([]interface{}, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", result.err)
		}
		pubKeys[result.index] = result.publicKey
	}
	
	return &MultiPQCPublicKey{
		PrimaryAlgorithm:   m.PrimaryAlgorithm,
		SecondaryAlgorithm: m.SecondaryAlgorithm,
		TertiaryAlgorithm:  m.TertiaryAlgorithm,
		PrimaryKey:         pubKeys[0],
		SecondaryKey:       pubKeys[1],
		TertiaryKey:        pubKeys[2],
		CombinedKeyID:      m.CombinedKeyID,
	}, nil
}

func (m *MultiPQCPrivateKey) SignMessage(message []byte) (*MultiPQCSignature, error) {
	return m.SignMessageWithTimeout(message, defaultTimeout)
}

func (m *MultiPQCPrivateKey) SignMessageWithTimeout(message []byte, timeout time.Duration) (*MultiPQCSignature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	keys := []interface{}{m.PrimaryKey, m.SecondaryKey, m.TertiaryKey}
	algorithms := []string{m.PrimaryAlgorithm, m.SecondaryAlgorithm, m.TertiaryAlgorithm}
	
	resultChan := make(chan signatureResult, len(keys))
	var wg sync.WaitGroup
	
	for i, key := range keys {
		wg.Add(1)
		go func(index int, privateKey interface{}) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- signatureResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			signature, err := Sign(privateKey, message)
			if err != nil {
				resultChan <- signatureResult{err: fmt.Errorf("%s signature failed: %w", algorithms[index], err), index: index}
				return
			}
			
			resultChan <- signatureResult{signature: signature, index: index}
		}(i, key)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	signatures := make([][]byte, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, result.err
		}
		signatures[result.index] = result.signature
	}
	
	combinedHash := sha256.Sum256(append(append(signatures[0], signatures[1]...), signatures[2]...))
	
	return &MultiPQCSignature{
		PrimarySignature:   signatures[0],
		SecondarySignature: signatures[1],
		TertiarySignature:  signatures[2],
		Algorithms:         algorithms,
		CombinedHash:       combinedHash[:],
	}, nil
}

func (m *MultiPQCPublicKey) Verify(message []byte, signature *MultiPQCSignature) bool {
	return m.VerifyWithTimeout(message, signature, defaultTimeout)
}

func (m *MultiPQCPublicKey) VerifyWithTimeout(message []byte, signature *MultiPQCSignature, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	if len(signature.Algorithms) != 3 {
		return false
	}
	
	if signature.Algorithms[0] != m.PrimaryAlgorithm ||
		signature.Algorithms[1] != m.SecondaryAlgorithm ||
		signature.Algorithms[2] != m.TertiaryAlgorithm {
		return false
	}
	
	keys := []interface{}{m.PrimaryKey, m.SecondaryKey, m.TertiaryKey}
	sigs := [][]byte{signature.PrimarySignature, signature.SecondarySignature, signature.TertiarySignature}
	
	resultChan := make(chan verificationResult, len(keys))
	var wg sync.WaitGroup
	
	for i, key := range keys {
		wg.Add(1)
		go func(index int, publicKey interface{}, sig []byte) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- verificationResult{valid: false, err: ctx.Err(), index: index}
				return
			default:
			}
			
			valid := Verify(publicKey, message, sig)
			resultChan <- verificationResult{valid: valid, index: index}
		}(i, key, sigs[i])
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	validations := make([]bool, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return false
		}
		validations[result.index] = result.valid
	}
	
	for _, valid := range validations {
		if !valid {
			return false
		}
	}
	
	expectedHash := sha256.Sum256(append(append(signature.PrimarySignature, signature.SecondarySignature...), signature.TertiarySignature...))
	
	if len(signature.CombinedHash) != len(expectedHash) {
		return false
	}
	
	for i := range expectedHash {
		if signature.CombinedHash[i] != expectedHash[i] {
			return false
		}
	}
	
	return true
}

func generateCombinedKeyID(primary, secondary, tertiary interface{}) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	type marshalResult struct {
		bytes []byte
		err   error
		index int
	}
	
	keys := []interface{}{primary, secondary, tertiary}
	resultChan := make(chan marshalResult, len(keys))
	var wg sync.WaitGroup
	
	for i, key := range keys {
		wg.Add(1)
		go func(index int, k interface{}) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- marshalResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			bytes, err := MarshalPublicKey(k)
			resultChan <- marshalResult{bytes: bytes, err: err, index: index}
		}(i, key)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keyBytes := make([][]byte, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to marshal key %d: %w", result.index, result.err)
		}
		keyBytes[result.index] = result.bytes
	}
	
	combined := append(append(keyBytes[0], keyBytes[1]...), keyBytes[2]...)
	hash := sha256.Sum256(combined)
	return hash[:20], nil
}

func MarshalMultiPQCPrivateKey(key *MultiPQCPrivateKey) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	type marshalResult struct {
		bytes []byte
		err   error
		index int
	}
	
	keys := []interface{}{key.PrimaryKey, key.SecondaryKey, key.TertiaryKey}
	resultChan := make(chan marshalResult, len(keys))
	var wg sync.WaitGroup
	
	for i, k := range keys {
		wg.Add(1)
		go func(index int, privateKey interface{}) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- marshalResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			bytes, err := MarshalPrivateKey(privateKey)
			resultChan <- marshalResult{bytes: bytes, err: err, index: index}
		}(i, k)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keyData := make([][]byte, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to marshal private key %d: %w", result.index, result.err)
		}
		keyData[result.index] = result.bytes
	}
	
	keyInfo := MultiPQCKeyInfo{
		Algorithms: []string{key.PrimaryAlgorithm, key.SecondaryAlgorithm, key.TertiaryAlgorithm},
		KeyData:    keyData,
		CombinedID: key.CombinedKeyID,
	}
	
	return asn1.Marshal(keyInfo)
}

func MarshalMultiPQCPublicKey(key *MultiPQCPublicKey) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	type marshalResult struct {
		bytes []byte
		err   error
		index int
	}
	
	keys := []interface{}{key.PrimaryKey, key.SecondaryKey, key.TertiaryKey}
	resultChan := make(chan marshalResult, len(keys))
	var wg sync.WaitGroup
	
	for i, k := range keys {
		wg.Add(1)
		go func(index int, publicKey interface{}) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- marshalResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			bytes, err := MarshalPublicKey(publicKey)
			resultChan <- marshalResult{bytes: bytes, err: err, index: index}
		}(i, k)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keyData := make([][]byte, len(keys))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to marshal public key %d: %w", result.index, result.err)
		}
		keyData[result.index] = result.bytes
	}
	
	keyInfo := MultiPQCKeyInfo{
		Algorithms: []string{key.PrimaryAlgorithm, key.SecondaryAlgorithm, key.TertiaryAlgorithm},
		KeyData:    keyData,
		CombinedID: key.CombinedKeyID,
	}
	
	return asn1.Marshal(keyInfo)
}

func ParseMultiPQCPrivateKey(data []byte) (*MultiPQCPrivateKey, error) {
	var keyInfo MultiPQCKeyInfo
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key info: %w", err)
	}
	
	if len(keyInfo.Algorithms) != 3 || len(keyInfo.KeyData) != 3 {
		return nil, fmt.Errorf("invalid multi-PQC key structure")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	type parseResult struct {
		key   interface{}
		err   error
		index int
	}
	
	resultChan := make(chan parseResult, len(keyInfo.KeyData))
	var wg sync.WaitGroup
	
	for i, keyData := range keyInfo.KeyData {
		wg.Add(1)
		go func(index int, data []byte) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- parseResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			key, err := ParsePrivateKey(data)
			resultChan <- parseResult{key: key, err: err, index: index}
		}(i, keyData)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keys := make([]interface{}, len(keyInfo.KeyData))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to parse private key %d: %w", result.index, result.err)
		}
		keys[result.index] = result.key
	}
	
	return &MultiPQCPrivateKey{
		PrimaryAlgorithm:   keyInfo.Algorithms[0],
		SecondaryAlgorithm: keyInfo.Algorithms[1],
		TertiaryAlgorithm:  keyInfo.Algorithms[2],
		PrimaryKey:         keys[0],
		SecondaryKey:       keys[1],
		TertiaryKey:        keys[2],
		CombinedKeyID:      keyInfo.CombinedID,
	}, nil
}

func ParseMultiPQCPublicKey(data []byte) (*MultiPQCPublicKey, error) {
	var keyInfo MultiPQCKeyInfo
	if _, err := asn1.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key info: %w", err)
	}
	
	if len(keyInfo.Algorithms) != 3 || len(keyInfo.KeyData) != 3 {
		return nil, fmt.Errorf("invalid multi-PQC key structure")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	type parseResult struct {
		key   interface{}
		err   error
		index int
	}
	
	resultChan := make(chan parseResult, len(keyInfo.KeyData))
	var wg sync.WaitGroup
	
	for i, keyData := range keyInfo.KeyData {
		wg.Add(1)
		go func(index int, data []byte) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- parseResult{err: ctx.Err(), index: index}
				return
			default:
			}
			
			key, err := ParsePublicKey(data)
			resultChan <- parseResult{key: key, err: err, index: index}
		}(i, keyData)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	keys := make([]interface{}, len(keyInfo.KeyData))
	
	for result := range resultChan {
		if result.err != nil {
			return nil, fmt.Errorf("failed to parse public key %d: %w", result.index, result.err)
		}
		keys[result.index] = result.key
	}
	
	return &MultiPQCPublicKey{
		PrimaryAlgorithm:   keyInfo.Algorithms[0],
		SecondaryAlgorithm: keyInfo.Algorithms[1],
		TertiaryAlgorithm:  keyInfo.Algorithms[2],
		PrimaryKey:         keys[0],
		SecondaryKey:       keys[1],
		TertiaryKey:        keys[2],
		CombinedKeyID:      keyInfo.CombinedID,
	}, nil
}

func SetDefaultTimeout(timeout time.Duration) {
	defaultTimeout = timeout
}

func GetMaxWorkers() int {
	return runtime.NumCPU()
}