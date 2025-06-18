package ca

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"quantumca-platform/internal/crypto/pq"
)

var (
	OIDExtensionPQCAlgorithmInfo    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 1}
	OIDExtensionPQCKeyUsage         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 2}
	OIDExtensionPQCMultiSignature   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 3}
	OIDExtensionPQCKeyDerivation    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 4}
	OIDExtensionPQCCertificateType  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 5}
	OIDExtensionPQCAlgorithmParams  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 6}
	OIDExtensionPQCHybridMode       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 7}
	OIDExtensionPQCSecurityLevel    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2, 8}
)

type PQCAlgorithmInfo struct {
	PrimaryAlgorithm   string `asn1:"utf8"`
	SecondaryAlgorithm string `asn1:"optional,utf8"`
	TertiaryAlgorithm  string `asn1:"optional,utf8"`
	SecurityLevel      int
	IsMultiPQC         bool
	IsHybrid           bool
}

type PQCKeyUsage struct {
	DigitalSignature  bool
	KeyEncipherment   bool
	KeyAgreement      bool
	CertSign          bool
	CRLSign           bool
	PostQuantumSafe   bool
	HybridCompatible  bool
	ForwardSecure     bool
}

type PQCMultiSignature struct {
	Algorithms []string `asn1:"sequence"`
	Signatures [][]byte `asn1:"sequence"`
	Combined   []byte
}

type PQCKeyDerivation struct {
	KEMAlgorithm     string `asn1:"utf8"`
	DerivationMethod string `asn1:"utf8"`
	Parameters       []byte `asn1:"optional"`
}

type PQCCertificateType struct {
	Type        string   `asn1:"utf8"`
	Purpose     string   `asn1:"utf8"`
	Constraints []string `asn1:"optional,sequence"`
}

type PQCAlgorithmParams struct {
	Algorithm  string `asn1:"utf8"`
	Parameters []byte `asn1:"optional"`
}

type PQCHybridMode struct {
	ClassicalAlgorithm string `asn1:"utf8"`
	PQCAlgorithm       string `asn1:"utf8"`
	CombinationMethod  string `asn1:"utf8"`
}

type PQCSecurityLevel struct {
	NISTLevel         int    `asn1:"optional"`
	QuantumSecurity   int
	ClassicalSecurity int    `asn1:"optional"`
	Description       string `asn1:"optional,utf8"`
}

func BuildPQCAlgorithmInfoExtension(privateKey interface{}) (ExtensionASN1, error) {
	var info PQCAlgorithmInfo

	switch key := privateKey.(type) {
	case *pq.MultiPQCPrivateKey:
		info = PQCAlgorithmInfo{
			PrimaryAlgorithm:   key.PrimaryAlgorithm,
			SecondaryAlgorithm: key.SecondaryAlgorithm,
			TertiaryAlgorithm:  key.TertiaryAlgorithm,
			SecurityLevel:      256,
			IsMultiPQC:         true,
			IsHybrid:           false,
		}
	default:
		algName, err := pq.GetAlgorithmName(privateKey)
		if err != nil {
			return ExtensionASN1{}, fmt.Errorf("failed to get algorithm name: %w", err)
		}
		secLevel := getSecurityLevelFromAlgorithm(algName)
		info = PQCAlgorithmInfo{
			PrimaryAlgorithm: algName,
			SecurityLevel:    secLevel,
			IsMultiPQC:       false,
			IsHybrid:         false,
		}
	}

	value, err := asn1.Marshal(info)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal PQC algorithm info: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCAlgorithmInfo,
		Value: value,
	}, nil
}

func BuildPQCKeyUsageExtension(isCA bool, isMultiPQC bool) (ExtensionASN1, error) {
	usage := PQCKeyUsage{
		PostQuantumSafe:  true,
		HybridCompatible: false,
		ForwardSecure:    isMultiPQC,
	}

	if isCA {
		usage.DigitalSignature = true
		usage.CertSign = true
		usage.CRLSign = true
	} else {
		usage.DigitalSignature = true
		usage.KeyEncipherment = true
		usage.KeyAgreement = true
	}

	value, err := asn1.Marshal(usage)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal PQC key usage: %w", err)
	}

	return ExtensionASN1{
		Id:       OIDExtensionPQCKeyUsage,
		Critical: false,
		Value:    value,
	}, nil
}

func BuildPQCMultiSignatureExtension(multiKey *pq.MultiPQCPrivateKey) (ExtensionASN1, error) {
	if multiKey == nil {
		return ExtensionASN1{}, fmt.Errorf("multi-PQC key cannot be nil")
	}

	algorithms := []string{
		multiKey.PrimaryAlgorithm,
		multiKey.SecondaryAlgorithm,
		multiKey.TertiaryAlgorithm,
	}

	testMessage := []byte("multi-signature-extension-test")
	signature, err := multiKey.SignMessage(testMessage)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to create test signature: %w", err)
	}

	multiSig := PQCMultiSignature{
		Algorithms: algorithms,
		Signatures: [][]byte{
			signature.PrimarySignature,
			signature.SecondarySignature,
			signature.TertiarySignature,
		},
		Combined: signature.CombinedHash,
	}

	value, err := asn1.Marshal(multiSig)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal multi-signature info: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCMultiSignature,
		Value: value,
	}, nil
}

func BuildPQCSecurityLevelExtension(algorithm string) (ExtensionASN1, error) {
	secLevel := PQCSecurityLevel{
		QuantumSecurity: getQuantumSecurityLevel(algorithm),
		Description:     fmt.Sprintf("Post-quantum security level for %s", algorithm),
	}

	switch algorithm {
	case "dilithium2", "falcon512", "sphincs-sha256-128f", "sphincs-sha256-128s":
		secLevel.NISTLevel = 1
		secLevel.ClassicalSecurity = 128
	case "dilithium3", "sphincs-sha256-192f":
		secLevel.NISTLevel = 3
		secLevel.ClassicalSecurity = 192
	case "dilithium5", "falcon1024", "sphincs-sha256-256f":
		secLevel.NISTLevel = 5
		secLevel.ClassicalSecurity = 256
	case "multi-pqc":
		secLevel.NISTLevel = 5
		secLevel.ClassicalSecurity = 256
		secLevel.QuantumSecurity = 256
		secLevel.Description = "Multi-algorithm post-quantum security"
	}

	value, err := asn1.Marshal(secLevel)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal security level: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCSecurityLevel,
		Value: value,
	}, nil
}

func BuildSubjectKeyIdentifierExtension(publicKey interface{}) (ExtensionASN1, error) {
	pubKeyBytes, err := pq.MarshalPublicKey(publicKey)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	keyID := hash[:20]

	value, err := asn1.Marshal(keyID)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal key identifier: %w", err)
	}

	return ExtensionASN1{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
		Value: value,
	}, nil
}

func BuildAuthorityKeyIdentifierExtension(issuerPublicKey interface{}) (ExtensionASN1, error) {
	pubKeyBytes, err := pq.MarshalPublicKey(issuerPublicKey)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal issuer public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	keyID := hash[:20]

	authKeyID := PQAuthorityKeyIdentifier{
		KeyIdentifier: keyID,
	}

	value, err := asn1.Marshal(authKeyID)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal authority key identifier: %w", err)
	}

	return ExtensionASN1{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
		Value: value,
	}, nil
}

func BuildCRLDistributionPointsExtension(crlURLs []string) (ExtensionASN1, error) {
	if len(crlURLs) == 0 {
		return ExtensionASN1{}, fmt.Errorf("no CRL URLs provided")
	}

	var distPoints []PQCRLDistributionPoint
	for range crlURLs {
		distPoint := PQCRLDistributionPoint{
			DistributionPoint: asn1.ObjectIdentifier{2, 5, 29, 31},
		}
		distPoints = append(distPoints, distPoint)
	}

	value, err := asn1.Marshal(distPoints)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal CRL distribution points: %w", err)
	}

	return ExtensionASN1{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 31},
		Value: value,
	}, nil
}

func BuildAuthorityInfoAccessExtension(ocspURLs []string, caIssuerURLs []string) (ExtensionASN1, error) {
	type AccessDescription struct {
		AccessMethod   asn1.ObjectIdentifier
		AccessLocation PQGeneralName
	}

	var accessDescriptions []AccessDescription

	for _, ocspURL := range ocspURLs {
		accessDescriptions = append(accessDescriptions, AccessDescription{
			AccessMethod: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1},
			AccessLocation: PQGeneralName{
				URI: ocspURL,
			},
		})
	}

	for _, caURL := range caIssuerURLs {
		accessDescriptions = append(accessDescriptions, AccessDescription{
			AccessMethod: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2},
			AccessLocation: PQGeneralName{
				URI: caURL,
			},
		})
	}

	value, err := asn1.Marshal(accessDescriptions)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal authority info access: %w", err)
	}

	return ExtensionASN1{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
		Value: value,
	}, nil
}

func BuildPQCKeyDerivationExtension(kemAlgorithm, derivationMethod string, parameters []byte) (ExtensionASN1, error) {
	keyDeriv := PQCKeyDerivation{
		KEMAlgorithm:     kemAlgorithm,
		DerivationMethod: derivationMethod,
		Parameters:       parameters,
	}

	value, err := asn1.Marshal(keyDeriv)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal key derivation: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCKeyDerivation,
		Value: value,
	}, nil
}

func BuildPQCCertificateTypeExtension(certType, purpose string, constraints []string) (ExtensionASN1, error) {
	certTypeExt := PQCCertificateType{
		Type:        certType,
		Purpose:     purpose,
		Constraints: constraints,
	}

	value, err := asn1.Marshal(certTypeExt)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal certificate type: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCCertificateType,
		Value: value,
	}, nil
}

func BuildPQCAlgorithmParamsExtension(algorithm string, parameters []byte) (ExtensionASN1, error) {
	algParams := PQCAlgorithmParams{
		Algorithm:  algorithm,
		Parameters: parameters,
	}

	value, err := asn1.Marshal(algParams)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal algorithm params: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCAlgorithmParams,
		Value: value,
	}, nil
}

func BuildPQCHybridModeExtension(classicalAlg, pqcAlg, combinationMethod string) (ExtensionASN1, error) {
	hybridMode := PQCHybridMode{
		ClassicalAlgorithm: classicalAlg,
		PQCAlgorithm:       pqcAlg,
		CombinationMethod:  combinationMethod,
	}

	value, err := asn1.Marshal(hybridMode)
	if err != nil {
		return ExtensionASN1{}, fmt.Errorf("failed to marshal hybrid mode: %w", err)
	}

	return ExtensionASN1{
		Id:    OIDExtensionPQCHybridMode,
		Value: value,
	}, nil
}

func getSecurityLevelFromAlgorithm(algorithm string) int {
	switch algorithm {
	case "dilithium2", "falcon512":
		return 128
	case "dilithium3":
		return 192
	case "dilithium5", "falcon1024":
		return 256
	case "sphincs-sha256-128f", "sphincs-sha256-128s":
		return 128
	case "sphincs-sha256-192f":
		return 192
	case "sphincs-sha256-256f":
		return 256
	case "multi-pqc":
		return 256
	default:
		return 128
	}
}

func getQuantumSecurityLevel(algorithm string) int {
	switch algorithm {
	case "dilithium2", "falcon512":
		return 128
	case "dilithium3":
		return 192
	case "dilithium5", "falcon1024":
		return 256
	case "sphincs-sha256-128f", "sphincs-sha256-128s":
		return 128
	case "sphincs-sha256-192f":
		return 192
	case "sphincs-sha256-256f":
		return 256
	case "multi-pqc":
		return 256
	default:
		return 128
	}
}

func ParsePQCExtensions(extensions []ExtensionASN1) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(OIDExtensionPQCAlgorithmInfo):
			var algInfo PQCAlgorithmInfo
			if _, err := asn1.Unmarshal(ext.Value, &algInfo); err == nil {
				result["pqc_algorithm_info"] = algInfo
			}
		case ext.Id.Equal(OIDExtensionPQCKeyUsage):
			var keyUsage PQCKeyUsage
			if _, err := asn1.Unmarshal(ext.Value, &keyUsage); err == nil {
				result["pqc_key_usage"] = keyUsage
			}
		case ext.Id.Equal(OIDExtensionPQCMultiSignature):
			var multiSig PQCMultiSignature
			if _, err := asn1.Unmarshal(ext.Value, &multiSig); err == nil {
				result["pqc_multi_signature"] = multiSig
			}
		case ext.Id.Equal(OIDExtensionPQCSecurityLevel):
			var secLevel PQCSecurityLevel
			if _, err := asn1.Unmarshal(ext.Value, &secLevel); err == nil {
				result["pqc_security_level"] = secLevel
			}
		case ext.Id.Equal(OIDExtensionPQCKeyDerivation):
			var keyDeriv PQCKeyDerivation
			if _, err := asn1.Unmarshal(ext.Value, &keyDeriv); err == nil {
				result["pqc_key_derivation"] = keyDeriv
			}
		case ext.Id.Equal(OIDExtensionPQCCertificateType):
			var certType PQCCertificateType
			if _, err := asn1.Unmarshal(ext.Value, &certType); err == nil {
				result["pqc_certificate_type"] = certType
			}
		case ext.Id.Equal(OIDExtensionPQCAlgorithmParams):
			var algParams PQCAlgorithmParams
			if _, err := asn1.Unmarshal(ext.Value, &algParams); err == nil {
				result["pqc_algorithm_params"] = algParams
			}
		case ext.Id.Equal(OIDExtensionPQCHybridMode):
			var hybridMode PQCHybridMode
			if _, err := asn1.Unmarshal(ext.Value, &hybridMode); err == nil {
				result["pqc_hybrid_mode"] = hybridMode
			}
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}):
			var keyID []byte
			if _, err := asn1.Unmarshal(ext.Value, &keyID); err == nil {
				result["subject_key_identifier"] = keyID
			}
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}):
			var authKeyID PQAuthorityKeyIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &authKeyID); err == nil {
				result["authority_key_identifier"] = authKeyID
			}
		}
	}

	return result, nil
}

func ValidatePQCExtensions(extensions map[string]interface{}) error {
	if algInfo, exists := extensions["pqc_algorithm_info"]; exists {
		if info, ok := algInfo.(PQCAlgorithmInfo); ok {
			if info.SecurityLevel < 128 {
				return fmt.Errorf("insufficient security level: %d", info.SecurityLevel)
			}
		}
	}

	if secLevel, exists := extensions["pqc_security_level"]; exists {
		if level, ok := secLevel.(PQCSecurityLevel); ok {
			if level.QuantumSecurity < 128 {
				return fmt.Errorf("insufficient quantum security level: %d", level.QuantumSecurity)
			}
		}
	}

	if keyUsage, exists := extensions["pqc_key_usage"]; exists {
		if usage, ok := keyUsage.(PQCKeyUsage); ok {
			if !usage.PostQuantumSafe {
				return fmt.Errorf("certificate is not post-quantum safe")
			}
		}
	}

	return nil
}