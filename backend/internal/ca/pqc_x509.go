package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"quantumca-platform/internal/crypto/pq"
)

func CreatePQCertificate(template, parent *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("template cannot be nil")
	}
	
	if parent == nil {
		parent = template
	}

	tbsCert, err := buildTBSCertificate(template, parent, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build TBS certificate: %w", err)
	}

	tbsBytes, err := asn1.Marshal(tbsCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBS certificate: %w", err)
	}

	signature, err := signTBSCertificate(tbsBytes, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign TBS certificate: %w", err)
	}

	signatureAlgorithm := tbsCert.Signature

	cert := PQCertificateASN1{
		TBSCertificate:     tbsCert,
		SignatureAlgorithm: signatureAlgorithm, 
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	return asn1.Marshal(cert)
}

func buildTBSCertificate(template, parent *x509.Certificate, publicKey interface{}) (TBSCertificateASN1, error) {
	publicKeyInfo, err := buildPublicKeyInfo(publicKey)
	if err != nil {
		return TBSCertificateASN1{}, fmt.Errorf("failed to build public key info: %w", err)
	}

	validity := ValidityASN1{
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
	}

	extensions, err := buildExtensions(template)
	if err != nil {
		return TBSCertificateASN1{}, fmt.Errorf("failed to build extensions: %w", err)
	}

	signatureAlg := AlgorithmIdentifierASN1{
		Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}, 
	}

	tbsCert := TBSCertificateASN1{
		Version:              2,
		SerialNumber:         template.SerialNumber,
		Signature:            signatureAlg,
		Issuer:               convertName(parent.Subject),
		Validity:             validity,
		Subject:              convertName(template.Subject),
		SubjectPublicKeyInfo: publicKeyInfo,
		Extensions:           extensions,
	}

	return tbsCert, nil
}

func buildPublicKeyInfo(publicKey interface{}) (SubjectPublicKeyInfoASN1, error) {
	var algorithm string
	var keyBytes []byte
	var err error

	switch key := publicKey.(type) {
	case *pq.DilithiumPublicKey:
		algorithm = key.Mode
		keyBytes, err = key.Bytes()
	case *pq.FalconPublicKey:
		algorithm = key.Mode
		keyBytes, err = key.Bytes()
	case *pq.SPHINCSPublicKey:
		algorithm = key.Mode
		keyBytes, err = key.Bytes()
	case *pq.MultiPQCPublicKey:
		algorithm = "multi-pqc"
		keyBytes, err = pq.MarshalMultiPQCPublicKey(key)
	default:
		keyBytes, err = pq.MarshalPublicKey(publicKey)
		if err == nil {
			algorithm = "dilithium3"
		}
	}

	if err != nil {
		return SubjectPublicKeyInfoASN1{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	var algorithmOID asn1.ObjectIdentifier
	switch algorithm {
	case "dilithium2":
		algorithmOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	case "dilithium3":
		algorithmOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	case "dilithium5":
		algorithmOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	case "falcon512":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 3}
	case "falcon1024":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 4}
	case "sphincs-sha256-128f":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 1}
	case "sphincs-sha256-128s":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 2}
	case "sphincs-sha256-192f":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 1}
	case "sphincs-sha256-256f":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 1}
	case "multi-pqc":
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
	default:
		algorithmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}
	}

	return SubjectPublicKeyInfoASN1{
		Algorithm: AlgorithmIdentifierASN1{
			Algorithm: algorithmOID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     keyBytes,
			BitLength: len(keyBytes) * 8,
		},
	}, nil
}

func buildExtensions(template *x509.Certificate) ([]ExtensionASN1, error) {
	var extensions []ExtensionASN1

	if template.BasicConstraintsValid {
		basicConstraints := BasicConstraintsASN1{
			IsCA:       template.IsCA,
			MaxPathLen: template.MaxPathLen,
		}
		basicConstraintsBytes, err := asn1.Marshal(basicConstraints)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal basic constraints: %w", err)
		}

		extensions = append(extensions, ExtensionASN1{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Critical: true,
			Value:    basicConstraintsBytes,
		})
	}

	if template.KeyUsage != 0 {
		keyUsage := buildKeyUsage(template.KeyUsage)
		keyUsageBytes, err := asn1.Marshal(keyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal key usage: %w", err)
		}

		extensions = append(extensions, ExtensionASN1{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
			Critical: true,
			Value:    keyUsageBytes,
		})
	}

	if len(template.ExtKeyUsage) > 0 {
		extKeyUsage := buildExtKeyUsage(template.ExtKeyUsage)
		extKeyUsageBytes, err := asn1.Marshal(extKeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal extended key usage: %w", err)
		}

		extensions = append(extensions, ExtensionASN1{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
			Value: extKeyUsageBytes,
		})
	}

	if len(template.DNSNames) > 0 || len(template.IPAddresses) > 0 || len(template.EmailAddresses) > 0 {
		sanBytes, err := buildSubjectAltName(template)
		if err != nil {
			return nil, fmt.Errorf("failed to build subject alt name: %w", err)
		}

		extensions = append(extensions, ExtensionASN1{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		})
	}

	return extensions, nil
}

func buildKeyUsage(keyUsage x509.KeyUsage) asn1.BitString {
	var bits []byte
	bits = append(bits, byte(keyUsage))
	if keyUsage>>8 != 0 {
		bits = append(bits, byte(keyUsage>>8))
	}

	return asn1.BitString{
		Bytes:     bits,
		BitLength: len(bits) * 8,
	}
}

func buildExtKeyUsage(extKeyUsage []x509.ExtKeyUsage) []asn1.ObjectIdentifier {
	var oids []asn1.ObjectIdentifier
	for _, usage := range extKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		case x509.ExtKeyUsageClientAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
		case x509.ExtKeyUsageCodeSigning:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})
		case x509.ExtKeyUsageEmailProtection:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4})
		case x509.ExtKeyUsageTimeStamping:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8})
		case x509.ExtKeyUsageOCSPSigning:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9})
		}
	}
	return oids
}

func buildSubjectAltName(template *x509.Certificate) ([]byte, error) {
	var altNames []SubjectAltNameASN1

	for _, dnsName := range template.DNSNames {
		altNames = append(altNames, SubjectAltNameASN1{
			DNSName: dnsName,
		})
	}

	for _, email := range template.EmailAddresses {
		altNames = append(altNames, SubjectAltNameASN1{
			EmailAddress: email,
		})
	}

	for _, ip := range template.IPAddresses {
		altNames = append(altNames, SubjectAltNameASN1{
			IPAddress: ip,
		})
	}

	return asn1.Marshal(altNames)
}

func signTBSCertificate(tbsBytes []byte, privateKey interface{}) ([]byte, error) {
	return pq.Sign(privateKey, tbsBytes)
}

func getSignatureAlgorithmFromKey(privateKey interface{}) (AlgorithmIdentifierASN1, error) {
	var algorithm string

	switch key := privateKey.(type) {
	case *pq.DilithiumPrivateKey:
		algorithm = key.Mode
	case *pq.FalconPrivateKey:
		algorithm = key.Mode
	case *pq.SPHINCSPrivateKey:
		algorithm = key.Mode
	case *pq.MultiPQCPrivateKey:
		algorithm = "multi-pqc"
	default:
		algorithm = "multi-pqc"
	}

	var oid asn1.ObjectIdentifier
	switch algorithm {
	case "dilithium2":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	case "dilithium3":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	case "dilithium5":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	case "falcon512":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 3}
	case "falcon1024":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 8, 3, 4}
	case "sphincs-sha256-128f":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 1}
	case "sphincs-sha256-128s":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 2}
	case "sphincs-sha256-192f":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 1}
	case "sphincs-sha256-256f":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 1}
	case "multi-pqc":
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
	default:
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
	}

	return AlgorithmIdentifierASN1{
		Algorithm: oid,
	}, nil
}

func convertName(name pkix.Name) NameASN1 {
	var rdns []RelativeDistinguishedNameASN1

	for _, country := range name.Country {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 6},
			Value: country,
		})
	}

	for _, org := range name.Organization {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 10},
			Value: org,
		})
	}

	for _, orgUnit := range name.OrganizationalUnit {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 11},
			Value: orgUnit,
		})
	}

	for _, locality := range name.Locality {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 7},
			Value: locality,
		})
	}

	for _, province := range name.Province {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 8},
			Value: province,
		})
	}

	if name.CommonName != "" {
		rdns = append(rdns, RelativeDistinguishedNameASN1{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
			Value: name.CommonName,
		})
	}

	return NameASN1{RDNSequence: rdns}
}

func ParsePQCertificate(data []byte) (*PQCertificateInfo, error) {
	var cert PQCertificateASN1
	_, err := asn1.Unmarshal(data, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PQ certificate: %w", err)
	}

	return convertASN1ToCertInfo(cert)
}

func convertASN1ToCertInfo(cert PQCertificateASN1) (*PQCertificateInfo, error) {
	subject := convertASN1Name(cert.TBSCertificate.Subject)
	issuer := convertASN1Name(cert.TBSCertificate.Issuer)

	publicKeyAlgorithm, err := getAlgorithmFromOID(cert.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm)
	if err != nil {
		publicKeyAlgorithm = "unknown"
	}

	signatureAlgorithm, err := getAlgorithmFromOID(cert.SignatureAlgorithm.Algorithm)
	if err != nil {
		signatureAlgorithm = "unknown"
	}

	certInfo := &PQCertificateInfo{
		Version:            cert.TBSCertificate.Version,
		SerialNumber:       cert.TBSCertificate.SerialNumber,
		Subject:            subject,
		Issuer:             issuer,
		NotBefore:          cert.TBSCertificate.Validity.NotBefore,
		NotAfter:           cert.TBSCertificate.Validity.NotAfter,
		PublicKeyAlgorithm: publicKeyAlgorithm,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKey:          cert.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.Bytes,
		Signature:          cert.SignatureValue.Bytes,
		Raw:                cert.TBSCertificate,
	}

	extensions, err := parseExtensions(cert.TBSCertificate.Extensions)
	if err == nil {
		certInfo.Extensions = extensions
	}

	return certInfo, nil
}

func convertASN1Name(name NameASN1) pkix.Name {
	var result pkix.Name

	for _, rdn := range name.RDNSequence {
		switch {
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}):
			result.CommonName = rdn.Value
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}):
			result.Country = append(result.Country, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 10}):
			result.Organization = append(result.Organization, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 11}):
			result.OrganizationalUnit = append(result.OrganizationalUnit, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 7}):
			result.Locality = append(result.Locality, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 8}):
			result.Province = append(result.Province, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 9}):
			result.StreetAddress = append(result.StreetAddress, rdn.Value)
		case rdn.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 17}):
			result.PostalCode = append(result.PostalCode, rdn.Value)
		}
	}

	return result
}

func getAlgorithmFromOID(oid asn1.ObjectIdentifier) (string, error) {
	oidMap := map[string]string{
		"2.16.840.1.101.3.4.3.17":      "dilithium2",
		"2.16.840.1.101.3.4.3.18":      "dilithium3",
		"2.16.840.1.101.3.4.3.19":      "dilithium5",
		"1.3.6.1.4.1.2.267.8.3.3":      "falcon512",
		"1.3.6.1.4.1.2.267.8.3.4":      "falcon1024",
		"1.3.6.1.4.1.2.267.12.4.1":     "sphincs-sha256-128f",
		"1.3.6.1.4.1.2.267.12.4.2":     "sphincs-sha256-128s",
		"1.3.6.1.4.1.2.267.12.6.1":     "sphincs-sha256-192f",
		"1.3.6.1.4.1.2.267.12.8.1":     "sphincs-sha256-256f",
		"1.3.6.1.4.1.99999.1.1.1":      "multi-pqc",
		"1.2.840.10045.2.1":            "ecPublicKey",
		"1.2.840.113549.1.1.1":         "rsaEncryption",
	}

	oidStr := oid.String()
	if alg, exists := oidMap[oidStr]; exists {
		return alg, nil
	}

	return "", fmt.Errorf("unknown OID: %s", oidStr)
}

func parseExtensions(extensions []ExtensionASN1) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}):
			var basicConstraints BasicConstraintsASN1
			if _, err := asn1.Unmarshal(ext.Value, &basicConstraints); err == nil {
				result["basic_constraints"] = basicConstraints
			}
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}):
			result["key_usage"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}):
			result["extended_key_usage"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}):
			result["subject_alt_name"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}):
			result["subject_key_identifier"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}):
			result["authority_key_identifier"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}):
			result["crl_distribution_points"] = ext.Value
		case ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}):
			result["authority_info_access"] = ext.Value
		}
	}

	return result, nil
}

func VerifyPQCertificate(certData []byte, issuerPublicKey interface{}) error {
	var cert PQCertificateASN1
	_, err := asn1.Unmarshal(certData, &cert)
	if err != nil {
		return fmt.Errorf("failed to unmarshal certificate: %w", err)
	}

	tbsBytes, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return fmt.Errorf("failed to marshal TBS certificate: %w", err)
	}

	signature := cert.SignatureValue.Bytes

	switch key := issuerPublicKey.(type) {
	case *pq.MultiPQCPublicKey:
		var multiSig pq.MultiPQCSignature
		if _, err := asn1.Unmarshal(signature, &multiSig); err != nil {
			return fmt.Errorf("failed to unmarshal multi-PQC signature: %w", err)
		}
		if !key.Verify(tbsBytes, &multiSig) {
			return fmt.Errorf("multi-PQC signature verification failed")
		}
	default:
		if !pq.Verify(issuerPublicKey, tbsBytes, signature) {
			return fmt.Errorf("signature verification failed")
		}
	}

	now := time.Now()
	if now.Before(cert.TBSCertificate.Validity.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if now.After(cert.TBSCertificate.Validity.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}

func CreatePQCertificateChain(endEntity, intermediate, root []byte) (*PQCertificateChain, error) {
	endEntityCert, err := ParsePQCertificate(endEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse end entity certificate: %w", err)
	}

	var intermediateCerts []*PQCertificateInfo
	if intermediate != nil {
		intermediateCert, err := ParsePQCertificate(intermediate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	var rootCert *PQCertificateInfo
	if root != nil {
		rootCert, err = ParsePQCertificate(root)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate: %w", err)
		}
	}

	return &PQCertificateChain{
		EndEntity:     endEntityCert,
   	Intermediates: intermediateCerts,
   	Root:          rootCert,
   }, nil
}

func ValidatePQCertificateChain(chain *PQCertificateChain) error {
   if chain == nil {
   	return fmt.Errorf("certificate chain cannot be nil")
   }

   if chain.EndEntity == nil {
   	return fmt.Errorf("end entity certificate is required")
   }

   now := time.Now()
   if now.Before(chain.EndEntity.NotBefore) {
   	return fmt.Errorf("end entity certificate is not yet valid")
   }
   if now.After(chain.EndEntity.NotAfter) {
   	return fmt.Errorf("end entity certificate has expired")
   }

   if len(chain.Intermediates) > 0 {
   	for i, intermediate := range chain.Intermediates {
   		if now.Before(intermediate.NotBefore) {
   			return fmt.Errorf("intermediate certificate %d is not yet valid", i)
   		}
   		if now.After(intermediate.NotAfter) {
   			return fmt.Errorf("intermediate certificate %d has expired", i)
   		}
   	}
   }

   if chain.Root != nil {
   	if now.Before(chain.Root.NotBefore) {
   		return fmt.Errorf("root certificate is not yet valid")
   	}
   	if now.After(chain.Root.NotAfter) {
   		return fmt.Errorf("root certificate has expired")
   	}
   }

   return nil
}