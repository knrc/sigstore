//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pqcrypto provides low-level post-quantum cryptographic operations
package pqcrypto

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"
)

// Standardized ITU-T X.509 alternative signature OIDs from RFC 3739
var (
	// PQSignatureAlgorithmObjectIdentifier is the standard ITU-T OID for alternative signature algorithm
	// id-ce-altSignatureAlgorithm (2.5.29.73) as defined in ITU-T X.509
	PQSignatureAlgorithmObjectIdentifier = asn1.ObjectIdentifier{2, 5, 29, 73}
	// PQSignatureAlgorithmOID is the string representation of the PQSignatureAlgorithmObjectIdentifier
	PQSignatureAlgorithmOID = PQSignatureAlgorithmObjectIdentifier.String()
	// PQSignatureValueObjectIdentifier is the standard ITU-T OID for alternative signature value
	// id-ce-altSignatureValue (2.5.29.74) as defined in ITU-T X.509
	PQSignatureValueObjectIdentifier = asn1.ObjectIdentifier{2, 5, 29, 74} // id-ce-altSignatureValue
	// PQSignatureValueOID is the string representation of the PQSignatureValueObjectIdentifier
	PQSignatureValueOID = PQSignatureValueObjectIdentifier.String()
)

// HybridCertificate represents an X.509 certificate with both classical and post-quantum signatures
type HybridCertificate struct {
	// Classical certificate (embedded standard X.509)
	*x509.Certificate

	// Post-quantum signature algorithm identifier
	PQSignatureAlgorithm pkix.AlgorithmIdentifier

	// Post-quantum signature value
	PQSignatureValue asn1.BitString

	// Indicates if this certificate contains valid hybrid signatures
	IsHybrid bool

	// Raw DER encoding for re-serialization
	Raw []byte
}

// ParseHybridCertificate parses a DER-encoded certificate and checks for hybrid signature extensions
func ParseHybridCertificate(der []byte) (*HybridCertificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	hybridCert := &HybridCertificate{
		Certificate: cert,
		IsHybrid:    false,
		Raw:         der,
	}

	for _, ext := range cert.Extensions {
		if PQSignatureAlgorithmObjectIdentifier.Equal(ext.Id) {
			var algID pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &algID); err != nil {
				return nil, fmt.Errorf("failed to parse PQ signature algorithm: %w", err)
			}
			hybridCert.PQSignatureAlgorithm = algID
			hybridCert.IsHybrid = true
		} else if PQSignatureValueObjectIdentifier.Equal(ext.Id) {
			var sigValue asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &sigValue); err != nil {
				return nil, fmt.Errorf("failed to parse PQ signature value: %w", err)
			}
			hybridCert.PQSignatureValue = sigValue
		}
	}

	return hybridCert, nil
}

// UnmarshalHybridCertificatesFromPEM extracts hybrid certificates from PEM data
func UnmarshalHybridCertificatesFromPEM(pemBytes []byte) ([]*HybridCertificate, error) {
	result := []*HybridCertificate{}
	remaining := bytes.TrimSpace(pemBytes)

	for len(remaining) > 0 {
		var certDer *pem.Block
		certDer, remaining = pem.Decode(remaining)

		if certDer == nil {
			return nil, errors.New("error during PEM decoding")
		}

		hybridCert, err := ParseHybridCertificate(certDer.Bytes)
		if err != nil {
			return nil, err
		}
		result = append(result, hybridCert)
	}
	return result, nil
}

// LoadHybridCertificatesFromPEM extracts hybrid certificates from io.Reader
func LoadHybridCertificatesFromPEM(pem io.Reader) ([]*HybridCertificate, error) {
	fileBytes, err := io.ReadAll(pem)
	if err != nil {
		return nil, err
	}
	return UnmarshalHybridCertificatesFromPEM(fileBytes)
}

// MarshalHybridCertificateToPEM converts a hybrid certificate to PEM format
func MarshalHybridCertificateToPEM(cert *HybridCertificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("nil hybrid certificate provided")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}

// ValidateHybridCertificate validates both classical and post-quantum signatures
func ValidateHybridCertificate(cert *HybridCertificate) error {
	if cert == nil {
		return errors.New("nil hybrid certificate")
	}

	if err := checkExpiration(cert.Certificate, time.Now()); err != nil {
		return fmt.Errorf("classical certificate validation failed: %w", err)
	}

	if cert.IsHybrid {
		if len(cert.PQSignatureAlgorithm.Algorithm) == 0 {
			return errors.New("hybrid certificate missing post-quantum algorithm identifier")
		}

		if len(cert.PQSignatureValue.Bytes) == 0 {
			return errors.New("hybrid certificate missing post-quantum signature value")
		}

		algOID := cert.PQSignatureAlgorithm.Algorithm
		if !IsPQAlgorithmOID(algOID) {
			return fmt.Errorf("unsupported post-quantum signature algorithm: %s", algOID)
		}
	}

	return nil
}

// CheckHybridCertificateExpiration validates expiration for both standard and hybrid certificates
func CheckHybridCertificateExpiration(cert interface{}, epoch time.Time) error {
	switch c := cert.(type) {
	case *x509.Certificate:
		return checkExpiration(c, epoch)
	case *HybridCertificate:
		return checkExpiration(c.Certificate, epoch)
	default:
		return errors.New("unsupported certificate type")
	}
}

// IsHybridCertificate checks if a standard certificate has hybrid extensions
func IsHybridCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	for _, ext := range cert.Extensions {
		if PQSignatureAlgorithmObjectIdentifier.Equal(ext.Id) || PQSignatureValueObjectIdentifier.Equal(ext.Id) {
			return true
		}
	}
	return false
}

// checkExpiration verifies that epoch is during the validity period of the certificate
func checkExpiration(cert *x509.Certificate, epoch time.Time) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}
	if cert.NotAfter.Before(epoch) {
		return fmt.Errorf("certificate expiration time %s is before %s",
			formatTime(cert.NotAfter), formatTime(epoch))
	}
	if cert.NotBefore.After(epoch) {
		return fmt.Errorf("certificate issued time %s is before %s",
			formatTime(cert.NotBefore), formatTime(epoch))
	}
	return nil
}

// formatTime formats time consistently
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
