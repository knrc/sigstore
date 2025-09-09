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
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Supported post-quantum algorithm identifiers
const (
	MLDSA65Algorithm      = "ML-DSA-65"
	MLDSA65PublicKeySize  = 1952
	MLDSA65PrivateKeySize = 4032

	MLDSA87Algorithm      = "ML-DSA-87"
	MLDSA87PublicKeySize  = 2592
	MLDSA87PrivateKeySize = 4896
)

// Standard ASN.1 ObjectIdentifiers for ML-DSA algorithms (NIST FIPS 204)
var (
	MLDSA65ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5}
	MLDSA87ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 7}
	MLDSA65OID              = MLDSA65ObjectIdentifier.String()
	MLDSA87OID              = MLDSA87ObjectIdentifier.String()
)

// ErrMissingPostQuantumBuildTag is returned when the build did not include PQC build tags
var ErrMissingPostQuantumBuildTag = errors.New("post-quantum key generation not available (requires build tags: pq_circl or pq_openssl)")

// PQPublicKey represents a post-quantum public key that implements crypto.PublicKey
type PQPublicKey struct {
	Algorithm string
	OID       asn1.ObjectIdentifier
	KeyData   []byte
	Raw       []byte
}

// PQPrivateKey represents a post-quantum private key that implements crypto.PrivateKey
type PQPrivateKey struct {
	Algorithm string
	OID       asn1.ObjectIdentifier
	KeyData   []byte
	PublicKey *PQPublicKey
}

// subjectPublicKeyInfo represents the ASN.1 structure of a SubjectPublicKeyInfo
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// pkcs8PrivateKeyInfo represents the ASN.1 structure of a PKCS#8 PrivateKeyInfo
type pkcs8PrivateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm pkix.AlgorithmIdentifier
	PrivateKey          []byte
	Attributes          []asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey           asn1.BitString  `asn1:"optional,tag:1"`
}

// Public returns the public key associated with this private key
func (k *PQPrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// Equal compares two PQ private keys for equality
func (k *PQPrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PQPrivateKey)
	if !ok {
		return false
	}
	return k.Algorithm == other.Algorithm &&
		k.OID.Equal(other.OID) &&
		bytes.Equal(k.KeyData, other.KeyData)
}

// Equal compares two PQ public keys for equality
func (k *PQPublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PQPublicKey)
	if !ok {
		return false
	}
	return k.Algorithm == other.Algorithm &&
		k.OID.Equal(other.OID) &&
		bytes.Equal(k.KeyData, other.KeyData)
}

// IsPQAlgorithmOID checks if the given OID represents a supported post-quantum algorithm
func IsPQAlgorithmOID(oid asn1.ObjectIdentifier) bool {
	return MLDSA65ObjectIdentifier.Equal(oid) || MLDSA87ObjectIdentifier.Equal(oid)
}

// IdentifyPQAlgorithm maps an OID string to the algorithm name.
func IdentifyPQAlgorithm(oid asn1.ObjectIdentifier) string {
	switch {
	case MLDSA65ObjectIdentifier.Equal(oid):
		return MLDSA65Algorithm
	case MLDSA87ObjectIdentifier.Equal(oid):
		return MLDSA87Algorithm
	default:
		return ""
	}
}

// ParsePKCS8PrivateKey parses DER bytes as a PQ private key
func ParsePKCS8PrivateKey(derBytes []byte) (*PQPrivateKey, error) {
	var privKeyInfo pkcs8PrivateKeyInfo
	_, err := asn1.Unmarshal(derBytes, &privKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("not a valid PKCS#8 structure: %w", err)
	}

	oid := privKeyInfo.PrivateKeyAlgorithm.Algorithm
	if !IsPQAlgorithmOID(oid) {
		return nil, fmt.Errorf("not a post-quantum algorithm: %s", oid)
	}
	algorithm := IdentifyPQAlgorithm(oid)

	if len(privKeyInfo.PublicKey.Bytes) == 0 {
		return nil, fmt.Errorf("post-quantum private key missing public key component")
	}

	pubKey := &PQPublicKey{
		Algorithm: algorithm,
		OID:       privKeyInfo.PrivateKeyAlgorithm.Algorithm,
		KeyData:   privKeyInfo.PublicKey.Bytes,
	}

	return &PQPrivateKey{
		Algorithm: algorithm,
		OID:       privKeyInfo.PrivateKeyAlgorithm.Algorithm,
		KeyData:   privKeyInfo.PrivateKey,
		PublicKey: pubKey,
	}, nil
}

// MarshalPKCS8PrivateKey marshals a PQ private key to PKCS#8 DER format
func MarshalPKCS8PrivateKey(priv *PQPrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil private key")
	}

	privKeyInfo := pkcs8PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: priv.OID,
		},
		PrivateKey: priv.KeyData,
		PublicKey: asn1.BitString{
			Bytes:     priv.PublicKey.KeyData,
			BitLength: len(priv.PublicKey.KeyData) * 8,
		},
	}

	return asn1.Marshal(privKeyInfo)
}

// ExtractPKIXPublicKeyAlgorithmOID extracts the algorithm OID from DER-encoded public key bytes
func ExtractPKIXPublicKeyAlgorithmOID(derBytes []byte) (asn1.ObjectIdentifier, error) {
	var spki subjectPublicKeyInfo
	_, err := asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return nil, err
	}
	return spki.Algorithm.Algorithm, nil
}

// ParsePKIXPublicKey parses DER-encoded bytes into a PQPublicKey
func ParsePKIXPublicKey(derBytes []byte) (*PQPublicKey, error) {
	var spki subjectPublicKeyInfo
	_, err := asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQ public key: %w", err)
	}
	oid := spki.Algorithm.Algorithm
	if !IsPQAlgorithmOID(oid) {
		return nil, fmt.Errorf("unsupported algorithm for PQ public key: %w", err)
	}

	algorithm := IdentifyPQAlgorithm(oid)

	return &PQPublicKey{
		Algorithm: algorithm,
		OID:       spki.Algorithm.Algorithm,
		KeyData:   spki.SubjectPublicKey.Bytes,
		Raw:       derBytes,
	}, nil
}

// MarshalPKIXPublicKey marshals a PQ public key to DER format
func MarshalPKIXPublicKey(pub *PQPublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("nil public key")
	}

	if len(pub.Raw) > 0 {
		return pub.Raw, nil
	}

	pubKeyInfo := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: pub.OID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pub.KeyData,
			BitLength: len(pub.KeyData) * 8,
		},
	}

	return asn1.Marshal(pubKeyInfo)
}
