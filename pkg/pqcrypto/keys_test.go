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

package pqcrypto

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestPQPrivateKeyEqual(t *testing.T) {
	pubKey1 := &PQPublicKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-public-key"),
	}

	pubKey2 := &PQPublicKey{
		Algorithm: MLDSA87Algorithm,
		OID:       MLDSA87ObjectIdentifier,
		KeyData:   []byte("different-public-key"),
	}

	privKey1 := &PQPrivateKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-private-key"),
		PublicKey: pubKey1,
	}

	privKey2 := &PQPrivateKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-private-key"),
		PublicKey: pubKey1,
	}

	privKey3 := &PQPrivateKey{
		Algorithm: MLDSA87Algorithm,
		OID:       MLDSA87ObjectIdentifier,
		KeyData:   []byte("different-private-key"),
		PublicKey: pubKey2,
	}

	tests := []struct {
		name     string
		key1     *PQPrivateKey
		key2     crypto.PrivateKey
		expected bool
	}{
		{
			name:     "equal keys",
			key1:     privKey1,
			key2:     privKey2,
			expected: true,
		},
		{
			name:     "different algorithms",
			key1:     privKey1,
			key2:     privKey3,
			expected: false,
		},
		{
			name:     "different type",
			key1:     privKey1,
			key2:     "not a private key",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key1.Equal(tt.key2)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestPQPublicKeyEqual(t *testing.T) {
	pubKey1 := &PQPublicKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-key-data"),
	}

	pubKey2 := &PQPublicKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-key-data"),
	}

	pubKey3 := &PQPublicKey{
		Algorithm: MLDSA87Algorithm,
		OID:       MLDSA87ObjectIdentifier,
		KeyData:   []byte("different-key-data"),
	}

	tests := []struct {
		name     string
		key1     *PQPublicKey
		key2     crypto.PublicKey
		expected bool
	}{
		{
			name:     "equal keys",
			key1:     pubKey1,
			key2:     pubKey2,
			expected: true,
		},
		{
			name:     "different algorithms",
			key1:     pubKey1,
			key2:     pubKey3,
			expected: false,
		},
		{
			name:     "different type",
			key1:     pubKey1,
			key2:     "not a public key",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key1.Equal(tt.key2)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExtractPKIXPublicKeyAlgorithmOID(t *testing.T) {
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: MLDSA65ObjectIdentifier,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes: []byte("test-key-data"),
		},
	}

	derBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	oid, err := ExtractPKIXPublicKeyAlgorithmOID(derBytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := MLDSA65ObjectIdentifier
	if !expected.Equal(oid) {
		t.Errorf("Expected %s, got %s", expected, oid)
	}

	_, err = ExtractPKIXPublicKeyAlgorithmOID([]byte("invalid der"))
	if err == nil {
		t.Error("Expected error for invalid DER")
	}
}

func TestIsPQAlgorithmOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{
			name:     "ML-DSA-65 OID",
			oid:      MLDSA65ObjectIdentifier,
			expected: true,
		},
		{
			name:     "ML-DSA-87 OID",
			oid:      MLDSA87ObjectIdentifier,
			expected: true,
		},
		{
			name:     "RSA OID",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			expected: false,
		},
		{
			name:     "Unknown OID",
			oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPQAlgorithmOID(tt.oid)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdentifyPQAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{
			name:     "ML-DSA-65 OID",
			oid:      MLDSA65ObjectIdentifier,
			expected: MLDSA65Algorithm,
		},
		{
			name:     "ML-DSA-87 OID",
			oid:      MLDSA87ObjectIdentifier,
			expected: MLDSA87Algorithm,
		},
		{
			name: "Unknown OID",
			oid:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IdentifyPQAlgorithm(tt.oid)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: MLDSA65ObjectIdentifier,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     []byte("test-key-data"),
			BitLength: 8 * len([]byte("test-key-data")),
		},
	}

	derBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	pubKey, err := ParsePKIXPublicKey(derBytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if pubKey.Algorithm != MLDSA65Algorithm {
		t.Errorf("Expected algorithm %s, got %s", MLDSA65Algorithm, pubKey.Algorithm)
	}

	if !pubKey.OID.Equal(MLDSA65ObjectIdentifier) {
		t.Errorf("Expected OID %v, got %v", MLDSA65ObjectIdentifier, pubKey.OID)
	}

	_, err = ParsePKIXPublicKey([]byte("invalid der"))
	if err == nil {
		t.Error("Expected error for invalid DER")
	}
}

func TestUnmarshalPQPrivateKey(t *testing.T) {
	pkcs8 := pkcs8PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: MLDSA65ObjectIdentifier,
		},
		PrivateKey: []byte("test-private-key-data"),
		PublicKey: asn1.BitString{
			Bytes:     []byte("test-public-key-data"),
			BitLength: 8 * len([]byte("test-public-key-data")),
		},
	}

	derBytes, err := asn1.Marshal(pkcs8)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8: %v", err)
	}

	privKey, err := ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if privKey.Algorithm != MLDSA65Algorithm {
		t.Errorf("Expected algorithm %s, got %s", MLDSA65Algorithm, privKey.Algorithm)
	}

	if !privKey.OID.Equal(MLDSA65ObjectIdentifier) {
		t.Errorf("Expected OID %v, got %v", MLDSA65ObjectIdentifier, privKey.OID)
	}

	if privKey.PublicKey == nil {
		t.Error("Expected public key to be set")
	}

	_, err = ParsePKCS8PrivateKey([]byte("invalid der"))
	if err == nil {
		t.Error("Expected error for invalid DER")
	}

	rsaPkcs8 := pkcs8PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA
		},
		PrivateKey: []byte("test-private-key-data"),
	}

	rsaDER, err := asn1.Marshal(rsaPkcs8)
	if err != nil {
		t.Fatalf("Failed to marshal RSA PKCS#8: %v", err)
	}

	_, err = ParsePKCS8PrivateKey(rsaDER)
	if err == nil {
		t.Error("Expected error for non-PQ algorithm")
	}

	pkcs8NoPub := pkcs8PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: MLDSA65ObjectIdentifier,
		},
		PrivateKey: []byte("test-private-key-data"),
	}

	derNoPub, err := asn1.Marshal(pkcs8NoPub)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8 without public key: %v", err)
	}

	_, err = ParsePKCS8PrivateKey(derNoPub)
	if err == nil {
		t.Error("Expected error for missing public key")
	}
}

func TestGeneratePQKey(t *testing.T) {
	tests := []struct {
		name                 string
		algorithm            string
		expectError          bool
		expectPublicKeySize  int
		expectPrivateKeySize int
	}{
		{
			name:                 "ML-DSA-65",
			algorithm:            MLDSA65Algorithm,
			expectError:          false,
			expectPublicKeySize:  MLDSA65PublicKeySize,
			expectPrivateKeySize: MLDSA65PrivateKeySize,
		},
		{
			name:                 "ML-DSA-87",
			algorithm:            MLDSA87Algorithm,
			expectError:          false,
			expectPublicKeySize:  MLDSA87PublicKeySize,
			expectPrivateKeySize: MLDSA87PrivateKeySize,
		},
		{
			name:        "Unsupported algorithm",
			algorithm:   "Unsupported-Algorithm",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := GeneratePQKey(tt.algorithm)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				if errors.Is(err, ErrMissingPostQuantumBuildTag) {
					t.Skip("Post-quantum build tags should be defined")
				}
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if privKey.Algorithm != tt.algorithm {
				t.Errorf("Expected algorithm %s, got %s", tt.algorithm, privKey.Algorithm)
			}

			privKeySize := len(privKey.KeyData)
			if privKeySize != tt.expectPrivateKeySize {
				t.Errorf("Expected private key size %d, got %d", tt.expectPrivateKeySize, privKeySize)
			}

			pubKeySize := len(privKey.PublicKey.KeyData)
			if pubKeySize != tt.expectPublicKeySize {
				t.Errorf("Expected public key size %d, got %d", tt.expectPublicKeySize, pubKeySize)
			}

			if privKey.PublicKey == nil {
				t.Error("Expected public key to be set")
			}

			if len(privKey.PublicKey.Raw) == 0 {
				t.Error("Expected public key Raw field to be set")
			}
		})
	}
}

func TestMarshalPQPrivateKeyToDER(t *testing.T) {
	_, err := MarshalPKCS8PrivateKey(nil)
	if err == nil {
		t.Error("Expected error for nil private key")
	}

	privKey, err := GeneratePQKey(MLDSA65Algorithm)
	if err != nil {
		if errors.Is(err, ErrMissingPostQuantumBuildTag) {
			t.Skip("Post-quantum build tags should be defined")
		}
		t.Fatalf("Failed to generate key: %v", err)
	}

	derBytes, err := MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(derBytes) == 0 {
		t.Error("Expected non-empty DER bytes")
	}

	unmarshaled, err := ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal DER: %v", err)
	}

	if !privKey.Equal(unmarshaled) {
		t.Error("Keys should be equal after marshal/unmarshal round trip")
	}
}

func TestMarshalPQPublicKeyToDER(t *testing.T) {
	_, err := MarshalPKIXPublicKey(nil)
	if err == nil {
		t.Error("Expected error for nil public key")
	}

	privKey, err := GeneratePQKey(MLDSA65Algorithm)
	if err != nil {
		if errors.Is(err, ErrMissingPostQuantumBuildTag) {
			t.Skip("Post-quantum build tags should be defined")
		}
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := privKey.PublicKey

	derBytes, err := MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(derBytes) == 0 {
		t.Error("Expected non-empty DER bytes")
	}

	unmarshaled, err := ParsePKIXPublicKey(derBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal DER: %v", err)
	}

	if !pubKey.Equal(unmarshaled) {
		t.Error("Keys should be equal after marshal/unmarshal round trip")
	}

	pubKey2 := &PQPublicKey{
		Algorithm: MLDSA65Algorithm,
		OID:       MLDSA65ObjectIdentifier,
		KeyData:   []byte("test-key-data"),
		Raw:       []byte("existing-raw-data"),
	}

	derBytes2, err := MarshalPKIXPublicKey(pubKey2)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if string(derBytes2) != "existing-raw-data" {
		t.Error("Should return existing Raw data when present")
	}
}
