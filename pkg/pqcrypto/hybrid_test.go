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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

func TestUnmarshalHybridCertificatesFromPEM(t *testing.T) {
	certs, err := UnmarshalHybridCertificatesFromPEM([]byte{})
	if err != nil {
		t.Errorf("Expected no error for empty input, got: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(certs))
	}

	invalidPEM := []byte("not a pem block")
	_, err = UnmarshalHybridCertificatesFromPEM(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestLoadHybridCertificatesFromPEM(t *testing.T) {
	emptyReader := strings.NewReader("")
	certs, err := LoadHybridCertificatesFromPEM(emptyReader)
	if err != nil {
		t.Errorf("Expected no error for empty reader, got: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(certs))
	}
}

func TestMarshalHybridCertificateToPEM(t *testing.T) {
	_, err := MarshalHybridCertificateToPEM(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}

	hybridCert := &HybridCertificate{
		Certificate: &x509.Certificate{
			Subject: pkix.Name{CommonName: "test"},
		},
		IsHybrid: false,
		Raw:      []byte("test-der-data"),
	}

	pemData, err := MarshalHybridCertificateToPEM(hybridCert)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.Contains(string(pemData), "BEGIN CERTIFICATE") {
		t.Error("PEM data should contain certificate header")
	}
}

func TestValidateHybridCertificate(t *testing.T) {
	x509Cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	tests := []struct {
		name        string
		cert        *HybridCertificate
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			expectError: true,
		},
		{
			name: "valid non-hybrid certificate",
			cert: &HybridCertificate{
				Certificate: x509Cert,
				IsHybrid:    false,
			},
			expectError: false,
		},
		{
			name: "hybrid certificate missing algorithm",
			cert: &HybridCertificate{
				Certificate: x509Cert,
				IsHybrid:    true,
			},
			expectError: true,
		},
		{
			name: "hybrid certificate missing signature value",
			cert: &HybridCertificate{
				Certificate: x509Cert,
				IsHybrid:    true,
				PQSignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: MLDSA65ObjectIdentifier,
				},
			},
			expectError: true,
		},
		{
			name: "valid hybrid certificate",
			cert: &HybridCertificate{
				Certificate: x509Cert,
				IsHybrid:    true,
				PQSignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: MLDSA65ObjectIdentifier,
				},
				PQSignatureValue: asn1.BitString{
					Bytes: []byte("test-signature"),
				},
			},
			expectError: false,
		},
		{
			name: "hybrid certificate with unsupported algorithm",
			cert: &HybridCertificate{
				Certificate: x509Cert,
				IsHybrid:    true,
				PQSignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
				},
				PQSignatureValue: asn1.BitString{
					Bytes: []byte("test-signature"),
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHybridCertificate(tt.cert)
			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCheckHybridCertificateExpiration(t *testing.T) {
	now := time.Now()
	validCert := &x509.Certificate{
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(1 * time.Hour),
	}
	expiredCert := &x509.Certificate{
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-1 * time.Hour),
	}
	futureCert := &x509.Certificate{
		NotBefore: now.Add(1 * time.Hour),
		NotAfter:  now.Add(2 * time.Hour),
	}

	tests := []struct {
		name        string
		cert        interface{}
		epoch       time.Time
		expectError bool
	}{
		{
			name:        "valid x509 certificate",
			cert:        validCert,
			epoch:       now,
			expectError: false,
		},
		{
			name:        "expired x509 certificate",
			cert:        expiredCert,
			epoch:       now,
			expectError: true,
		},
		{
			name:        "future x509 certificate",
			cert:        futureCert,
			epoch:       now,
			expectError: true,
		},
		{
			name: "valid hybrid certificate",
			cert: &HybridCertificate{
				Certificate: validCert,
			},
			epoch:       now,
			expectError: false,
		},
		{
			name: "expired hybrid certificate",
			cert: &HybridCertificate{
				Certificate: expiredCert,
			},
			epoch:       now,
			expectError: true,
		},
		{
			name:        "unsupported certificate type",
			cert:        "not a certificate",
			epoch:       now,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHybridCertificateExpiration(tt.cert, tt.epoch)
			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestIsHybridCertificate(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: false,
		},
		{
			name: "standard certificate",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "test"},
			},
			expected: false,
		},
		{
			name: "certificate with PQ signature algorithm extension",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "test"},
				Extensions: []pkix.Extension{
					{
						Id:    PQSignatureAlgorithmObjectIdentifier,
						Value: []byte("test"),
					},
				},
			},
			expected: true,
		},
		{
			name: "certificate with PQ signature value extension",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "test"},
				Extensions: []pkix.Extension{
					{
						Id:    PQSignatureValueObjectIdentifier,
						Value: []byte("test"),
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHybridCertificate(tt.cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCheckExpiration(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		cert        *x509.Certificate
		epoch       time.Time
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			epoch:       now,
			expectError: true,
		},
		{
			name: "valid certificate",
			cert: &x509.Certificate{
				NotBefore: now.Add(-1 * time.Hour),
				NotAfter:  now.Add(1 * time.Hour),
			},
			epoch:       now,
			expectError: false,
		},
		{
			name: "expired certificate",
			cert: &x509.Certificate{
				NotBefore: now.Add(-2 * time.Hour),
				NotAfter:  now.Add(-1 * time.Hour),
			},
			epoch:       now,
			expectError: true,
		},
		{
			name: "not yet valid certificate",
			cert: &x509.Certificate{
				NotBefore: now.Add(1 * time.Hour),
				NotAfter:  now.Add(2 * time.Hour),
			},
			epoch:       now,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkExpiration(tt.cert, tt.epoch)
			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
