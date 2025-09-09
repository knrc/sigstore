//go:build pq_circl

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
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// GeneratePQKey generates a post-quantum keypair using CIRCL
func GeneratePQKey(algorithm string) (*PQPrivateKey, error) {
	var oid asn1.ObjectIdentifier
	var privKeyData, pubKeyData []byte
	var err error

	switch algorithm {
	case MLDSA65Algorithm:
		oid = MLDSA65ObjectIdentifier

		pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ML-DSA-65 keypair: %w", err)
		}

		privKeyData = privKey.Bytes()
		pubKeyData = pubKey.Bytes()
	case MLDSA87Algorithm:
		oid = MLDSA87ObjectIdentifier

		pubKey, privKey, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ML-DSA-87 keypair: %w", err)
		}

		privKeyData = privKey.Bytes()
		pubKeyData = pubKey.Bytes()
	default:
		return nil, fmt.Errorf("unsupported post-quantum algorithm: %s", algorithm)
	}

	pqPubKey := &PQPublicKey{
		Algorithm: algorithm,
		OID:       oid,
		KeyData:   pubKeyData,
	}

	pubKeyInfo := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pubKeyData,
			BitLength: len(pubKeyData) * 8,
		},
	}

	pubKeyDER, err := asn1.Marshal(pubKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pqPubKey.Raw = pubKeyDER

	return &PQPrivateKey{
		Algorithm: algorithm,
		OID:       oid,
		KeyData:   privKeyData,
		PublicKey: pqPubKey,
	}, nil
}
