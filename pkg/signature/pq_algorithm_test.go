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

package signature

import (
	"crypto"
	"encoding/asn1"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5}

func TestGetAlgorithmDetailsForPQ(t *testing.T) {
	tests := []struct {
		name      string
		algorithm v1.PublicKeyDetails
		keyType   PublicKeyType
		hashType  crypto.Hash
		flagValue string
	}{
		{
			name:      "ML-DSA-65",
			algorithm: v1.PublicKeyDetails_ML_DSA_65,
			keyType:   PQ,
			hashType:  crypto.Hash(0),
			flagValue: "ml-dsa-65",
		},
		{
			name:      "ML-DSA-87",
			algorithm: v1.PublicKeyDetails_ML_DSA_87,
			keyType:   PQ,
			hashType:  crypto.Hash(0),
			flagValue: "ml-dsa-87",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details, err := GetAlgorithmDetails(tt.algorithm)
			require.NoError(t, err)

			assert.Equal(t, tt.algorithm, details.GetSignatureAlgorithm())
			assert.Equal(t, tt.keyType, details.GetKeyType())
			assert.Equal(t, tt.hashType, details.GetHashType())

			flag, err := FormatSignatureAlgorithmFlag(tt.algorithm)
			require.NoError(t, err)
			assert.Equal(t, tt.flagValue, flag)

			parsedAlg, err := ParseSignatureAlgorithmFlag(tt.flagValue)
			require.NoError(t, err)
			assert.Equal(t, tt.algorithm, parsedAlg)
		})
	}
}

func TestGetDefaultPublicKeyDetailsForPQ(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		expected  v1.PublicKeyDetails
	}{
		{
			name:      "ML-DSA-65",
			algorithm: "ML-DSA-65",
			expected:  v1.PublicKeyDetails_ML_DSA_65,
		},
		{
			name:      "ML-DSA-87",
			algorithm: "ML-DSA-87",
			expected:  v1.PublicKeyDetails_ML_DSA_87,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pqKey := &pqcrypto.PQPublicKey{
				Algorithm: tt.algorithm,
				OID:       mockOID,
				KeyData:   make([]byte, 32),
				Raw:       make([]byte, 64),
			}

			details, err := GetDefaultPublicKeyDetails(pqKey)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, details)

			algDetails, err := GetDefaultAlgorithmDetails(pqKey)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, algDetails.GetSignatureAlgorithm())
			assert.Equal(t, PQ, algDetails.GetKeyType())
		})
	}
}
