//go:build pq_circl || pq_openssl

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
	"testing"

	"github.com/sigstore/sigstore/pkg/pqcrypto"
	"github.com/stretchr/testify/assert"
)

func TestPQKeySupport(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{
			name:      "ML-DSA-65",
			algorithm: "ML-DSA-65",
		},
		{
			name:      "ML-DSA-87",
			algorithm: "ML-DSA-87",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pqPubKey := &pqcrypto.PQPublicKey{
				Algorithm: tt.algorithm,
				OID:       mockOID,
				KeyData:   make([]byte, 32),
				Raw:       make([]byte, 64),
			}

			pqPrivKey := &pqcrypto.PQPrivateKey{
				Algorithm: tt.algorithm,
				OID:       mockOID,
				KeyData:   make([]byte, 64),
				PublicKey: pqPubKey,
			}

			pubSupported := isPQPublicKeySupported(pqPubKey)
			assert.True(t, pubSupported, "Public Key for Algorithm %s not supports", tt.algorithm)
			privSupported := isPQPrivateKeySupported(pqPrivKey)
			assert.True(t, privSupported, "Private Key for Algorithm %s not supports", tt.algorithm)
		})
	}
}
