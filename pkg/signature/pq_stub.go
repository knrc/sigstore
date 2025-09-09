//go:build !pq_circl && !pq_openssl

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
	"errors"
)

// LoadPQSignerVerifier returns an error when PQ support is not compiled in
func LoadPQSignerVerifier(_ crypto.PublicKey, _ crypto.PrivateKey) (SignerVerifier, error) {
	return nil, errors.New("post-quantum signature support not compiled in (use build tags: pq_circl or pq_openssl)")
}

// LoadPQVerifier returns an error when PQ support is not compiled in
func LoadPQVerifier(_ crypto.PublicKey) (Verifier, error) {
	return nil, errors.New("post-quantum signature support not compiled in (use build tags: pq_circl or pq_openssl)")
}

// isPQPublicKeySupported returns false when PQ support is not compiled in
func isPQPublicKeySupported(_ crypto.PublicKey) bool {
	return false
}

// isPQPrivateKeySupported returns false when PQ support is not compiled in
func isPQPrivateKeySupported(_ crypto.PrivateKey) bool {
	return false
}
