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

package signature

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
)

// PQVerifier implements Verifier using CIRCL for post-quantum algorithms (verification only)
type PQVerifier struct {
	publicKey *pqcrypto.PQPublicKey
}

// PQSignerVerifier implements SignerVerifier using CIRCL for post-quantum algorithms
type PQSignerVerifier struct {
	PQVerifier
	privateKey *pqcrypto.PQPrivateKey
}

// VerifySignature verifies a signature using the post-quantum public key via CIRCL (PQVerifier)
func (pq *PQVerifier) VerifySignature(sig, msg io.Reader, opts ...VerifyOption) error {
	signature, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	message, err := io.ReadAll(msg)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	switch pq.publicKey.Algorithm {
	case pqcrypto.MLDSA65Algorithm:
		if len(pq.publicKey.KeyData) != mldsa65.PublicKeySize {
			return fmt.Errorf("invalid ML-DSA-65 public key size: got %d, expected %d",
				len(pq.publicKey.KeyData), mldsa65.PublicKeySize)
		}

		var pubKey mldsa65.PublicKey
		var keyBuf [mldsa65.PublicKeySize]byte
		copy(keyBuf[:], pq.publicKey.KeyData)
		pubKey.Unpack(&keyBuf)

		if !mldsa65.Verify(&pubKey, message, nil, signature) {
			return errors.New("ML-DSA-65 signature verification failed")
		}
		return nil

	case pqcrypto.MLDSA87Algorithm:
		if len(pq.publicKey.KeyData) != mldsa87.PublicKeySize {
			return fmt.Errorf("invalid ML-DSA-87 public key size: got %d, expected %d",
				len(pq.publicKey.KeyData), mldsa87.PublicKeySize)
		}

		var pubKey mldsa87.PublicKey
		var keyBuf [mldsa87.PublicKeySize]byte
		copy(keyBuf[:], pq.publicKey.KeyData)
		pubKey.Unpack(&keyBuf)

		if !mldsa87.Verify(&pubKey, message, nil, signature) {
			return errors.New("ML-DSA-87 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm for verification: %s", pq.publicKey.Algorithm)
	}
}

// PublicKey returns the post-quantum public key (PQVerifier)
func (pq *PQVerifier) PublicKey(opts ...PublicKeyOption) (crypto.PublicKey, error) {
	return pq.publicKey, nil
}

// SignMessage signs a message using the post-quantum private key via CIRCL
func (pq *PQSignerVerifier) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
	msg, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	switch pq.privateKey.Algorithm {
	case pqcrypto.MLDSA65Algorithm:
		if len(pq.privateKey.KeyData) != mldsa65.PrivateKeySize {
			return nil, fmt.Errorf("invalid ML-DSA-65 private key size: got %d, expected %d",
				len(pq.privateKey.KeyData), mldsa65.PrivateKeySize)
		}

		var privKey mldsa65.PrivateKey
		var keyBuf [mldsa65.PrivateKeySize]byte
		copy(keyBuf[:], pq.privateKey.KeyData)
		privKey.Unpack(&keyBuf)

		sig := make([]byte, mldsa65.SignatureSize)
		err := mldsa65.SignTo(&privKey, msg, nil, false, sig)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 signing failed: %w", err)
		}
		return sig, nil

	case pqcrypto.MLDSA87Algorithm:
		if len(pq.privateKey.KeyData) != mldsa87.PrivateKeySize {
			return nil, fmt.Errorf("invalid ML-DSA-87 private key size: got %d, expected %d",
				len(pq.privateKey.KeyData), mldsa87.PrivateKeySize)
		}

		var privKey mldsa87.PrivateKey
		var keyBuf [mldsa87.PrivateKeySize]byte
		copy(keyBuf[:], pq.privateKey.KeyData)
		privKey.Unpack(&keyBuf)

		sig := make([]byte, mldsa87.SignatureSize)
		err := mldsa87.SignTo(&privKey, msg, nil, false, sig)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-87 signing failed: %w", err)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm for signing: %s", pq.privateKey.Algorithm)
	}
}

func isValidCIRCLAlgorithm(algorithm string) error {
	switch algorithm {
	case pqcrypto.MLDSA65Algorithm, pqcrypto.MLDSA87Algorithm:
		return nil
	default:
		return fmt.Errorf("CIRCL does not support algorithm: %s", algorithm)
	}
}

// isPQPublicKeySupported returns true for supported PQ public keys when CIRCL is compiled in
func isPQPublicKeySupported(key crypto.PublicKey) bool {
	pqKey, ok := key.(*pqcrypto.PQPublicKey)
	if !ok {
		return false
	}

	return isValidCIRCLAlgorithm(pqKey.Algorithm) == nil
}

// isPQPrivateKeySupported returns true for supported PQ private keys when CIRCL is compiled in
func isPQPrivateKeySupported(key crypto.PrivateKey) bool {
	pqKey, ok := key.(*pqcrypto.PQPrivateKey)
	if !ok {
		return false
	}
	return isValidCIRCLAlgorithm(pqKey.Algorithm) == nil
}

// LoadPQSignerVerifier creates a new PQSignerVerifier using CIRCL implementation
func LoadPQSignerVerifier(pub crypto.PublicKey, priv crypto.PrivateKey) (SignerVerifier, error) {
	pqPub, ok := pub.(*pqcrypto.PQPublicKey)
	if !ok {
		return nil, errors.New("public key is not a post-quantum key")
	}

	pqPriv, ok := priv.(*pqcrypto.PQPrivateKey)
	if !ok {
		return nil, errors.New("private key is not a post-quantum key")
	}

	if pqPub.Algorithm != pqPriv.Algorithm {
		return nil, errors.New("public and private key algorithms do not match")
	}

	if err := isValidCIRCLAlgorithm(pqPub.Algorithm); err != nil {
		return nil, err
	}

	return &PQSignerVerifier{
		PQVerifier: PQVerifier{publicKey: pqPub},
		privateKey: pqPriv,
	}, nil
}

// LoadPQVerifier creates a new PQVerifier using CIRCL implementation (verification only)
func LoadPQVerifier(pub crypto.PublicKey) (Verifier, error) {
	pqPub, ok := pub.(*pqcrypto.PQPublicKey)
	if !ok {
		return nil, errors.New("public key is not a post-quantum key")
	}

	if err := isValidCIRCLAlgorithm(pqPub.Algorithm); err != nil {
		return nil, err
	}

	return &PQVerifier{
		publicKey: pqPub,
	}, nil
}
