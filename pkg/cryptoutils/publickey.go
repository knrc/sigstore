//
// Copyright 2021 The Sigstore Authors.
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

package cryptoutils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // nolint:gosec
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/letsencrypt/boulder/goodkey"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
)

const (
	// PublicKeyPEMType is the string "PUBLIC KEY" to be used during PEM encoding and decoding
	PublicKeyPEMType PEMType = "PUBLIC KEY"
	// PKCS1PublicKeyPEMType is the string "RSA PUBLIC KEY" used to parse PKCS#1-encoded public keys
	PKCS1PublicKeyPEMType PEMType = "RSA PUBLIC KEY"
)

// subjectPublicKeyInfo is used to construct a subject key ID.
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// UnmarshalPEMToPublicKey converts a PEM-encoded byte slice into a crypto.PublicKey
func UnmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	derBytes, _ := pem.Decode(pemBytes)
	if derBytes == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBytes.Type {
	case string(PublicKeyPEMType):
		if oid, err := pqcrypto.ExtractPKIXPublicKeyAlgorithmOID(derBytes.Bytes); err == nil {
			if pqcrypto.IsPQAlgorithmOID(oid) {
				return pqcrypto.ParsePKIXPublicKey(derBytes.Bytes)
			}
		}
		return x509.ParsePKIXPublicKey(derBytes.Bytes)
	case string(PKCS1PublicKeyPEMType):
		return x509.ParsePKCS1PublicKey(derBytes.Bytes)
	default:
		return nil, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?",
			derBytes.Type)
	}
}

// UnmarshalDERToPublicKey parses DER-encoded public key bytes and returns a crypto.PublicKey.
// It handles both classical keys (RSA, ECDSA, Ed25519) and post-quantum keys.
func UnmarshalDERToPublicKey(derBytes []byte) (crypto.PublicKey, error) {
	if len(derBytes) == 0 {
		return nil, errors.New("empty DER bytes")
	}

	if oid, err := pqcrypto.ExtractPKIXPublicKeyAlgorithmOID(derBytes); err == nil {
		if pqcrypto.IsPQAlgorithmOID(oid) {
			return pqcrypto.ParsePKIXPublicKey(derBytes)
		}
	}

	return x509.ParsePKIXPublicKey(derBytes)
}

// MarshalPublicKeyToDER converts a crypto.PublicKey into a PKIX, ASN.1 DER byte slice
func MarshalPublicKeyToDER(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty key")
	}

	if pqKey, ok := pub.(*pqcrypto.PQPublicKey); ok {
		return pqcrypto.MarshalPKIXPublicKey(pqKey)
	}

	return x509.MarshalPKIXPublicKey(pub)
}

// MarshalPublicKeyToPEM converts a crypto.PublicKey into a PEM-encoded byte slice
func MarshalPublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	derBytes, err := MarshalPublicKeyToDER(pub)
	if err != nil {
		return nil, err
	}
	return PEMEncode(PublicKeyPEMType, derBytes), nil
}

// SKID generates a 160-bit SHA-1 hash of the value of the BIT STRING
// subjectPublicKey (excluding the tag, length, and number of unused bits).
// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
func SKID(pub crypto.PublicKey) ([]byte, error) {
	derPubBytes, err := MarshalPublicKeyToDER(pub)
	if err != nil {
		return nil, err
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(derPubBytes, &spki); err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes) // nolint:gosec
	return skid[:], nil
}

// EqualKeys compares two public keys. Supports RSA, ECDSA, ED25519, and post-quantum keys.
// If not equal, the error message contains hex-encoded SHA1 hashes of the DER-encoded keys
func EqualKeys(first, second crypto.PublicKey) error {
	switch pub := first.(type) {
	case *rsa.PublicKey:
		if !pub.Equal(second) {
			return errors.New(genErrMsg(first, second, "rsa"))
		}
	case *ecdsa.PublicKey:
		if !pub.Equal(second) {
			return errors.New(genErrMsg(first, second, "ecdsa"))
		}
	case ed25519.PublicKey:
		if !pub.Equal(second) {
			return errors.New(genErrMsg(first, second, "ed25519"))
		}
	case *pqcrypto.PQPublicKey:
		if !pub.Equal(second) {
			return errors.New(genErrMsg(first, second, "post-quantum"))
		}
	default:
		return errors.New("unsupported key type")
	}
	return nil
}

// genErrMsg generates an error message for EqualKeys
func genErrMsg(first, second crypto.PublicKey, keyType string) string {
	msg := fmt.Sprintf("%s public keys are not equal", keyType)
	// Calculate SKID to include in error message
	firstSKID, err := SKID(first)
	if err != nil {
		return msg
	}
	secondSKID, err := SKID(second)
	if err != nil {
		return msg
	}
	return fmt.Sprintf("%s (%s, %s)", msg, hex.EncodeToString(firstSKID), hex.EncodeToString(secondSKID))
}

// ValidatePubKey validates the parameters of an RSA, ECDSA, ED25519, or post-quantum public key.
func ValidatePubKey(pub crypto.PublicKey) error {
	// goodkey policy enforces:
	// * RSA
	//   * Size of key: 2048 <= size <= 4096, size % 8 = 0
	//   * Exponent E = 65537 (Default exponent for OpenSSL and Golang)
	//   * Small primes check for modulus
	//   * Weak keys generated by Infineon hardware (see https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
	//   * Key is easily factored with Fermat's factorization method
	// * EC
	//   * Public key Q is not the identity element (Ø)
	//   * Public key Q's x and y are within [0, p-1]
	//   * Public key Q is on the curve
	//   * Public key Q's order matches the subgroups (nQ = Ø)
	allowedKeys := &goodkey.AllowedKeys{
		RSA2048:   true,
		RSA3072:   true,
		RSA4096:   true,
		ECDSAP256: true,
		ECDSAP384: true,
		ECDSAP521: true,
	}
	cfg := &goodkey.Config{
		FermatRounds: 100,
		AllowedKeys:  allowedKeys,
	}
	p, err := goodkey.NewPolicy(cfg, nil)
	if err != nil {
		// Should not occur, only chances to return errors are if fermat rounds
		// are <0 or when loading blocked/weak keys from disk (not used here)
		return errors.New("unable to initialize key policy")
	}

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		// ctx is unused
		return p.GoodKey(context.Background(), pub)
	case *ecdsa.PublicKey:
		// ctx is unused
		return p.GoodKey(context.Background(), pub)
	case ed25519.PublicKey:
		return validateEd25519Key(pk)
	case *pqcrypto.PQPublicKey:
		return validatePQKey(pk)
	}
	return errors.New("unsupported public key type")
}

// No validations currently, ED25519 supports only one key size.
func validateEd25519Key(_ ed25519.PublicKey) error {
	return nil
}

// validatePQKey validates post-quantum keys
func validatePQKey(pk *pqcrypto.PQPublicKey) error {
	switch pk.Algorithm {
	case pqcrypto.MLDSA65Algorithm, pqcrypto.MLDSA87Algorithm:
		break
	default:
		return fmt.Errorf("unsupported post-quantum algorithm: %s", pk.Algorithm)
	}

	if len(pk.KeyData) == 0 {
		return errors.New("post-quantum key has empty key data")
	}

	switch pk.Algorithm {
	case pqcrypto.MLDSA65Algorithm:
		if len(pk.KeyData) != pqcrypto.MLDSA65PublicKeySize {
			return fmt.Errorf("ML-DSA-65 key data size is invalid: got %d bytes, expected %d", len(pk.KeyData), pqcrypto.MLDSA65PublicKeySize)
		}
	case pqcrypto.MLDSA87Algorithm:
		if len(pk.KeyData) != pqcrypto.MLDSA87PublicKeySize {
			return fmt.Errorf("ML-DSA-87 key data size is invalid: got %d bytes, expected %d", len(pk.KeyData), pqcrypto.MLDSA87PublicKeySize)
		}
	}

	return nil
}
