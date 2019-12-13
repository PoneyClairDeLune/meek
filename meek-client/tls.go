package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// makeVerifyPeerPublicKey returns a function, compatible with the tls.Config
// CertifyPeerCertificate, that only checks that the leaf certificate has one of
// a set of set of public keys. Public keys are identified by base64-encoded
// SHA-256 hashes of the Subject Public Key Info, as in HPKP (RFC 7469).
func makeVerifyPeerPublicKey(pubkeyHashes []string) func([][]byte, [][]*x509.Certificate) error {
	// Compare to https://github.com/golang/go/issues/31792.
	return func(certificates [][]byte, _ [][]*x509.Certificate) error {
		if len(certificates) < 1 {
			return errors.New("no certificates presented")
		}
		leaf, err := x509.ParseCertificate(certificates[0])
		if err != nil {
			return err
		}
		rawHash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		hash := base64.StdEncoding.EncodeToString(rawHash[:])
		for _, allowed := range pubkeyHashes {
			if hash == allowed {
				return nil
			}
		}
		return errors.New("unexpected public key hash " + hash)
	}
}
