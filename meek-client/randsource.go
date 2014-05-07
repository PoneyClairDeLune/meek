package main

import "crypto/rand"

type _CryptoRandSource bool

func (source _CryptoRandSource) Int63() int64 {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err.Error())
	}
	// Unset the top bit.
	b[0] &= 0x7f
	return (int64(b[0]) << 56) | (int64(b[1]) << 48) | (int64(b[2]) << 40) | (int64(b[3]) << 32) |
		(int64(b[4]) << 24) | (int64(b[5]) << 16) | (int64(b[6]) << 8) | (int64(b[7]))
}

func (source _CryptoRandSource) Seed(seed int64) {
	// Ignored.
}

// CryptoRandSource is a math/rand Source that sources from crypto/rand Read.
// Its Seed method is a no-op.
var CryptoRandSource _CryptoRandSource
