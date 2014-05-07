package main

import "testing"
import mathrand "math/rand"

// Test that Int63 returns only non-negative values.
func TestInt63(t *testing.T) {
	rng := mathrand.New(CryptoRandSource)
	for i := 0; i < 128; i++ {
		v := rng.Int63()
		if v < 0 {
			t.Fatalf("%d < 0", v)
		}
	}
}
