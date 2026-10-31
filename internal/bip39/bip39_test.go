// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bip39

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOfficialVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Entropy, Mnemonic string }
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 8 {
		t.Fatal("missing official 256-bit vectors")
	}
	for _, v := range vectors {
		t.Run(v.Entropy, func(t *testing.T) {
			raw, err := hex.DecodeString(v.Entropy)
			if err != nil {
				t.Fatal(err)
			}
			entropy := [32]byte(raw)
			if got := Encode(entropy); got != v.Mnemonic {
				t.Fatalf("encoding differs from official vector: %q", got)
			}
			got, err := Decode(v.Mnemonic)
			if err != nil || got != entropy {
				t.Fatalf("decoding differs from official vector: %x, %v", got, err)
			}
			got, err = Decode("\n\t" + strings.ReplaceAll(strings.ToUpper(v.Mnemonic), " ", "\n  ") + "\n")
			if err != nil || got != entropy {
				t.Fatalf("case/whitespace normalization failed: %v", err)
			}
		})
	}
}

func TestInvalidPhrases(t *testing.T) {
	for _, phrase := range []string{
		"", strings.Repeat("abandon ", 12), strings.Repeat("abandon ", 23),
		strings.Repeat("abandon ", 25), strings.Repeat("abandon ", 24),
		strings.Repeat("abandon ", 23) + "notaword", strings.Repeat("abandon ", 23) + "ar",
		strings.Repeat("abandon ", 23) + "art!", strings.Repeat("abandon ", 23) + "аrt",
	} {
		if got, err := Decode(phrase); err == nil || got != ([32]byte{}) {
			t.Errorf("accepted invalid phrase or returned seed on error")
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(Encode([32]byte{}))
	f.Add("")
	f.Add(strings.Repeat("zoo ", 24))
	f.Fuzz(func(t *testing.T, phrase string) {
		seed, err := Decode(phrase)
		if err != nil {
			return
		}
		canonical := strings.Join(strings.Fields(strings.ToLower(phrase)), " ")
		if got := Encode(seed); got != canonical {
			t.Fatal("non-canonical decoding")
		}
	})
}

func TestWordList(t *testing.T) {
	// Pin the complete canonical list, not just words exercised by the vectors.
	digest := sha256.Sum256([]byte(english))
	if hex.EncodeToString(digest[:]) != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatal("BIP39 English word list changed")
	}
	if len(words) != 2048 || len(indices) != 2048 {
		t.Fatal("word list must contain 2048 unique words")
	}
}

func TestEverySeedBit(t *testing.T) {
	for bit := 0; bit < 256; bit++ {
		var seed [32]byte
		seed[bit/8] = 1 << (bit % 8)
		phrase := Encode(seed)
		got, err := Decode(phrase)
		if err != nil || got != seed {
			t.Fatalf("lost bit %d: %v", bit, err)
		}
	}
}
