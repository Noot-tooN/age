// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bip39 encodes exactly 256 bits as 24 English BIP39 words, with the
// standard eight-bit checksum. It does not implement BIP39's wallet seed KDF.
package bip39

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"strings"
)

// The canonical BIP39 English word list is distributed under LICENSE.wordlist.
//
//go:embed english.txt
var english string

var words = strings.Fields(english)
var indices = func() map[string]uint16 {
	m := make(map[string]uint16, len(words))
	for i, word := range words {
		m[word] = uint16(i)
	}
	return m
}()

// Encode returns the canonical 24-word representation of entropy.
func Encode(entropy [32]byte) string {
	checksum := sha256.Sum256(entropy[:])
	var data [33]byte
	copy(data[:], entropy[:])
	data[32] = checksum[0]
	var phrase [24]string
	for i := range phrase {
		var index uint16
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			index = index<<1 | uint16((data[bit/8]>>(7-bit%8))&1)
		}
		phrase[i] = words[index]
	}
	return strings.Join(phrase[:], " ")
}

// Decode recovers entropy, checking word count, full words, and checksum.
// Letter case and whitespace are ignored. No secret input is included in errors.
func Decode(phrase string) ([32]byte, error) {
	fields := strings.Fields(strings.ToLower(phrase))
	if len(fields) != 24 {
		return [32]byte{}, errors.New("expected exactly 24 English BIP39 words")
	}
	var data [33]byte
	for i, word := range fields {
		index, ok := indices[word]
		if !ok {
			return [32]byte{}, errors.New("mnemonic contains an unknown word; use full English BIP39 words")
		}
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			data[bit/8] |= byte((index>>(10-j))&1) << (7 - bit%8)
		}
	}
	checksum := sha256.Sum256(data[:32])
	if data[32] != checksum[0] {
		return [32]byte{}, errors.New("invalid mnemonic checksum")
	}
	return [32]byte(data[:32]), nil
}
