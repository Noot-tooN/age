// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/bip39"
)

// convertMnemonic maps the complete, standard PQ identity seed to BIP39 entropy.
// There is no password, wallet KDF, extra backup file, or change to key derivation.
// Only PQ identities are supported: the mnemonic itself has no key-type tag.
func convertMnemonic(in io.Reader, importing bool) ([]byte, error) {
	const maxInput = 64 << 10
	data, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil {
		return nil, errors.New("failed to read mnemonic conversion input")
	}
	if len(data) > maxInput {
		return nil, errors.New("mnemonic conversion input exceeds 64 KiB")
	}
	if importing {
		seed, err := bip39.Decode(string(data))
		if err != nil {
			return nil, err
		}
		encoded, err := bech32.Encode("AGE-SECRET-KEY-PQ-", seed[:])
		if err != nil {
			return nil, errors.New("failed to encode PQ identity")
		}
		id, err := age.ParseHybridIdentity(encoded)
		if err != nil {
			return nil, errors.New("failed to restore PQ identity")
		}
		return []byte(id.String() + "\n"), nil
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	// Do not forward parser errors: some parsers include secret input in errors.
	if err != nil {
		return nil, errors.New("invalid identity file for mnemonic export")
	}
	if len(ids) != 1 {
		return nil, errors.New("mnemonic export requires exactly one PQ identity")
	}
	id, ok := ids[0].(*age.HybridIdentity)
	if !ok {
		return nil, errors.New("mnemonic export supports only native PQ identities")
	}
	hrp, seed, err := bech32.Decode(id.String())
	if err != nil || hrp != "AGE-SECRET-KEY-PQ-" || len(seed) != 32 {
		return nil, errors.New("unsupported PQ identity seed format")
	}
	return []byte(bip39.Encode([32]byte(seed)) + "\n"), nil
}
