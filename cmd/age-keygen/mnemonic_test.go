// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func mnemonicFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runMnemonic(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("age-keygen", args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestMnemonicKnownIdentity(t *testing.T) {
	identity := mnemonicFixture(t, "pq-identity.txt")
	phrase := mnemonicFixture(t, "pq-mnemonic.txt")
	for _, tt := range []struct{ mode, input, want string }{
		{"-export-mnemonic", identity, phrase},
		{"-export-mnemonic", "# public test fixture\n\n" + identity, phrase},
		{"-import-mnemonic", phrase, identity},
		{"-import-mnemonic", strings.ToUpper(strings.ReplaceAll(phrase, " ", "\n\t")), identity},
	} {
		out, stderr, err := runMnemonic(t, tt.input, tt.mode)
		if err != nil || out != tt.want || stderr != "" {
			t.Fatalf("%s: output mismatch; err=%v stderr=%q", tt.mode, err, stderr)
		}
	}
	// Recovery is independent of an original identity file: only the paper words
	// and a public, fixed ciphertext created with unmodified upstream age are used.
	restored, stderr, err := runMnemonic(t, phrase, "-import-mnemonic")
	if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	id, err := age.ParseHybridIdentity(strings.TrimSpace(restored))
	if err != nil {
		t.Fatal(err)
	}
	if id.Recipient().String()+"\n" != mnemonicFixture(t, "pq-recipient.txt") {
		t.Fatal("recovered a different public key")
	}
	ciphertext, err := os.Open("testdata/pq-ciphertext.age")
	if err != nil {
		t.Fatal(err)
	}
	defer ciphertext.Close()
	plaintext, err := age.Decrypt(ciphertext, id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plaintext)
	if err != nil || string(got) != "age PQ mnemonic recovery interoperability fixture\n" {
		t.Fatalf("decryption mismatch: %v", err)
	}
}

func TestMnemonicRejectsInvalidInput(t *testing.T) {
	identity := mnemonicFixture(t, "pq-identity.txt")
	phrase := mnemonicFixture(t, "pq-mnemonic.txt")
	classic := "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0\n"
	for _, tt := range []struct {
		name, input string
		args        []string
	}{
		{"empty", "", []string{"-export-mnemonic"}},
		{"multiple", identity + identity, []string{"-export-mnemonic"}},
		{"classic", classic, []string{"-export-mnemonic"}},
		{"malformed", "PRIVATE_SENTINEL", []string{"-export-mnemonic"}},
		{"unknown word", strings.Repeat("abandon ", 23) + "PRIVATE_SENTINEL", []string{"-import-mnemonic"}},
		{"checksum", strings.Repeat("abandon ", 24), []string{"-import-mnemonic"}},
		{"short", strings.Repeat("abandon ", 12), []string{"-import-mnemonic"}},
		{"large", strings.Repeat(" ", 65537) + phrase, []string{"-import-mnemonic"}},
		{"large identity", strings.Repeat("#\n", 32769) + identity, []string{"-export-mnemonic"}},
		{"conflicting modes", phrase, []string{"-import-mnemonic", "-export-mnemonic"}},
		{"recipient mode", phrase, []string{"-import-mnemonic", "-y"}},
		{"pq generation mode", phrase, []string{"-import-mnemonic", "-pq"}},
		{"export generation mode", identity, []string{"-export-mnemonic", "-pq"}},
		{"extra paths", "", []string{"-import-mnemonic", "one", "two"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "key")
			args := append([]string{"-o", dest}, tt.args...)
			out, stderr, err := runMnemonic(t, tt.input, args...)
			if err == nil || out != "" || stderr == "" {
				t.Fatalf("expected failure without output: %v %q %q", err, out, stderr)
			}
			if strings.Contains(stderr, "PRIVATE_SENTINEL") || strings.Contains(stderr, strings.TrimSpace(identity)) {
				t.Fatal("diagnostic leaked secret input")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("invalid input created an output file")
			}
		})
	}
}

func TestMnemonicFiles(t *testing.T) {
	phrase := mnemonicFixture(t, "pq-mnemonic.txt")
	identity := mnemonicFixture(t, "pq-identity.txt")
	for _, mode := range []string{"-import-mnemonic", "-export-mnemonic"} {
		t.Run(mode, func(t *testing.T) {
			input, want := phrase, identity
			if mode == "-export-mnemonic" {
				input, want = identity, phrase
			}
			dir := t.TempDir()
			src, dest := filepath.Join(dir, "input"), filepath.Join(dir, "output")
			if err := os.WriteFile(src, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			out, stderr, err := runMnemonic(t, "", mode, "-o", dest, src)
			if err != nil || out != "" || stderr != "" {
				t.Fatalf("file conversion: %v %s", err, stderr)
			}
			got, err := os.ReadFile(dest)
			if err != nil || string(got) != want {
				t.Fatal("wrong output file")
			}
			info, err := os.Stat(dest)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
				t.Fatal("output is not private")
			}
			if _, _, err := runMnemonic(t, input, mode, "-o", dest); err == nil {
				t.Fatal("overwrote existing output")
			}
			got, _ = os.ReadFile(dest)
			if string(got) != want {
				t.Fatal("existing output changed")
			}
			if _, _, err := runMnemonic(t, "", mode, "-o", filepath.Join(dir, "new"), filepath.Join(dir, "missing")); err == nil {
				t.Fatal("accepted missing input")
			}
			out, stderr, err = runMnemonic(t, input, mode, "-")
			if err != nil || out != want || stderr != "" {
				t.Fatal("explicit stdin failed")
			}
		})
	}
}

func TestMnemonicOutputWriteErrors(t *testing.T) {
	for _, tt := range []struct{ mode, fixture string }{
		{"-import-mnemonic", "pq-mnemonic.txt"}, {"-export-mnemonic", "pq-identity.txt"},
	} {
		cmd := exec.Command("age-keygen", tt.mode)
		cmd.Stdin = strings.NewReader(mnemonicFixture(t, tt.fixture))
		cmd.Stdout = unwritable(t)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), "failed to write output") {
			t.Fatalf("did not propagate output error: %v %s", err, &stderr)
		}
	}
}

type failingMnemonicReader struct{}

func (failingMnemonicReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_SENTINEL") }

func TestMnemonicReadError(t *testing.T) {
	for _, importing := range []bool{true, false} {
		out, err := convertMnemonic(failingMnemonicReader{}, importing)
		if err == nil || len(out) != 0 || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
			t.Fatal("input error was lost or exposed")
		}
	}
}
