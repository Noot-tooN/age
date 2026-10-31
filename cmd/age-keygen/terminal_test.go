// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestMnemonicTerminal(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		signal      os.Signal
		success     bool
	}{
		{name: "SIGINT", signal: os.Interrupt},
		{name: "SIGTERM", signal: syscall.SIGTERM},
		{name: "Ctrl-C", input: "\x03"},
		{name: "EOF", input: "\x04"},
		{name: "invalid", input: "PRIVATE_SENTINEL\n"},
		{name: "success", input: mnemonicFixture(t, "pq-mnemonic.txt"), success: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			master, slave := openMnemonicPTY(t)
			original, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dest := filepath.Join(t.TempDir(), "restored-key")
			cmd := exec.CommandContext(ctx, "age-keygen", "-import-mnemonic", "-o", dest)
			cmd.Stdin = slave
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			cmd.WaitDelay = time.Second
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var runErr error
			go func() { runErr = cmd.Wait(); close(done) }()
			t.Cleanup(func() { cancel(); <-done })

			// Synchronize on the real terminal state, not a sleep or prompt output
			// which can occur before echo has been disabled.
			for {
				state, err := term.GetState(int(slave.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(state, original) {
					break
				}
				select {
				case <-done:
					t.Fatalf("exited before reading: %v", runErr)
				case <-ctx.Done():
					t.Fatal("terminal did not enter hidden input mode")
				case <-time.After(time.Millisecond):
				}
			}
			if tt.signal != nil {
				if err := cmd.Process.Signal(tt.signal); err != nil {
					t.Fatal(err)
				}
			} else if _, err := master.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			<-done
			if ctx.Err() != nil {
				t.Fatal("terminal read did not finish")
			}
			if (runErr == nil) != tt.success {
				t.Fatalf("unexpected exit: %v; stderr: %s", runErr, &stderr)
			}
			restored, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored, original) {
				t.Error("terminal settings were not restored")
			}
			if stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte("PRIVATE_SENTINEL")) || bytes.Contains(stderr.Bytes(), []byte(mnemonicFixture(t, "pq-mnemonic.txt"))) {
				t.Error("secret input or identity leaked to output")
			}
			if tt.success {
				got, err := os.ReadFile(dest)
				if err != nil || string(got) != mnemonicFixture(t, "pq-identity.txt") {
					t.Fatal("wrong restored identity")
				}
			} else if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Error("cancellation or invalid input created an output file")
			}
		})
	}
}

func openMnemonicPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	name, err := mnemonicPTYSlave(master)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}
