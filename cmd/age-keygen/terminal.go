// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// readMnemonicTerminal owns the terminal mode so cancellation can restore it
// without racing with a reader that is still changing terminal settings.
// The caller must exit on error: an interrupted console read can stay blocked.
func readMnemonicTerminal(in *os.File) (phrase []byte, err error) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)

	fd := int(in.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer func() {
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			phrase, err = nil, restoreErr
		}
	}()

	type result struct {
		phrase string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		terminal := term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{in, os.Stderr}, "")
		phrase, err := terminal.ReadPassword("Enter 24 recovery words (input hidden): ")
		done <- result{phrase, err}
	}()
	select {
	case <-interrupts:
		return nil, errors.New("mnemonic input interrupted")
	case r := <-done:
		return []byte(r.phrase), r.err
	}
}
