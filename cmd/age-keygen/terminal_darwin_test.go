// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func mnemonicPTYSlave(master *os.File) (string, error) {
	fd := int(master.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		return "", err
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		return "", err
	}
	// Darwin encodes the output buffer length in the ioctl request.
	var name [(unix.TIOCPTYGNAME >> 16) & 0x1fff]byte
	// x/sys exposes no libSystem wrapper for TIOCPTYGNAME. This test-only
	// ioctl follows the PTY setup used by our existing testscript dependency.
	//lint:ignore SA1019 No exported libSystem wrapper exists for this PTY ioctl.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	if errno != 0 {
		return "", errno
	}
	return string(bytes.TrimRight(name[:], "\x00")), nil
}
