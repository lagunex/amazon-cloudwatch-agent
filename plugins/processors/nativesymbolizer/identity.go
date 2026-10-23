// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
)

// htlhashSpan is how many bytes of the head and of the tail of a file the
// htlhash covers.
const htlhashSpan = 4096

// htlhash returns the htlhash of f, as the OTel semantic conventions define
// process.executable.build_id.htlhash, a deterministic build ID for files with
// no GNU build ID:
//
//	Input   = Concat(File[:4096], File[-4096:], BigEndianUInt64(Len(File)))
//	Digest  = SHA256(Input)
//	BuildID = Digest[:16], as a hex string
//
// A file shorter than 8 KiB has some bytes in both the head and the tail, and
// a file shorter than 4 KiB is hashed whole, twice. It returns lowercase hex;
// the processor compares it with the mapping's value case-insensitively.
func htlhash(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := fi.Size()
	span := min(size, htlhashSpan)
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, span)); err != nil {
		return "", err
	}
	if _, err := io.Copy(h, io.NewSectionReader(f, size-span, span)); err != nil {
		return "", err
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(size)) //nolint:gosec // G115: a file size is not negative
	h.Write(length[:])
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}
