// Package memcall provides a cross-platform wrapper over some common
// memory-related system calls.
//
// To keep sensitive data out of core dumps, callers should both Lock each
// buffer and call DisableCoreDumps. Per-mapping dump exclusion is not available
// on every platform (notably macOS, NetBSD, Solaris, AIX, and Windows), so Lock
// alone is not sufficient everywhere. On Windows, DisableCoreDumps excludes the
// process from Windows Error Reporting but cannot prevent policy-configured
// full-memory crash dumps. See the README for the per-platform details.
//
// Page granularity: Lock, Unlock, and Protect operate on whole memory pages.
// The kernel rounds the start address down and the end up to page boundaries, so
// these functions must only be given buffers returned by Alloc (or otherwise
// page-aligned buffers that occupy their own dedicated pages). Passing a
// sub-slice or a Go heap-allocated slice lets the call reach unrelated data that
// happens to share a page: Unlock can silently make an adjacent locked secret
// swappable (mlock is not reference-counted), and Protect can strip protection
// from — or fault the runtime on — neighbouring objects.
package memcall

import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

// MemoryProtectionFlag specifies some particular memory protection flag.
type MemoryProtectionFlag struct {
	// NOACCESS  := 1 (0001)
	// READ      := 2 (0010)
	// WRITE     := 4 (0100) // unused
	// READWRITE := 6 (0110)

	flag byte
}

// NoAccess specifies that the memory should be marked unreadable and immutable.
func NoAccess() MemoryProtectionFlag {
	return MemoryProtectionFlag{flag: 1}
}

// ReadOnly specifies that the memory should be marked read-only (immutable).
func ReadOnly() MemoryProtectionFlag {
	return MemoryProtectionFlag{flag: 2}
}

// ReadWrite specifies that the memory should be made readable and writable.
func ReadWrite() MemoryProtectionFlag {
	return MemoryProtectionFlag{flag: 6}
}

// ErrInvalidFlag indicates that a given memory protection flag is undefined.
const ErrInvalidFlag = "<memcall> memory protection flag is undefined"

// ErrUnaligned indicates that a buffer passed to Lock, Unlock, or Protect does
// not start on a page boundary. These calls act at page granularity, so a
// non-page-aligned buffer would reach unrelated data sharing its first page;
// memcall rejects it rather than corrupt a bystander mapping.
const ErrUnaligned = "<memcall> buffer is not page-aligned; pass a buffer returned by Alloc"

// wipe zeroes a byte slice. Declared as a variable so the compiler cannot
// inline the call or prove the stores are dead, preventing the zeroing
// loop from being optimised away.
var wipe = func(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	// Keep the buffer alive past the zeroing loop so a future compiler cannot
	// prove the stores dead and eliminate them.
	runtime.KeepAlive(buf)
}

// Placeholder variable for when we need a valid pointer to zero bytes.
var _zero uintptr

// Auxiliary functions.
func _getStartPtr(b []byte) unsafe.Pointer {
	if len(b) > 0 {
		return unsafe.Pointer(&b[0]) // #nosec G103 -- pointer passed to OS memory syscalls
	}
	return unsafe.Pointer(&_zero) // #nosec G103 -- valid pointer to zero-length region for syscalls
}

// _checkAligned returns ErrUnaligned unless b begins on a page boundary. Lock,
// Unlock, and Protect act at page granularity, so a non-page-aligned buffer
// would let the call reach unrelated data sharing its first page. Empty buffers
// span no pages and are always accepted.
func _checkAligned(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if uintptr(_getStartPtr(b))%uintptr(os.Getpagesize()) != 0 {
		return errors.New(ErrUnaligned)
	}
	return nil
}
