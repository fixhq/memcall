package memcall

import (
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
	return MemoryProtectionFlag{1}
}

// ReadOnly specifies that the memory should be marked read-only (immutable).
func ReadOnly() MemoryProtectionFlag {
	return MemoryProtectionFlag{2}
}

// ReadWrite specifies that the memory should be made readable and writable.
func ReadWrite() MemoryProtectionFlag {
	return MemoryProtectionFlag{6}
}

// ErrInvalidFlag indicates that a given memory protection flag is undefined.
const ErrInvalidFlag = "<memcall> memory protection flag is undefined"

// wipe zeroes a byte slice. Declared as a variable so the compiler cannot
// inline the call or prove the stores are dead, preventing the zeroing
// loop from being optimised away.
var wipe = func(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
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
