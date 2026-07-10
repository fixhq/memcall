//go:build windows

package memcall

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Lock is a wrapper for windows.VirtualLock()
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. These calls act at page granularity, so a sub-slice or a
// heap-backed slice can disturb unrelated data sharing the same pages; see the
// package documentation.
func Lock(b []byte) error {
	if err := windows.VirtualLock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not acquire lock on %s, limit reached? [Err: %s]", _addr(b), err)
	}

	return nil
}

// Unlock is a wrapper for windows.VirtualUnlock()
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. Unlock acts at page granularity, so unlocking a buffer that
// shares a page with another locked secret can silently make that secret
// swappable; see the package documentation.
func Unlock(b []byte) error {
	if err := windows.VirtualUnlock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not free lock on %s [Err: %s]", _addr(b), err)
	}

	return nil
}

// Alloc allocates a byte slice of length n and returns it.
func Alloc(n int) ([]byte, error) {
	// Allocate the memory.
	ptr, err := windows.VirtualAlloc(_zero, uintptr(n), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}

	// Convert this pointer to a slice.
	b := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n)

	// Wipe it just in case there is some remnant data.
	wipe(b)

	// Return the allocated memory.
	return b, nil
}

// Free deallocates the byte slice specified.
func Free(b []byte) error {
	// Make the memory region readable and writable.
	if err := Protect(b, ReadWrite()); err != nil {
		return err
	}

	// Wipe the memory region while it is still locked, closing the window in
	// which a secret could be paged out to the pagefile between the unlock and
	// the wipe.
	wipe(b)

	// Unlock the memory to release lock accounting. Ignore the error: the
	// buffer may never have been locked, and VirtualFree releases the lock.
	_ = Unlock(b)

	// Free the memory back to the kernel.
	if err := windows.VirtualFree(uintptr(_getStartPtr(b)), uintptr(0), windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("<memcall> could not deallocate %s [Err: %s]", _addr(b), err)
	}

	return nil
}

// Protect modifies the memory protection flags for a specified byte slice.
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. Protect acts at page granularity, so changing protection on
// a sub-slice or heap-backed slice also reprotects unrelated data sharing the
// same pages; see the package documentation.
func Protect(b []byte, mpf MemoryProtectionFlag) error {
	var prot uint32
	if mpf.flag == ReadWrite().flag {
		prot = windows.PAGE_READWRITE
	} else if mpf.flag == ReadOnly().flag {
		prot = windows.PAGE_READONLY
	} else if mpf.flag == NoAccess().flag {
		prot = windows.PAGE_NOACCESS
	} else {
		return errors.New(ErrInvalidFlag)
	}

	var oldProtect uint32
	if err := windows.VirtualProtect(uintptr(_getStartPtr(b)), uintptr(len(b)), prot, &oldProtect); err != nil {
		return fmt.Errorf("<memcall> could not set %d on %s [Err: %s]", prot, _addr(b), err)
	}

	return nil
}

// DisableCoreDumps is a no-op on Windows and always returns nil.
//
// Windows has no process-wide equivalent of RLIMIT_CORE, and memcall cannot
// exclude individual mappings from crash dumps on this platform. In particular,
// Windows Error Reporting (WER) LocalDumps can still write full-memory
// minidumps of a crashing process — including locked, secret-holding buffers —
// to the configured dump directory, and VirtualLock does not exclude pages from
// those dumps.
//
// Suppressing full-memory crash dumps on Windows must therefore be handled
// outside this library, by system policy (for example, disabling or scoping WER
// LocalDumps). Do not treat the nil return here as evidence that dump
// protection is in effect.
func DisableCoreDumps() error { return nil }
