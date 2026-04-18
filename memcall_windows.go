//go:build windows

package memcall

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Lock is a wrapper for windows.VirtualLock()
func Lock(b []byte) error {
	if err := windows.VirtualLock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not acquire lock on %p, limit reached? [Err: %s]", _getStartPtr(b), err)
	}

	return nil
}

// Unlock is a wrapper for windows.VirtualUnlock()
func Unlock(b []byte) error {
	if err := windows.VirtualUnlock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not free lock on %p [Err: %s]", _getStartPtr(b), err)
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

	// Unlock the memory to release lock accounting.
	_ = Unlock(b)

	// Wipe the memory region in case of remnant data.
	wipe(b)

	// Free the memory back to the kernel.
	if err := windows.VirtualFree(uintptr(_getStartPtr(b)), uintptr(0), windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("<memcall> could not deallocate %p [Err: %s]", _getStartPtr(b), err)
	}

	return nil
}

// Protect modifies the memory protection flags for a specified byte slice.
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
		return fmt.Errorf("<memcall> could not set %d on %p [Err: %s]", prot, _getStartPtr(b), err)
	}

	return nil
}

// DisableCoreDumps is included for compatibility reasons. On windows it is a no-op function.
func DisableCoreDumps() error { return nil }
