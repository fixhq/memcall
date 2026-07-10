//go:build openbsd

package memcall

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Lock is a wrapper for mlock(2).
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. These calls act at page granularity, so a sub-slice or a
// heap-backed slice can disturb unrelated data sharing the same pages; see the
// package documentation.
func Lock(b []byte) error {
	if err := _checkAligned(b); err != nil {
		return err
	}

	// Call mlock.
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("<memcall> could not acquire lock on %s, limit reached? [Err: %s]", _addr(b), err)
	}

	return nil
}

// Unlock is a wrapper for munlock(2).
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. Unlock acts at page granularity, so unlocking a buffer that
// shares a page with another locked secret can silently make that secret
// swappable; see the package documentation.
func Unlock(b []byte) error {
	if err := _checkAligned(b); err != nil {
		return err
	}

	if err := unix.Munlock(b); err != nil {
		return fmt.Errorf("<memcall> could not free lock on %s [Err: %s]", _addr(b), err)
	}

	return nil
}

// Alloc allocates a byte slice of length n and returns it.
func Alloc(n int) ([]byte, error) {
	// Allocate the memory.
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON|unix.MAP_CONCEAL)
	if err != nil {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}

	// Wipe it just in case there is some remnant data.
	wipe(b)

	// Return the allocated memory.
	return b, nil
}

// Free deallocates the byte slice specified.
func Free(b []byte) error {
	// Best-effort restore to read/write so the wipe below can proceed. If this
	// fails we still wipe, unlock, and unmap rather than leave the secret sitting
	// in mapped memory: a restore failure on an Alloc-returned buffer indicates
	// caller misuse, where the pages are normally still writable. The failure is
	// surfaced once the cleanup has run.
	protectErr := Protect(b, ReadWrite())

	// Wipe the memory region while it is still locked, closing the window in
	// which a secret could be paged out to swap between the unlock and the wipe.
	wipe(b)

	// Unlock the memory to release mlock accounting. Ignore the error: the
	// buffer may never have been locked, and munmap releases the lock anyway.
	_ = Unlock(b)

	// Free the memory back to the kernel.
	if err := unix.Munmap(b); err != nil {
		return fmt.Errorf("<memcall> could not deallocate %s [Err: %s]", _addr(b), err)
	}

	// Surface the earlier restore failure, if any, now that cleanup has run.
	return protectErr
}

// Protect modifies the protection state for a specified byte slice.
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. Protect acts at page granularity, so changing protection on
// a sub-slice or heap-backed slice also reprotects unrelated data sharing the
// same pages; see the package documentation.
func Protect(b []byte, mpf MemoryProtectionFlag) error {
	if err := _checkAligned(b); err != nil {
		return err
	}

	var prot int
	if mpf.flag == ReadWrite().flag {
		prot = unix.PROT_READ | unix.PROT_WRITE
	} else if mpf.flag == ReadOnly().flag {
		prot = unix.PROT_READ
	} else if mpf.flag == NoAccess().flag {
		prot = unix.PROT_NONE
	} else {
		return errors.New(ErrInvalidFlag)
	}

	// Change the protection value of the byte slice.
	if err := unix.Mprotect(b, prot); err != nil {
		return fmt.Errorf("<memcall> could not set %d on %s [Err: %s]", prot, _addr(b), err)
	}

	return nil
}

// DisableCoreDumps disables core dumps on Unix systems.
func DisableCoreDumps() error {
	// Disable core dumps.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("<memcall> could not set rlimit [Err: %s]", err)
	}

	return nil
}
