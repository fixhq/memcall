//go:build !windows && !darwin && !openbsd && !freebsd && !aix && !netbsd && !solaris && !dragonfly

package memcall

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Lock is a wrapper for mlock(2), with extra precautions.
func Lock(b []byte) error {
	// Advise the kernel to exclude this mapping from core dumps. Surface a
	// failure rather than swallowing it, so a caller is never misled into
	// believing dump-exclusion is in effect when it is not.
	if err := unix.Madvise(b, unix.MADV_DONTDUMP); err != nil {
		return fmt.Errorf("<memcall> could not exclude %s from core dumps [Err: %s]", _addr(b), err)
	}

	// Call mlock.
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("<memcall> could not acquire lock on %s, limit reached? [Err: %s]", _addr(b), err)
	}

	return nil
}

// Unlock is a wrapper for munlock(2).
func Unlock(b []byte) error {
	if err := unix.Munlock(b); err != nil {
		return fmt.Errorf("<memcall> could not free lock on %s [Err: %s]", _addr(b), err)
	}

	return nil
}

// Alloc allocates a byte slice of length n and returns it.
func Alloc(n int) ([]byte, error) {
	// Allocate the memory.
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}

	// Exclude the mapping from core dumps at allocation time. Linux mmap has no
	// equivalent flag (unlike MAP_NOCORE/MAP_CONCEAL on the BSDs), so without
	// this a crash before the caller reaches Lock — or a caller that never Locks
	// because mlock limits were exhausted — would leak the buffer into a core
	// file. Lock advises this again as belt-and-braces. Fail loudly rather than
	// hand back a dumpable buffer.
	if err := unix.Madvise(b, unix.MADV_DONTDUMP); err != nil {
		_ = unix.Munmap(b)
		return nil, fmt.Errorf("<memcall> could not exclude %s from core dumps [Err: %s]", _addr(b), err)
	}

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
	// which a secret could be paged out to swap between the unlock and the wipe.
	wipe(b)

	// Unlock the memory to release mlock accounting. Ignore the error: the
	// buffer may never have been locked, and munmap releases the lock anyway.
	_ = Unlock(b)

	// Free the memory back to the kernel.
	if err := unix.Munmap(b); err != nil {
		return fmt.Errorf("<memcall> could not deallocate %s [Err: %s]", _addr(b), err)
	}

	return nil
}

// Protect modifies the protection state for a specified byte slice.
func Protect(b []byte, mpf MemoryProtectionFlag) error {
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
