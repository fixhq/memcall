//go:build windows

package memcall

import (
	"errors"
	"fmt"
	"os"
	"runtime"
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
	if err := _checkAligned(b); err != nil {
		return err
	}

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
	if err := _checkAligned(b); err != nil {
		return err
	}

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
	// Best-effort restore to read/write so the wipe below can proceed. If this
	// fails we still wipe, unlock, and free rather than leave the secret sitting
	// in mapped memory: a restore failure on an Alloc-returned buffer indicates
	// caller misuse, where the pages are normally still writable. The failure is
	// surfaced once the cleanup has run.
	protectErr := Protect(b, ReadWrite())

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

	// Surface the earlier restore failure, if any, now that cleanup has run.
	return protectErr
}

// Protect modifies the memory protection flags for a specified byte slice.
//
// b must be page-aligned and occupy its own dedicated pages — pass only buffers
// returned by Alloc. Protect acts at page granularity, so changing protection on
// a sub-slice or heap-backed slice also reprotects unrelated data sharing the
// same pages; see the package documentation.
func Protect(b []byte, mpf MemoryProtectionFlag) error {
	if err := _checkAligned(b); err != nil {
		return err
	}

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

var (
	modwer                        = windows.NewLazySystemDLL("wer.dll")
	procWerAddExcludedApplication = modwer.NewProc("WerAddExcludedApplication")
)

// DisableCoreDumps excludes the current executable from Windows Error Reporting
// so that a crash does not generate a WER report or dump for it. It calls
// WerAddExcludedApplication for the current user (which does not require
// administrator rights) and returns an error if the exclusion cannot be
// registered.
//
// This is best-effort hardening, not a complete guarantee. Windows has no
// process-wide equivalent of RLIMIT_CORE, and the exclusion does not stop WER
// LocalDumps configured under HKLM by system policy, which can still write
// full-memory minidumps — including locked, secret-holding buffers. Suppressing
// those remains a system-policy concern outside this library.
func DisableCoreDumps() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("<memcall> could not determine executable path [Err: %s]", err)
	}

	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("<memcall> could not encode executable path [Err: %s]", err)
	}

	// bAllUsers = 0 registers the exclusion for the current user only, so no
	// administrator privileges are needed. The call returns an HRESULT; a
	// negative value indicates failure.
	r, _, _ := procWerAddExcludedApplication.Call(uintptr(unsafe.Pointer(exe16)), 0)
	runtime.KeepAlive(exe16)
	if int32(r) < 0 {
		return fmt.Errorf("<memcall> could not exclude process from Windows Error Reporting [HRESULT: 0x%08x]", uint32(r))
	}

	return nil
}
