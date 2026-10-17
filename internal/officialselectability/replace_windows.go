//go:build windows

package officialselectability

import (
	"syscall"
	"unsafe"
)

var (
	kernel32Selectability   = syscall.NewLazyDLL("kernel32.dll")
	moveFileExSelectability = kernel32Selectability.NewProc("MoveFileExW")
)

func atomicReplace(oldPath, newPath string) error {
	oldName, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExSelectability.Call(uintptr(unsafe.Pointer(oldName)), uintptr(unsafe.Pointer(newName)), 0x1|0x8)
	if result == 0 {
		return callErr
	}
	return nil
}

func syncDirectory(string) error { return nil }
