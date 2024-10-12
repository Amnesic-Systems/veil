package system

import (
	"log"
	"syscall"
)

func HasSecureKernelVersion() bool {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		log.Printf("Error calling uname system call: %v", err)
		return false
	}
	return hasSecureKernelVersion(uname)
}

func hasSecureKernelVersion(uname syscall.Utsname) bool {
	// Store major, minor, and patch version in an array.
	var version [3]int
	var digit, offset int
	// Parse the kernel version, which is a character array of the form
	// "5.17.12".
	for _, char := range uname.Release {
		if '0' <= char && char <= '9' {
			digit = digit*10 + int(char-'0')
		} else {
			version[offset] = digit
			digit = 0
			offset++
			if offset > len(version) {
				break
			}
		}
	}

	// We are looking for kernel version 5.17.12 or later.
	minVersion := [3]int{5, 17, 12}
	for i := range version {
		if version[i] < minVersion[i] {
			return false
		}
		if version[i] > minVersion[i] {
			return true
		}
	}
	return true
}
