//go:build unix

package certs

import (
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	// Nonblocking prevents a replacement FIFO from blocking before f.Stat.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
