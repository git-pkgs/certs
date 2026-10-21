//go:build unix

package certs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenNoFollowRejectsSymlinkAndDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openNoFollow(link); err == nil {
		_ = file.Close()
		t.Fatal("followed symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openNoFollow(fifo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Mode().IsRegular() {
		t.Fatalf("FIFO must be rejected by the opened-file check: %+v %v", info, err)
	}
}
