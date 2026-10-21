//go:build unix

package certs_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/git-pkgs/certs"
)

func TestScanFileRejectsSymlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, pemCertificate(certificate(t, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, fifo} {
		if result, err := certs.ScanFile(context.Background(), path, certs.Options{}); err == nil || result != nil {
			t.Fatalf("accepted %s: %+v, %v", path, result, err)
		}
	}
}
