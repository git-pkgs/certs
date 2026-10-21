//go:build !unix && !windows

package certs

import (
	"errors"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	return nil, &os.PathError{Op: "open", Path: path, Err: errors.ErrUnsupported}
}
