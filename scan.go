package certs

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/git-pkgs/archives"
	"github.com/git-pkgs/magic"
)

const (
	DefaultMaxInputBytes    = 512 << 20
	DefaultMaxFileBytes     = 16 << 20
	DefaultMaxExpandedBytes = 1 << 30
	DefaultMaxEntries       = 100_000
	DefaultMaxDepth         = 8
	DefaultMaxCertificates  = 100_000
	DefaultMaxDiagnostics   = 1000
	sniffBytes              = 512
)

var ErrLimit = errors.New("scan resource limit exceeded")

var errExpandedLimit = errors.New("shared archive expanded-byte limit reached")

type scanner struct {
	ctx         context.Context
	options     Options
	result      *Inventory
	identities  map[string]bool
	expanded    int64
	entries     int
	occurrences int
}

// Scan reads one file or archive without closing input. Malformed or skipped
// members produce diagnostics. Input and cancellation errors also return an error.
// SHA256 is populated only when the entire input has been consumed.
func Scan(ctx context.Context, name string, input io.Reader, options Options) (*Inventory, error) {
	options, err := options.defaults()
	if err != nil {
		return nil, err
	}
	result := &Inventory{Path: name, Complete: true, Certificates: []Certificate{}, Collections: []Collection{}, Diagnostics: []Diagnostic{}}
	s := &scanner{ctx: ctx, options: options, result: result, identities: make(map[string]bool)}
	bounded := &inputReader{ctx: ctx, reader: input, remaining: options.MaxInputBytes}
	hash := sha256.New()
	reader := io.TeeReader(bounded, hash)
	location := []Member{{Path: name}}
	err = s.scan(reader, location, 0)
	if err == nil {
		_, err = io.Copy(io.Discard, reader)
	}
	result.Size = bounded.total
	switch {
	case errors.Is(err, ErrLimit):
		s.diagnostic(location, "input_limit", err.Error())
		err = nil
	case err != nil:
		s.diagnostic(location, "input_error", err.Error())
	default:
		result.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	}
	slices.SortFunc(result.Certificates, func(a, b Certificate) int { return strings.Compare(a.SHA256, b.SHA256) })
	return result, err
}

// ScanFile opens a regular local file. It does not follow symlink inputs.
func ScanFile(ctx context.Context, path string, options Options) (*Inventory, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file", path)
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s: file changed while opening", path)
	}
	return Scan(ctx, path, f, options)
}

func (o Options) defaults() (Options, error) {
	if o.MaxFileBytes == math.MaxInt64 {
		return o, errors.New("file byte limit must leave room for an overflow byte")
	}
	if o.MaxInputBytes < 0 || o.MaxFileBytes < 0 || o.MaxExpandedBytes < 0 || o.MaxEntries < 0 || o.MaxDepth < 0 || o.MaxCertificates < 0 || o.MaxDiagnostics < 0 {
		return o, errors.New("scan limits must not be negative")
	}
	if o.MaxInputBytes == 0 {
		o.MaxInputBytes = DefaultMaxInputBytes
	}
	if o.MaxFileBytes == 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	if o.MaxExpandedBytes == 0 {
		o.MaxExpandedBytes = DefaultMaxExpandedBytes
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	if o.MaxDepth == 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxCertificates == 0 {
		o.MaxCertificates = DefaultMaxCertificates
	}
	if o.MaxDiagnostics == 0 {
		o.MaxDiagnostics = DefaultMaxDiagnostics
	}
	if o.Catalog == nil {
		o.Catalog = defaultCatalog()
	}
	return o, nil
}

func (s *scanner) scan(input io.Reader, location []Member, depth int) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(input, sniffBytes)
	prefix, err := reader.Peek(sniffBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	detection := magic.DetectPrefix(prefix)
	format := detection.Format
	if archiveFormat(format) {
		if depth >= s.options.MaxDepth {
			s.diagnostic(location, "depth_limit", "nested archive depth limit reached")
			return nil
		}
		return s.archive(reader, location, format, depth)
	}
	s.result.Files++
	if nativeFormat(format) {
		s.diagnostic(location, "binary_not_scanned", "compiled certificate material is outside this scan")
		return nil
	}
	if ignoredFormat(format) {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(reader, s.options.MaxFileBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > s.options.MaxFileBytes {
		s.diagnostic(location, "file_limit", "file exceeds certificate parsing limit")
		return nil
	}
	if detection.Reason == magic.ReasonNeedMore {
		detection = magic.Detect(data)
	}
	s.parse(data, location, detection)
	return nil
}

func (s *scanner) archive(reader io.Reader, location []Member, format string, depth int) error {
	name := archiveName(location[len(location)-1].Path, format)
	stream, err := archives.OpenStreamContext(s.ctx, name, reader, archives.StreamOptions{
		MaxInputBytes: s.options.MaxInputBytes, MaxEntryBytes: math.MaxInt64,
		MaxExpandedBytes: s.options.MaxExpandedBytes, MaxEntries: s.options.MaxEntries,
	})
	if err != nil {
		_, err = s.archiveFailure(nil, location, "archive_error", err)
		return err
	}
	defer func() { _ = stream.Close() }()
	for ordinal := 0; ; {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		child := location
		if entry != nil {
			ordinal++
			child = append(slices.Clone(location), Member{Path: entry.Path, Entry: ordinal})
		}
		if err != nil {
			if entry != nil && s.skipRejectedEntry(stream) {
				s.diagnostic(child, "archive_limit", err.Error())
				continue
			}
			retry, failure := s.archiveFailure(stream, child, "archive_error", err)
			if !retry {
				return failure
			}
			continue
		}
		if s.entries >= s.options.MaxEntries {
			s.diagnostic(child, "archive_limit", "shared archive entry limit reached")
			return nil
		}
		s.entries++
		if entry.Size > s.options.MaxExpandedBytes-s.expanded {
			s.diagnostic(child, "archive_limit", "entry exceeds remaining shared expanded-byte budget")
			if stream.Skip() == nil {
				continue
			}
			return nil
		}
		s.expanded += max(0, entry.Size)
		if err := s.archiveMember(stream, entry, child, depth); err != nil {
			retry, failure := s.archiveFailure(stream, child, "member_error", err)
			if !retry {
				return failure
			}
		}
	}
}

func (s *scanner) skipRejectedEntry(stream *archives.Stream) bool {
	if s.entries >= s.options.MaxEntries {
		return false
	}
	s.entries++
	return stream.Skip() == nil
}

func (s *scanner) archiveMember(stream *archives.Stream, entry *archives.StreamEntry, location []Member, depth int) error {
	if entry.IsDir {
		return nil
	}
	if entry.IsHardlink || fs.FileMode(entry.Mode)&fs.ModeType != 0 {
		s.diagnostic(location, "link_or_special_file", "archive link or special file was not followed")
		return nil
	}
	var reader io.Reader = stream
	if entry.Size < 0 {
		reader = &expansionReader{scanner: s, reader: stream}
	}
	err := s.scan(reader, location, depth+1)
	if err == nil && entry.Size < 0 {
		_, err = io.Copy(io.Discard, reader)
	}
	return err
}

type expansionReader struct {
	scanner *scanner
	reader  io.Reader
}

func (r *expansionReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.scanner.options.MaxExpandedBytes - r.scanner.expanded
	if remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			return 0, errExpandedLimit
		}
		return 0, err
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.scanner.expanded += int64(n)
	return n, err
}

func archiveLimitError(err error) bool {
	return errors.Is(err, errExpandedLimit) ||
		errors.Is(err, archives.ErrInputLimit) || errors.Is(err, archives.ErrEntryLimit) ||
		errors.Is(err, archives.ErrEntrySizeLimit) || errors.Is(err, archives.ErrDecompressLimit)
}

func (s *scanner) archiveFailure(stream *archives.Stream, location []Member, code string, err error) (bool, error) {
	if canceled := s.ctx.Err(); canceled != nil {
		return false, canceled
	}
	if errors.Is(err, ErrLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, err
	}
	limit := archiveLimitError(err)
	if limit {
		code = "archive_limit"
	}
	s.diagnostic(location, code, err.Error())
	return !limit && stream != nil && stream.Recover() == nil, nil
}

func archiveFormat(format string) bool {
	switch format {
	case magic.FormatZIP, magic.FormatTAR, magic.FormatGZIP, magic.FormatBZIP2, magic.FormatXZ, magic.FormatZstd:
		return true
	default:
		return false
	}
}

func nativeFormat(format string) bool {
	switch format {
	case magic.FormatELF, magic.FormatMachO, magic.FormatPE, magic.FormatWASM, magic.FormatAR:
		return true
	default:
		return false
	}
}

func ignoredFormat(format string) bool {
	switch format {
	case magic.FormatPNG, magic.FormatJPEG, magic.FormatGIF, magic.FormatPDF, magic.FormatJavaClass:
		return true
	default:
		return false
	}
}

func archiveName(name, format string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if (ext == ".gem" && format == magic.FormatTAR) || (ext == ".conda" && format == magic.FormatZIP) {
		return "input" + ext
	}
	return "" // Other containers are opened by content, irrespective of their labels.
}

func (s *scanner) diagnostic(location []Member, code, message string) {
	s.result.Complete = false
	diagnostic := Diagnostic{Location: slices.Clone(location), Code: code, Message: message}
	if len(s.result.Diagnostics) < s.options.MaxDiagnostics {
		s.result.Diagnostics = append(s.result.Diagnostics, diagnostic)
		return
	}
	if len(s.result.Diagnostics) == s.options.MaxDiagnostics {
		s.result.Diagnostics = append(s.result.Diagnostics, Diagnostic{
			Location: []Member{{Path: s.result.Path}}, Code: "diagnostic_limit", Message: "additional diagnostics were omitted",
		})
	}
	if !coverageDiagnostic(code) {
		for i := 0; i < s.options.MaxDiagnostics; i++ {
			if coverageDiagnostic(s.result.Diagnostics[i].Code) {
				s.result.Diagnostics[i] = diagnostic
				return
			}
		}
	}
}

func coverageDiagnostic(code string) bool {
	switch code {
	case "unrecognized_binary", "binary_not_scanned", "unrecognized_asn1", "unsupported_pem", "link_or_special_file":
		return true
	default:
		return false
	}
}

type inputReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
	total     int64
	err       error
}

func (r *inputReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			r.err = ErrLimit
			return 0, r.err
		}
		r.err = err
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.err = err
	r.remaining -= int64(n)
	r.total += int64(n)
	return n, err
}
