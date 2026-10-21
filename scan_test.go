package certs_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/certs"
)

func certificate(t testing.TB, serial int64) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("Inventory test CA %d", serial)},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func sha(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func scan(t testing.TB, name string, data []byte, options certs.Options) *certs.Inventory {
	t.Helper()
	result, err := certs.Scan(context.Background(), name, bytes.NewReader(data), options)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func hasDiagnostic(result *certs.Inventory, code string) bool {
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func TestScanRenamedPEMAndDER(t *testing.T) {
	first, second := certificate(t, 1), certificate(t, 2)
	for _, format := range []string{"pem", "der"} {
		t.Run(format, func(t *testing.T) {
			data := append(bytes.Clone(first), second...)
			if format == "pem" {
				data = append(pemCertificate(first), pemCertificate(second)...)
			}
			result := scan(t, "arbitrary.data", data, certs.Options{})
			if !result.Complete || len(result.Certificates) != 2 || len(result.Collections) != 1 {
				t.Fatalf("%+v", result)
			}
			collection := result.Collections[0]
			if collection.Format != format || collection.SHA256 != sha(data) || result.SHA256 != sha(data) {
				t.Fatalf("%+v", collection)
			}
			if len(collection.Occurrences) != 2 || collection.Occurrences[0].SHA256 != sha(first) {
				t.Fatal(collection.Occurrences)
			}
			if *collection.Occurrences[0].Offset != 0 {
				t.Fatal("wrong first offset")
			}
			if result.Certificates[0].SPKISHA256 != result.Certificates[1].SPKISHA256 {
				t.Fatal("same key must have the same SPKI hash")
			}
			parsed, err := x509.ParseCertificate(first)
			if err != nil {
				t.Fatal(err)
			}
			if result.Certificates[0].SPKISHA256 != sha(parsed.RawSubjectPublicKeyInfo) {
				t.Fatal("SPKI hash is not over original DER")
			}
		})
	}
}

func TestCollectionIdentityIgnoresOrderFormattingAndDuplicates(t *testing.T) {
	a, b := certificate(t, 1), certificate(t, 2)
	first := append(pemCertificate(a), pemCertificate(b)...)
	second := append([]byte("# renamed bundle\r\n"), pemCertificate(b)...)
	second = append(second, pemCertificate(a)...)
	second = append(second, pemCertificate(a)...)
	reference := certs.Reference{Name: "test bundle", Source: "local fixture", SHA256: sha(first), Certificates: []string{sha(a), sha(b)}}
	catalog, err := certs.PrepareCatalog([]certs.Reference{reference})
	if err != nil {
		t.Fatal(err)
	}
	options := certs.Options{Catalog: catalog}
	one := scan(t, "bundle.pem", first, options)
	two := scan(t, "other-name", second, options)
	if one.Collections[0].SetSHA256 != two.Collections[0].SetSHA256 {
		t.Fatal("membership differs")
	}
	if one.Collections[0].SHA256 == two.Collections[0].SHA256 {
		t.Fatal("file hashes should differ")
	}
	if len(two.Certificates) != 2 || len(two.Collections[0].Occurrences) != 3 {
		t.Fatal("duplicates were not retained")
	}
	if one.Collections[0].Matches[0].Kind != "file" || two.Collections[0].Matches[0].Kind != "certificate_set" {
		t.Fatal("incorrect provenance evidence")
	}
}

type member struct {
	name string
	data []byte
}

func zipArchive(t testing.TB, members ...member) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	for _, member := range members {
		file, err := w.Create(member.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func tarArchive(t testing.TB, members ...member) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	for _, member := range members {
		if err := w.WriteHeader(&tar.Header{Name: member.name, Size: int64(len(member.data)), Mode: 0o600}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func gzipData(t testing.TB, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := gzip.NewWriter(&buffer)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestScanNestedArchivesRetainsDuplicatePaths(t *testing.T) {
	der := certificate(t, 1)
	inner := zipArchive(t, member{"../renamed.bin", der}, member{"../renamed.bin", pemCertificate(der)})
	data := gzipData(t, tarArchive(t, member{"lib/roots.jar", inner}, member{"README", []byte("package documentation")}))
	result := scan(t, "published.crate", data, certs.Options{})
	if !result.Complete || len(result.Collections) != 2 || len(result.Certificates) != 1 || result.Files != 3 {
		t.Fatalf("%+v", result)
	}
	for i, collection := range result.Collections {
		want := []certs.Member{{Path: "published.crate"}, {Path: "lib/roots.jar", Entry: 1}, {Path: "../renamed.bin", Entry: i + 1}}
		if !reflect.DeepEqual(collection.Location, want) {
			t.Fatalf("location: %+v", collection.Location)
		}
	}
	if result.SHA256 != sha(data) {
		t.Fatal("root digest must cover compressed bytes")
	}
}

func TestArchiveContentOverridesMisleadingExtension(t *testing.T) {
	data := zipArchive(t, member{"root", certificate(t, 1)})
	result := scan(t, "renamed.tar", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 {
		t.Fatalf("%+v", result)
	}
}

func TestLimitsKeepInventoryAndCoverage(t *testing.T) {
	der := certificate(t, 1)
	bundle := append(pemCertificate(der), pemCertificate(der)...)
	archive := zipArchive(t, member{"one", der}, member{"two", der})
	tests := []struct {
		name    string
		data    []byte
		options certs.Options
		code    string
	}{
		{"file", bundle, certs.Options{MaxFileBytes: 64}, "file_limit"},
		{"certificates", bundle, certs.Options{MaxCertificates: 1}, "certificate_limit"},
		{"entries", archive, certs.Options{MaxEntries: 1}, "archive_limit"},
		{"expanded", archive, certs.Options{MaxExpandedBytes: int64(len(der))}, "archive_limit"},
		{"depth", zipArchive(t, member{"nested.zip", archive}), certs.Options{MaxDepth: 1}, "depth_limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := scan(t, "input", test.data, test.options)
			if result.Complete || !hasDiagnostic(result, test.code) {
				t.Fatalf("%+v", result)
			}
			if result.SHA256 != sha(test.data) {
				t.Fatal("complete input hash should remain available")
			}
		})
	}
}

func TestNestedArchivesShareExpansionBudget(t *testing.T) {
	der := certificate(t, 1)
	inner := zipArchive(t, member{"root", der})
	outer := zipArchive(t, member{"first.zip", inner}, member{"second.zip", inner})
	result := scan(t, "outer", outer, certs.Options{MaxExpandedBytes: int64(len(inner) * 2)})
	if result.Complete || len(result.Collections) != 1 || !hasDiagnostic(result, "archive_limit") {
		t.Fatalf("%+v", result)
	}
}

func TestInputLimitAndCancellation(t *testing.T) {
	data := pemCertificate(certificate(t, 1))
	result, err := certs.Scan(context.Background(), "input", bytes.NewReader(data), certs.Options{MaxInputBytes: 10})
	if err != nil || result.Complete || result.SHA256 != "" || !hasDiagnostic(result, "input_limit") {
		t.Fatalf("%+v %v", result, err)
	}
	result = scan(t, "input", data, certs.Options{MaxInputBytes: int64(len(data))})
	if !result.Complete {
		t.Fatalf("exact limit should succeed: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = certs.Scan(ctx, "input", bytes.NewReader(data), certs.Options{})
	if !errors.Is(err, context.Canceled) || result.Complete {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestArchiveInputLimitOmitsPartialDigest(t *testing.T) {
	data := zipArchive(t, member{"one", certificate(t, 1)}, member{"two", certificate(t, 2)})
	result, err := certs.Scan(context.Background(), "package.whl", bytes.NewReader(data), certs.Options{MaxInputBytes: int64(len(data) - 1)})
	if err != nil || result.Complete || result.SHA256 != "" || !hasDiagnostic(result, "input_limit") {
		t.Fatalf("partial digest: %+v, error %v", result, err)
	}
}

func TestScanFile(t *testing.T) {
	data := pemCertificate(certificate(t, 1))
	path := filepath.Join(t.TempDir(), "renamed")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := certs.ScanFile(context.Background(), path, certs.Options{})
	if err != nil || !result.Complete || len(result.Certificates) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err := certs.ScanFile(context.Background(), filepath.Dir(path), certs.Options{}); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestMalformedPEMDoesNotHideLaterCertificate(t *testing.T) {
	valid := pemCertificate(certificate(t, 1))
	data := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n"), valid...)
	result := scan(t, "bundle", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || !hasDiagnostic(result, "malformed_certificate") {
		t.Fatalf("%+v", result)
	}
	if *result.Collections[0].Occurrences[0].Offset != int64(len(data)-len(valid)) {
		t.Fatal("wrong offset after malformed block")
	}
}

func TestDERPartialAndNativeCoverage(t *testing.T) {
	data := append(certificate(t, 1), []byte("truncated")...)
	result := scan(t, "broken", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 {
		t.Fatalf("%+v", result)
	}
	native := append([]byte{0x7f, 'E', 'L', 'F'}, pemCertificate(certificate(t, 1))...)
	result = scan(t, "module.so", native, certs.Options{})
	if result.Complete || len(result.Certificates) != 0 || !hasDiagnostic(result, "binary_not_scanned") {
		t.Fatalf("%+v", result)
	}
}

func TestNonCertificatePEM(t *testing.T) {
	result := scan(t, "public-key", []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), certs.Options{})
	if !result.Complete || len(result.Collections) != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestSourceMentionsAreNotMalformedCertificates(t *testing.T) {
	for _, data := range []string{
		"start = \"-----BEGIN CERTIFICATE-----\"\n",
		"0 certificates found\n",
		"if line == b\"-----BEGIN CERTIFICATE-----\":\n    pass\n",
	} {
		result := scan(t, "source.py", []byte(data), certs.Options{})
		if !result.Complete || len(result.Collections) != 0 {
			t.Fatalf("%q: %+v", data, result)
		}
	}
}

func TestCommentedPEMIsOutsideCertificateInventory(t *testing.T) {
	pemData := pemCertificate(certificate(t, 1))
	for _, prefix := range []string{"// ", "   * ", "# ", "root = \""} {
		commented := prefix + strings.ReplaceAll(strings.TrimSpace(string(pemData)), "\n", "\n"+prefix) + "\n"
		result := scan(t, "source.rs", []byte(commented), certs.Options{})
		if !result.Complete || len(result.Collections) != 0 || len(result.Diagnostics) != 0 {
			t.Fatalf("comment prefix %q: %+v", prefix, result)
		}
		result = scan(t, "README.md", append([]byte(commented), pemData...), certs.Options{})
		if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 {
			t.Fatalf("standalone PEM after comment %q: %+v", prefix, result)
		}
	}
}

func TestDiagnosticLimit(t *testing.T) {
	data := bytes.Repeat([]byte("-----BEGIN CERTIFICATE-----\nbad!\n-----END CERTIFICATE-----\n"), 10)
	result := scan(t, "bundle", data, certs.Options{MaxDiagnostics: 2})
	if result.Complete || len(result.Diagnostics) != 3 || result.Diagnostics[2].Code != "diagnostic_limit" {
		t.Fatalf("%+v", result)
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, options := range []certs.Options{{MaxDepth: -1}, {MaxFileBytes: math.MaxInt64}} {
		if _, err := certs.Scan(context.Background(), "input", strings.NewReader(""), options); err == nil {
			t.Fatalf("accepted %+v", options)
		}
	}
}

type tinyReader struct{ io.Reader }

func (r tinyReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestChunkBoundaries(t *testing.T) {
	data := zipArchive(t, member{"root.pem", pemCertificate(certificate(t, 1))})
	result, err := certs.Scan(context.Background(), "wheel", tinyReader{bytes.NewReader(data)}, certs.Options{})
	if err != nil || !result.Complete || result.SHA256 != sha(data) || len(result.Certificates) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
}

func FuzzScan(f *testing.F) {
	der := certificate(f, 1)
	f.Add(der)
	legacy, _ := pem.Decode(sourceFixture(f, "ec-acc.pem"))
	f.Add(legacy.Bytes)
	f.Add(pemCertificate(der))
	f.Add(zipArchive(f, member{"root", der}))
	f.Add([]byte{0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		options := certs.Options{MaxInputBytes: 1 << 20, MaxFileBytes: 1 << 16, MaxExpandedBytes: 1 << 20, MaxEntries: 100, MaxCertificates: 100, MaxDepth: 3, Catalog: &certs.PreparedCatalog{}}
		result, _ := certs.Scan(context.Background(), "input", bytes.NewReader(data), options)
		if result == nil {
			t.Fatal("missing inventory")
		}
		if result.Complete && len(result.Diagnostics) != 0 {
			t.Fatal("complete scan has skipped content")
		}
	})
}

func BenchmarkScanBundle(b *testing.B) {
	var data []byte
	for i := int64(0); i < 120; i++ {
		data = append(data, pemCertificate(certificate(b, i+1))...)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		_ = scan(b, "bundle", data, certs.Options{})
	}
}

func BenchmarkScanArchive(b *testing.B) {
	der := certificate(b, 1)
	var members []member
	for i := 0; i < 100; i++ {
		members = append(members, member{fmt.Sprintf("vendor/%d/data", i), bytes.Repeat([]byte("ordinary source code\n"), 512)})
	}
	members = append(members, member{"vendored/roots", pemCertificate(der)})
	data := zipArchive(b, members...)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		_ = scan(b, "package.whl", data, certs.Options{})
	}
}
