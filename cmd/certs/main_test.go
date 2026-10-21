package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/certs"
)

func cliFixture(t *testing.T) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CLI test CA"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	entry, err := w.Create("vendor/trust/renamed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(entry, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "example.whl")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLICompressedLimitIsIncomplete(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(bytes.Repeat([]byte("example text\n"), 100)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.gz")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-max-expanded-bytes", "100", path}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result certs.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.SHA256) != 64 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "archive_limit" || stderr.Len() != 0 {
		t.Fatalf("inventory: %+v, stderr: %s", result, stderr.String())
	}
}

func TestCLIArchiveInventory(t *testing.T) {
	path := cliFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result certs.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Path != path || len(result.Certificates) != 1 || result.Certificates[0].Subject != "CN=CLI test CA" {
		t.Fatalf("%+v", result)
	}
	if result.Collections[0].Location[1].Path != "vendor/trust/renamed.txt" {
		t.Fatal(result.Collections)
	}
}

func TestCLIIncompleteAndErrors(t *testing.T) {
	path := cliFixture(t)
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{"-max-file-bytes", "8", path}, 2},
		{[]string{"-max-depth", "-1", path}, 1},
		{[]string{path + ".missing", path}, 1},
		{[]string{}, 1},
		{[]string{"-help"}, 0},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), test.args, &stdout, &stderr); code != test.code {
			t.Fatalf("%v: exit %d, want %d: %s", test.args, code, test.code, stderr.String())
		}
	}
}

func TestCLIInputLimitIsIncomplete(t *testing.T) {
	zipPath := cliFixture(t)
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"cert.pem": data, "cert.gz": compressed.Bytes()} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(zipPath), name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{zipPath, filepath.Join(filepath.Dir(zipPath), "cert.pem"), filepath.Join(filepath.Dir(zipPath), "cert.gz")} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"-max-input-bytes", "100", path}, &stdout, &stderr); code != 2 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		var result certs.Inventory
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.SHA256 != "" || result.Size != 100 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "input_limit" || stderr.Len() != 0 {
			t.Fatalf("input limit: %+v, stderr: %s", result, stderr.String())
		}
	}
}

func TestCLIMultipleFilesAndCustomCatalog(t *testing.T) {
	path := cliFixture(t)
	initial, err := certs.ScanFile(context.Background(), path, certs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := initial.Certificates[0].SHA256
	references := []certs.Reference{{Name: "fixture", Source: "test", SHA256: initial.Collections[0].SHA256, Certificates: []string{fingerprint, fingerprint}}}
	data, err := json.Marshal(references)
	if err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalog, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-catalog", catalog, path, path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	for i := 0; i < 2; i++ {
		var result certs.Inventory
		if err := decoder.Decode(&result); err != nil {
			t.Fatal(err)
		}
		matches := result.Collections[0].Matches
		if len(matches) != 1 || matches[0].Kind != "file" || matches[0].Name != "fixture" {
			t.Fatalf("custom catalog match: %+v", matches)
		}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("trailing output: %v", err)
	}
	if err := os.WriteFile(catalog, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"-catalog", catalog, path}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "JSON array") {
		t.Fatal("invalid catalogue accepted")
	}
}
