package certs_test

import (
	"bytes"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/git-pkgs/certs"
)

func TestExpansionLimitsKeepHash(t *testing.T) {
	payload := pemCertificate(certificate(t, 1))
	for name, data := range map[string][]byte{
		"compressed": gzipData(t, payload),
		"zip":        zipArchive(t, member{"root.pem", payload}),
	} {
		result := scan(t, name, data, certs.Options{MaxExpandedBytes: 100})
		if result.Complete || result.SHA256 != sha(data) || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "archive_limit" {
			t.Fatalf("%s: %+v", name, result)
		}
		if strings.Contains(result.Diagnostics[0].Message, "entry exceeds size") {
			t.Fatal("expansion budget reported as per-entry limit")
		}
	}
}

func TestNestedLimitsKeepLaterMembersWithinBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("text\n"), 1000)
	compressed := gzipData(t, payload)
	certificateData := pemCertificate(certificate(t, 1))
	data := zipArchive(t, member{"large.gz", compressed}, member{"root.pem", certificateData})
	result := scan(t, "package", data, certs.Options{MaxFileBytes: 1000})
	if result.Complete || len(result.Certificates) != 1 || !hasDiagnostic(result, "file_limit") || result.SHA256 != sha(data) {
		t.Fatalf("local file limit: %+v", result)
	}
	result = scan(t, "package", data, certs.Options{MaxExpandedBytes: int64(len(compressed) + 100)})
	if result.Complete || len(result.Certificates) != 0 || !hasDiagnostic(result, "archive_limit") || result.SHA256 != sha(data) {
		t.Fatalf("exhausted global budget: %+v", result)
	}

	inner := zipArchive(t, member{"large.txt", payload})
	outer := zipArchive(t, member{"inner.zip", inner}, member{"root.pem", certificateData})
	limit := int64(len(inner) + len(certificateData))
	result = scan(t, "outer", outer, certs.Options{MaxExpandedBytes: limit})
	if result.Complete || len(result.Certificates) != 1 || !hasDiagnostic(result, "archive_limit") || result.SHA256 != sha(outer) {
		t.Fatalf("nested size rejection with remaining budget: %+v", result)
	}
}

func TestDERJunkProducesOneDiagnostic(t *testing.T) {
	der := certificate(t, 1)
	for name, suffix := range map[string][]byte{
		"padding": bytes.Repeat([]byte{0}, 4096),
		"junk":    {0x30, 0x05, 'a', 'b', 'c', 0xff, 0xff, 0xff},
	} {
		for _, prefix := range [][]byte{nil, der} {
			data := append(bytes.Clone(prefix), suffix...)
			if prefix == nil && name == "padding" {
				continue
			}
			result := scan(t, name, data, certs.Options{})
			if result.Complete || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "unrecognized_asn1" {
				t.Fatalf("%s: %+v", name, result)
			}
			wantCollections := 0
			if prefix != nil {
				wantCollections = 1
			}
			if len(result.Collections) != wantCollections || len(result.Certificates) != wantCollections {
				t.Fatalf("%s collections: %+v", name, result)
			}
		}
	}
	data := append(bytes.Clone(der), bytes.Repeat([]byte{0}, 4096)...)
	data = append(data, certificate(t, 2)...)
	result := scan(t, "padded", data, certs.Options{})
	if len(result.Certificates) != 2 || len(result.Diagnostics) != 1 {
		t.Fatalf("certificate after padding: %+v", result)
	}
}

func TestPEMPlaceholdersAndNonCertificateBlocks(t *testing.T) {
	for _, body := range []string{"...", "…"} {
		data := []byte("Example:\n```\n-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n```\n")
		result := scan(t, "README.md", data, certs.Options{})
		if !result.Complete || len(result.Collections) != 0 {
			t.Fatalf("placeholder: %+v", result)
		}
		data = append(data, pemCertificate(certificate(t, 1))...)
		result = scan(t, "README.md", data, certs.Options{})
		if !result.Complete || len(result.Certificates) != 1 {
			t.Fatalf("real certificate in documentation: %+v", result)
		}
	}
	for _, label := range []string{"EC PARAMETERS", "X509 CRL", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "OPENSSH PRIVATE KEY"} {
		data := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: []byte{1, 2, 3}})
		result := scan(t, "renamed", data, certs.Options{})
		if !result.Complete || len(result.Collections) != 0 {
			t.Fatalf("%s: %+v", label, result)
		}
	}
}

func TestFinalClassificationIncludesBytesAfterPrefix(t *testing.T) {
	data := append(bytes.Repeat([]byte("0"), 1024), 0)
	result := scan(t, "renamed", data, certs.Options{})
	if result.Complete || !hasDiagnostic(result, "unrecognized_asn1") {
		t.Fatalf("text prefix hid binary suffix: %+v", result)
	}
}

func TestJavaArchiveDoesNotFillDiagnostics(t *testing.T) {
	class, err := os.ReadFile("testdata/InventoryExample.class")
	if err != nil {
		t.Fatal(err)
	}
	members := make([]member, certs.DefaultMaxDiagnostics+5)
	for i := range members {
		members[i] = member{"renamed", class}
	}
	members = append(members, member{"root.pem", pemCertificate(certificate(t, 1))})
	result := scan(t, "app.jar", zipArchive(t, members...), certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("Java archive: %+v", result)
	}
}
