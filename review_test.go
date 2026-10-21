package certs_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/git-pkgs/certs"
)

func TestCorruptArchiveMemberKeepsLaterCertificate(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range []string{"a.pem", "b.pem"} {
		entry, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(pemCertificate(certificate(t, 1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := z.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	data[offset] ^= 1
	result := scan(t, "bundle.zip", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || result.SHA256 != sha(data) || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "member_error" {
		t.Fatalf("%+v", result)
	}
	if result.Collections[0].Location[1].Path != "b.pem" {
		t.Fatal(result.Collections)
	}
	// Also exercise corruption encountered when a native member is skipped.
	var skipped bytes.Buffer
	w = zip.NewWriter(&skipped)
	entry, err := w.CreateHeader(&zip.FileHeader{Name: "a.so", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 1024)...)); err != nil {
		t.Fatal(err)
	}
	entry, err = w.Create("b.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(entry, bytes.NewReader(pemCertificate(certificate(t, 1)))); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data = skipped.Bytes()
	data[600] ^= 1
	result = scan(t, "skipped.zip", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || result.SHA256 != sha(data) || !hasDiagnostic(result, "archive_error") {
		t.Fatalf("%+v", result)
	}
}

func privateKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPKCS8IsNotPKCS12(t *testing.T) {
	result := scan(t, "renamed", privateKeyDER(t), certs.Options{})
	if len(result.Collections) != 0 || !hasDiagnostic(result, "unrecognized_asn1") {
		t.Fatalf("%+v", result)
	}
	for _, version := range []int{0, 1, 2, 4} {
		data := marshal(t, testPFX{Version: version, AuthSafe: testContentInfo{Type: testDataOID}})
		result = scan(t, "version", data, certs.Options{})
		if len(result.Collections) != 0 {
			t.Fatalf("version %d: %+v", version, result)
		}
	}
	data := marshal(t, testPFX{Version: 3, AuthSafe: testContentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}}})
	result = scan(t, "signed", data, certs.Options{})
	if len(result.Collections) != 1 || result.Collections[0].Format != "pkcs12" || !hasDiagnostic(result, "unsupported_store") {
		t.Fatalf("%+v", result)
	}
}

func TestCorruptDeflateMemberKeepsLaterCertificate(t *testing.T) {
	pemData := pemCertificate(certificate(t, 1))
	data := zipArchive(t, member{"a.pem", pemData}, member{"b.pem", pemData})
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := z.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	data[offset] = 0x07
	result := scan(t, "deflate.zip", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || result.SHA256 != sha(data) || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "member_error" {
		t.Fatalf("%+v", result)
	}
	if result.Collections[0].Location[1].Path != "b.pem" || result.Collections[0].Location[1].Entry != 2 {
		t.Fatal(result.Collections)
	}
}

func TestRecognizedImagesSkipCertificateFileLimit(t *testing.T) {
	for _, prefix := range [][]byte{
		{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'},
		[]byte("GIF89a"),
		{0xff, 0xd8, 0xff},
	} {
		data := append(bytes.Clone(prefix), bytes.Repeat([]byte{0}, 4096)...)
		result := scan(t, "renamed", data, certs.Options{MaxFileBytes: 64})
		if !result.Complete || len(result.Diagnostics) != 0 || result.SHA256 != sha(data) {
			t.Fatalf("image: %+v", result)
		}
	}
}

func TestCompressedCertificateFiles(t *testing.T) {
	pemData := pemCertificate(certificate(t, 1))
	compressed := gzipData(t, pemData)
	for _, name := range []string{"bundle.pem.gz", "renamed"} {
		result := scan(t, name, compressed, certs.Options{})
		if !result.Complete || len(result.Certificates) != 1 || result.SHA256 != sha(compressed) || result.Collections[0].SHA256 != sha(pemData) {
			t.Fatalf("%s: %+v", name, result)
		}
		if result.Collections[0].Location[1].Path != "content" {
			t.Fatal(result.Collections)
		}
	}
	data := zipArchive(t, member{"bundle.pem.gz", compressed})
	result := scan(t, "package.zip", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 || len(result.Collections[0].Location) != 3 {
		t.Fatalf("%+v", result)
	}
}

func TestCompressedFilesShareExpansionBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("source text\n"), 100)
	compressed := gzipData(t, payload)
	data := zipArchive(t, member{"one.gz", compressed}, member{"two.gz", compressed})
	limit := int64(2*len(compressed) + len(payload))
	result, err := certs.Scan(context.Background(), "package.zip", bytes.NewReader(data), certs.Options{MaxExpandedBytes: limit})
	if err != nil || result.Complete || result.SHA256 != sha(data) || !hasDiagnostic(result, "archive_limit") {
		t.Fatalf("shared expansion limit: %+v %v", result, err)
	}
	result = scan(t, "exact.gz", compressed, certs.Options{MaxExpandedBytes: int64(len(payload))})
	if !result.Complete {
		t.Fatalf("exact limit: %+v", result)
	}
}

func TestUnsupportedPEMCoverage(t *testing.T) {
	container := marshal(t, testContentInfo{
		Type:    asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: explicit(marshal(t, []asn1.RawValue{{FullBytes: certificate(t, 1)}})),
	})
	for _, label := range []string{"PKCS7", "CMS"} {
		data := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: container})
		result := scan(t, "renamed", data, certs.Options{})
		if result.Complete || !hasDiagnostic(result, "unsupported_pem") || len(result.Certificates) != 0 {
			t.Fatalf("%s: %+v", label, result)
		}
		data = append(data, pemCertificate(certificate(t, 2))...)
		result = scan(t, "mixed", data, certs.Options{})
		if result.Complete || len(result.Certificates) != 1 || result.Collections[0].Complete {
			t.Fatalf("%s mixed: %+v", label, result)
		}
	}
}

func TestTrailingDERObjects(t *testing.T) {
	der := certificate(t, 1)
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	issuer.KeyUsage |= x509.KeyUsageCRLSign
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, trailing := range map[string][]byte{"key": privateKeyDER(t), "crl": crl} {
		data := append(bytes.Clone(der), trailing...)
		data = append(data, certificate(t, 2)...)
		result := scan(t, name, data, certs.Options{})
		wantComplete := name == "crl"
		if result.Complete != wantComplete || len(result.Certificates) != 2 || hasDiagnostic(result, "malformed_certificate") || hasDiagnostic(result, "unrecognized_asn1") == wantComplete {
			t.Fatalf("%s: %+v", name, result)
		}
		if result.Collections[0].Complete != wantComplete {
			t.Fatal("incorrect collection coverage")
		}
	}
	for _, data := range [][]byte{crl, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})} {
		result := scan(t, "revocations", data, certs.Options{})
		if !result.Complete || len(result.Collections) != 0 {
			t.Fatalf("CRL encoding changed coverage: %+v", result)
		}
	}
}

func TestCoverageDiagnosticsDoNotHideMalformedCertificates(t *testing.T) {
	members := make([]member, 0, certs.DefaultMaxDiagnostics+10)
	for i := 0; i < certs.DefaultMaxDiagnostics+5; i++ {
		members = append(members, member{fmt.Sprintf("unknown%d", i), []byte{0, 1, 2, 3, 4}})
	}
	members = append(members, member{"bad.pem", []byte("-----BEGIN CERTIFICATE-----\nbad!\n-----END CERTIFICATE-----\n")})
	result := scan(t, "app.jar", zipArchive(t, members...), certs.Options{})
	if result.Complete || !hasDiagnostic(result, "malformed_certificate") || !hasDiagnostic(result, "diagnostic_limit") || len(result.Diagnostics) != certs.DefaultMaxDiagnostics+1 {
		t.Fatalf("diagnostics: %d, malformed: %v", len(result.Diagnostics), hasDiagnostic(result, "malformed_certificate"))
	}
}
