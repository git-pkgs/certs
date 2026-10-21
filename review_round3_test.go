package certs_test

import (
	"archive/zip"
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/git-pkgs/certs"
)

func TestPEMMarkerDoesNotOverrideBinaryDetection(t *testing.T) {
	marker := []byte("-----BEGIN CERTIFICATE-----")
	der := certificate(t, 1)
	result := scan(t, "mixed", append(bytes.Clone(der), marker...), certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || !hasDiagnostic(result, "unrecognized_asn1") {
		t.Fatalf("DER with marker: %+v", result)
	}
	for _, prefix := range [][]byte{[]byte("dex\n035\x00"), {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}} {
		for _, suffix := range [][]byte{nil, marker, pemCertificate(der)} {
			result = scan(t, "renamed", append(bytes.Clone(prefix), suffix...), certs.Options{})
			if result.Complete || len(result.Diagnostics) != 1 || !hasDiagnostic(result, "unrecognized_binary") {
				t.Fatalf("binary with marker: %+v", result)
			}
		}
	}
}

func TestMalformedPEMDoesNotCreateCollection(t *testing.T) {
	for _, body := range []string{"invalid!", "MAMCAQA="} {
		result := scan(t, "broken", []byte("-----BEGIN CERTIFICATE-----\n"+body+"\n-----END CERTIFICATE-----\n"), certs.Options{})
		if result.Complete || len(result.Collections) != 0 || !hasDiagnostic(result, "malformed_certificate") {
			t.Fatalf("malformed PEM: %+v", result)
		}
	}
}

func TestPEMOnlyCertificateContainersNeedCoverageDiagnostic(t *testing.T) {
	for _, label := range []string{"DH PARAMETERS", "DSA PARAMETERS", "X9.42 DH PARAMETERS", "PARAMETERS", "APPLICATION DATA", "PKCS7", "CMS", "CERTIFICATE PAIR", "PKCS #7 SIGNED DATA"} {
		data := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0}})
		result := scan(t, "renamed", data, certs.Options{})
		unsupported := label == "PKCS7" || label == "CMS" || label == "CERTIFICATE PAIR" || label == "PKCS #7 SIGNED DATA"
		if result.Complete == unsupported || hasDiagnostic(result, "unsupported_pem") != unsupported || len(result.Collections) != 0 {
			t.Fatalf("%s: %+v", label, result)
		}
	}
}

func TestOversizedZIPMemberKeepsSmallSibling(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for _, m := range []member{{"big.txt", bytes.Repeat([]byte{'a'}, 2700)}, {"root.pem", pemCertificate(certificate(t, 1))}} {
			body, err := w.CreateHeader(&zip.FileHeader{Name: m.name, Method: method})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := body.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		result := scan(t, "package", buf.Bytes(), certs.Options{MaxExpandedBytes: 1000})
		if result.Complete || len(result.Certificates) != 1 || len(result.Diagnostics) != 1 || result.SHA256 != sha(buf.Bytes()) {
			t.Fatalf("oversized sibling: %+v", result)
		}
		if result.Diagnostics[0].Location[1].Path != "big.txt" || result.Collections[0].Location[1].Entry != 2 {
			t.Fatalf("member locations: %+v", result)
		}
	}
}

func TestSharedNestedBudgetSkipsZIPMember(t *testing.T) {
	der := certificate(t, 1)
	inner := zipArchive(t, member{"big.txt", bytes.Repeat([]byte{'a'}, 2700)}, member{"root", der})
	outer := zipArchive(t, member{"nested", inner})
	result := scan(t, "outer", outer, certs.Options{MaxExpandedBytes: int64(len(inner) + len(der))})
	if result.Complete || len(result.Certificates) != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("nested shared budget: %+v", result)
	}
}
