package certs_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/git-pkgs/certs"
)

func TestScanLegacyNegativeSerialPreservesIdentity(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	encoded := sourceFixture(t, "ec-acc.pem")
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("missing fixture certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Fatal("fixture must exercise strict serial parsing")
	}
	before := bytes.Clone(block.Bytes)
	for _, data := range [][]byte{encoded, block.Bytes, zipArchive(t, member{"cacerts", encoded})} {
		result := scan(t, "renamed.data", data, certs.Options{})
		if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 || len(result.Diagnostics) != 0 {
			t.Fatalf("%+v", result)
		}
		identity := result.Certificates[0]
		if identity.SHA256 != "88497f01602f3154246ae28c4d5aef10f1d87ebb76626f4ae0b7f95ba7968799" || identity.Serial != "-11d4c2142bde21eb579d53fb0c223bff" {
			t.Fatalf("identity: %+v", identity)
		}
		if identity.Subject != identity.Issuer || !identity.IsCA || !identity.BasicConstraints {
			t.Fatalf("CA metadata: %+v", identity)
		}
	}
	if !bytes.Equal(before, block.Bytes) || os.Getenv("GODEBUG") != "x509negativeserial=0" {
		t.Fatal("input bytes or process policy changed")
	}
}

func TestNegativeSerialDoesNotBypassOtherCertificateErrors(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	encoded := sourceFixture(t, "ec-acc.pem")
	block, _ := pem.Decode(encoded)
	for _, data := range [][]byte{block.Bytes[:len(block.Bytes)-1], bytes.Replace(block.Bytes, []byte("030107230000Z"), []byte("xxxxxxxxxxxxZ"), 1)} {
		result := scan(t, "bad.pem", pemCertificate(data), certs.Options{})
		if result.Complete || len(result.Certificates) != 0 || !hasDiagnostic(result, "malformed_certificate") {
			t.Fatalf("%+v", result)
		}
	}
}
