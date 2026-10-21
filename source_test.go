package certs_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/certs"
)

func sourceFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGeneratedSourceCertificates(t *testing.T) {
	for _, tc := range []struct {
		file, fingerprint, entryType, marker string
	}{
		{"node-roots.h", "1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7", "c-string-pem", `"-----BEGIN`},
		{"rust-roots.rs", "018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05", "rust-byte-der", "CertificateDer::from_slice"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			data := sourceFixture(t, tc.file)
			result := scan(t, "renamed.data", data, certs.Options{})
			if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 {
				t.Fatalf("%+v", result)
			}
			collection := result.Collections[0]
			occurrence := collection.Occurrences[0]
			if collection.Format != "source" || collection.SHA256 != sha(data) || result.SHA256 != sha(data) {
				t.Fatalf("file identity: %+v", collection)
			}
			if occurrence.SHA256 != tc.fingerprint || occurrence.EntryType != tc.entryType || occurrence.Offset == nil || *occurrence.Offset != int64(bytes.Index(data, []byte(tc.marker))) {
				t.Fatalf("occurrence: %+v", occurrence)
			}
		})
	}
}

func TestSourceCertificatesInRenamedArchiveMembers(t *testing.T) {
	archive := zipArchive(t, member{"vendor/a.data", sourceFixture(t, "node-roots.h")}, member{"vendor/b.data", sourceFixture(t, "rust-roots.rs")})
	result := scan(t, "package.zip", archive, certs.Options{})
	if !result.Complete || len(result.Certificates) != 2 || len(result.Collections) != 2 {
		t.Fatalf("%+v", result)
	}
	for i, collection := range result.Collections {
		if len(collection.Location) != 2 || collection.Location[1].Entry != i+1 {
			t.Fatal(collection.Location)
		}
	}
	limited := scan(t, "package.zip", archive, certs.Options{MaxCertificates: 1})
	if limited.Complete || len(limited.Certificates) != 1 || !hasDiagnostic(limited, "certificate_limit") {
		t.Fatalf("limit: %+v", limited)
	}
}

func TestSourceIgnoresCommentedAndQuotedConstructors(t *testing.T) {
	rust := sourceFixture(t, "rust-roots.rs")
	node := sourceFixture(t, "node-roots.h")
	data := append([]byte("/* outer /* nested */\n"), rust...)
	data = append(data, []byte("*/\n")...)
	for _, line := range bytes.Split(node, []byte{'\n'}) {
		data = append(data, append([]byte("// "), line...)...)
		data = append(data, '\n')
	}
	data = append(data, []byte(`"CertificateDer::from_slice(b\"not a certificate\")"`)...)
	result := scan(t, "notes.txt", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 0 || len(result.Collections) != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestMalformedSourceRecoversLaterCertificate(t *testing.T) {
	valid := sourceFixture(t, "rust-roots.rs")
	for _, bad := range []string{
		`CertificateDer::from_slice(b"\xZZ"),`,
		`CertificateDer::from_slice(b"\u1234"),`,
		`CertificateDer::from_slice(b"\x30")`,
		`CertificateDer::from_slice(b"\x30",`,
		"CertificateDer::from_slice(b\"unterminated\n",
		`"-----BEGIN CERTIFICATE-----\n" "invalid\q",`,
		`"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",`,
	} {
		t.Run(bad, func(t *testing.T) {
			data := append([]byte(bad+"\n"), valid...)
			result := scan(t, "renamed.data", data, certs.Options{})
			if result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 || len(result.Diagnostics) == 0 {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestRustCertificateAPICallsAreNotEncodedCollections(t *testing.T) {
	data := []byte(`CertificateDer::from_slice(cert); CertificateDer::from_slice(include_bytes!("roots.der"));`)
	result := scan(t, "source.rs", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 0 || len(result.Collections) != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestSourceAndPlainPEMShareIdentity(t *testing.T) {
	der := certificate(t, 1)
	var source strings.Builder
	source.WriteString("CertificateDer::from_slice(b\"")
	for _, b := range der {
		fmt.Fprintf(&source, `\x%02x`, b)
	}
	source.WriteString("\");\n")
	data := append([]byte(source.String()), pemCertificate(der)...)
	result := scan(t, "mixed.data", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 || len(result.Collections[0].Occurrences) != 2 {
		t.Fatalf("%+v", result)
	}
	plain := scan(t, "root.pem", pemCertificate(der), certs.Options{})
	if result.Collections[0].SetSHA256 != plain.Collections[0].SetSHA256 || result.Certificates[0].SPKISHA256 != plain.Certificates[0].SPKISHA256 {
		t.Fatal("decoded identities differ")
	}
}

func TestQuotedSourceRetainsLaterBlockAfterMalformedPEM(t *testing.T) {
	bad := "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
	good := string(pemCertificate(certificate(t, 1)))
	data := []byte(strconv.Quote(bad) + "\n" + strconv.Quote(good))
	result := scan(t, "renamed.data", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 1 || !hasDiagnostic(result, "malformed_certificate") {
		t.Fatalf("%+v", result)
	}
}

func TestUnsupportedCStringEscapeIsNotInterpretedAsRust(t *testing.T) {
	data := []byte(`"-----BEGIN CERTIFICATE-----\n\x41B\n-----END CERTIFICATE-----"`)
	result := scan(t, "renamed.data", data, certs.Options{})
	if result.Complete || len(result.Certificates) != 0 || !hasDiagnostic(result, "unsupported_source") {
		t.Fatalf("%+v", result)
	}
}

func TestStaticTemplatePEMBundleInArchive(t *testing.T) {
	first, second := certificate(t, 1), certificate(t, 2)
	body := string(pemCertificate(first)) + strings.TrimSpace(string(pemCertificate(second)))
	source := []byte("\"use strict\";\nconst RedisCloudCA = `" + body + "`;\nexports.default = {ca: RedisCloudCA};\n")
	result := scan(t, "package.zip", zipArchive(t, member{"package/built/TLSProfiles.js", source}), certs.Options{})
	if !result.Complete || len(result.Certificates) != 2 || len(result.Collections) != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("%+v", result)
	}
	collection := result.Collections[0]
	if collection.Format != "source" || collection.SHA256 != sha(source) || len(collection.Occurrences) != 2 {
		t.Fatalf("collection: %+v", collection)
	}
	plain := scan(t, "bundle.pem", []byte(body), certs.Options{})
	if collection.SetSHA256 != plain.Collections[0].SetSHA256 {
		t.Fatal("template changed certificate identities")
	}
	for _, occurrence := range collection.Occurrences {
		if occurrence.EntryType != "js-template-pem" || occurrence.Offset == nil || *occurrence.Offset != int64(bytes.IndexByte(source, '`')) {
			t.Fatalf("occurrence: %+v", occurrence)
		}
	}
}

func TestUnsupportedTemplatesDoNotLeakPlainPEM(t *testing.T) {
	good := string(pemCertificate(certificate(t, 1)))
	for _, body := range []string{good + "${value}", "${value}" + good, good + `\n`, good + `\` + "`", strings.ReplaceAll(good, "\n", `\n`)} {
		source := []byte("const ca = `" + body + "`;\n" + good)
		result := scan(t, "source.js", source, certs.Options{})
		if result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 || len(result.Collections[0].Occurrences) != 1 || !hasDiagnostic(result, "unsupported_source") {
			t.Fatalf("body %q: %+v", body, result)
		}
	}
	result := scan(t, "source.js", []byte("const ca = `"+good), certs.Options{})
	if result.Complete || len(result.Certificates) != 0 || !hasDiagnostic(result, "unsupported_source") {
		t.Fatalf("unterminated: %+v", result)
	}
}

func TestTemplatePEMAndPlainDuplicateKeepBothOccurrences(t *testing.T) {
	good := string(pemCertificate(certificate(t, 1)))
	data := []byte("const other = `unrelated text`;\nconst ca = `" + good + "`;\n" + good)
	result := scan(t, "source.js", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 || len(result.Collections[0].Occurrences) != 2 {
		t.Fatalf("%+v", result)
	}
}

func FuzzSourceCertificates(f *testing.F) {
	f.Add(sourceFixture(f, "node-roots.h"))
	f.Add(sourceFixture(f, "rust-roots.rs"))
	f.Add([]byte("const ca = `" + string(sourceFixture(f, "ec-acc.pem")) + "`;"))
	f.Add([]byte(`CertificateDer::from_slice(b"\x`))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := certs.Scan(context.Background(), "input", bytes.NewReader(data), certs.Options{MaxFileBytes: 1 << 20, MaxCertificates: 100, MaxDiagnostics: 10})
		if err != nil || result == nil {
			t.Fatalf("scan: %v", err)
		}
	})
}
