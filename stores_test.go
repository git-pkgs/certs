package certs_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/git-pkgs/certs"
)

func writeValue(t testing.TB, w *bytes.Buffer, value any) {
	t.Helper()
	if err := binary.Write(w, binary.BigEndian, value); err != nil {
		t.Fatal(err)
	}
}

func javaString(t testing.TB, w *bytes.Buffer, text string) {
	t.Helper()
	var encoded []byte
	for _, unit := range utf16.Encode([]rune(text)) {
		switch {
		case unit > 0 && unit < 0x80:
			encoded = append(encoded, byte(unit))
		case unit < 0x800:
			encoded = append(encoded, 0xc0|byte(unit>>6), 0x80|byte(unit&0x3f))
		default:
			encoded = append(encoded, 0xe0|byte(unit>>12), 0x80|byte((unit>>6)&0x3f), 0x80|byte(unit&0x3f))
		}
	}
	writeValue(t, w, uint16(len(encoded)))
	w.Write(encoded)
}

func jksStore(t testing.TB, version uint32, der []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writeValue(t, &buffer, uint32(0xfeedfeed))
	writeValue(t, &buffer, version)
	writeValue(t, &buffer, uint32(2))
	for _, tag := range []uint32{2, 1} {
		writeValue(t, &buffer, tag)
		javaString(t, &buffer, "root\x00\U0001D11E")
		writeValue(t, &buffer, uint64(1700000000000))
		if tag == 1 {
			writeValue(t, &buffer, uint32(3))
			buffer.Write([]byte{1, 2, 3})
			writeValue(t, &buffer, uint32(1))
		}
		if version == 2 {
			javaString(t, &buffer, "X.509")
		}
		writeValue(t, &buffer, uint32(len(der)))
		buffer.Write(der)
	}
	buffer.Write(make([]byte, 20))
	return buffer.Bytes()
}

func TestJKSStoresThroughArchive(t *testing.T) {
	for _, version := range []uint32{1, 2} {
		der := certificate(t, 1)
		store := jksStore(t, version, der)
		result := scan(t, "package.jar", zipArchive(t, member{"security/renamed", store}), certs.Options{})
		if !result.Complete || len(result.Certificates) != 1 || len(result.Collections) != 1 {
			t.Fatalf("%+v", result)
		}
		collection := result.Collections[0]
		if collection.Format != "jks" || collection.Integrity != "not_checked" || len(collection.Occurrences) != 2 {
			t.Fatalf("%+v", collection)
		}
		if collection.Occurrences[0].EntryType != "trusted_certificate" || collection.Occurrences[1].EntryType != "key_certificate_chain" {
			t.Fatal(collection.Occurrences)
		}
		for _, occurrence := range collection.Occurrences {
			if occurrence.Alias != "root\x00\U0001D11E" {
				t.Fatalf("alias: %q", occurrence.Alias)
			}
			if !bytes.Equal(store[*occurrence.Offset:*occurrence.Offset+int64(len(der))], der) {
				t.Fatal("incorrect DER offset")
			}
		}
	}
}

func TestTruncatedJKSAndEntryLimit(t *testing.T) {
	store := jksStore(t, 2, certificate(t, 1))
	for _, size := range []int{4, 12, len(store) - 1} {
		result := scan(t, "store", store[:size], certs.Options{})
		if result.Complete || len(result.Diagnostics) == 0 {
			t.Fatalf("truncated store accepted: %+v", result)
		}
	}
	result := scan(t, "store", store, certs.Options{MaxEntries: 1})
	if result.Complete || !hasDiagnostic(result, "store_limit") {
		t.Fatalf("%+v", result)
	}
}

type testContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type testPFX struct {
	Version  int
	AuthSafe testContentInfo
}
type testBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue   `asn1:"explicit,tag:0"`
	Attributes []testAttribute `asn1:"set,optional"`
}
type testAttribute struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}
type testCertBag struct {
	ID    asn1.ObjectIdentifier
	Value []byte `asn1:"explicit,tag:0"`
}

var testDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

func marshal(t testing.TB, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func explicit(data []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data}
}

func certificateBag(t testing.TB, der []byte) testBag {
	return testBag{
		ID:    asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3},
		Value: explicit(marshal(t, testCertBag{ID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}, Value: der})),
		Attributes: []testAttribute{
			{ID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}, Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: marshal(t, asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0, 'C', 0, 'A'}})}},
			{ID: asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}, Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: marshal(t, asn1.ObjectIdentifier{2, 5, 29, 37, 0})}},
		},
	}
}

func pfxStore(t testing.TB, contents ...testContentInfo) []byte {
	safe := marshal(t, contents)
	return marshal(t, testPFX{Version: 3, AuthSafe: testContentInfo{Type: testDataOID, Content: explicit(marshal(t, safe))}})
}

func readableContents(t testing.TB, bags ...testBag) testContentInfo {
	return testContentInfo{Type: testDataOID, Content: explicit(marshal(t, marshal(t, bags)))}
}

func TestPKCS12ReadableAndEncryptedContents(t *testing.T) {
	der := certificate(t, 1)
	readable := readableContents(t, certificateBag(t, der))
	encrypted := testContentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}, Content: explicit(marshal(t, []byte("encrypted safe")))}
	for _, partial := range []bool{false, true} {
		contents := []testContentInfo{readable}
		if partial {
			contents = append(contents, encrypted)
		}
		result := scan(t, "renamed.store", pfxStore(t, contents...), certs.Options{})
		if result.Complete == partial || len(result.Certificates) != 1 || len(result.Collections) != 1 {
			t.Fatalf("%+v", result)
		}
		collection := result.Collections[0]
		if collection.Format != "pkcs12" || collection.Integrity != "not_present" {
			t.Fatal(collection)
		}
		occurrence := collection.Occurrences[0]
		if occurrence.SHA256 != sha(der) || occurrence.Alias != "CA" || occurrence.EntryType != "trusted_certificate" || occurrence.TrustOIDs[0] != "2.5.29.37.0" {
			t.Fatal(occurrence)
		}
		if partial && !hasDiagnostic(result, "encrypted_store") {
			t.Fatal(result.Diagnostics)
		}
	}
}

func TestPKCS12NestedBagsAndLimits(t *testing.T) {
	bag := certificateBag(t, certificate(t, 1))
	nested := testBag{ID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}, Value: explicit(marshal(t, []testBag{bag}))}
	data := pfxStore(t, readableContents(t, nested))
	result := scan(t, "store", data, certs.Options{})
	if !result.Complete || len(result.Certificates) != 1 {
		t.Fatalf("%+v", result)
	}
	result = scan(t, "store", data, certs.Options{MaxDepth: 1})
	if result.Complete || !hasDiagnostic(result, "depth_limit") {
		t.Fatalf("%+v", result)
	}
	result = scan(t, "store", data, certs.Options{MaxEntries: 1})
	if result.Complete || !hasDiagnostic(result, "store_limit") {
		t.Fatalf("%+v", result)
	}
}

func TestPKCS12EncryptedOnlyRetainsStore(t *testing.T) {
	data := pfxStore(t, testContentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}, Content: explicit(marshal(t, []byte("encrypted safe")))})
	result := scan(t, "store", data, certs.Options{})
	if result.Complete || len(result.Collections) != 1 || result.Collections[0].Format != "pkcs12" || len(result.Certificates) != 0 {
		t.Fatalf("%+v", result)
	}
}
