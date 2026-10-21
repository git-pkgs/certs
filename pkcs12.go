package certs

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

var (
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEncryptedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidKeyBag          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Bag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidJavaTrust       = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}
)

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type pfx struct {
	Version  int
	AuthSafe contentInfo
	MAC      asn1.RawValue `asn1:"optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue  `asn1:"explicit,tag:0"`
	Attributes []bagAttribute `asn1:"set,optional"`
}

type bagAttribute struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID    asn1.ObjectIdentifier
	Value []byte `asn1:"explicit,tag:0"`
}

func looksLikePFX(data []byte) bool {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(data, &outer); err != nil || outer.Tag != asn1.TagSequence || outer.Class != asn1.ClassUniversal {
		return false
	}
	var version int
	rest, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != 3 {
		return false
	}
	var info contentInfo
	_, err = asn1.Unmarshal(rest, &info)
	return err == nil && (info.Type.Equal(oidData) || info.Type.Equal(oidSignedData))
}

func (s *scanner) pkcs12(data []byte, collection *Collection) {
	var store pfx
	if err := unmarshalExact(data, &store); err != nil {
		s.problem(collection, "malformed_store", err.Error())
		return
	}
	collection.Integrity = "not_present"
	if len(store.MAC.FullBytes) > 0 {
		collection.Integrity = "not_checked"
	}
	if store.Version != 3 || !store.AuthSafe.Type.Equal(oidData) {
		s.problem(collection, "unsupported_store", "unsupported PKCS#12 authentication format")
		return
	}
	var authenticatedSafe []byte
	if err := unmarshalExact(store.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		s.problem(collection, "malformed_store", err.Error())
		return
	}
	var sequence asn1.RawValue
	if err := unmarshalExact(authenticatedSafe, &sequence); err != nil || sequence.Tag != asn1.TagSequence || sequence.Class != asn1.ClassUniversal {
		s.problem(collection, "malformed_store", "invalid PKCS#12 authenticated safe sequence")
		return
	}
	for remaining := sequence.Bytes; len(remaining) > 0; {
		if s.entries >= s.options.MaxEntries {
			s.problem(collection, "store_limit", "PKCS#12 content limit reached")
			return
		}
		s.entries++
		var info contentInfo
		rest, err := asn1.Unmarshal(remaining, &info)
		if err != nil {
			s.problem(collection, "malformed_store", err.Error())
			return
		}
		remaining = rest
		s.pkcs12Content(info, collection)
	}
}

func (s *scanner) pkcs12Content(info contentInfo, collection *Collection) {
	switch {
	case info.Type.Equal(oidData):
		var contents []byte
		if err := unmarshalExact(info.Content.Bytes, &contents); err != nil {
			s.problem(collection, "malformed_store", err.Error())
			return
		}
		s.safeContents(contents, collection, 0)
	case info.Type.Equal(oidEncryptedData):
		s.problem(collection, "encrypted_store", "encrypted PKCS#12 contents were not decrypted")
	default:
		s.problem(collection, "unsupported_store", "unsupported PKCS#12 content type: "+info.Type.String())
	}
}

func (s *scanner) safeContents(data []byte, collection *Collection, depth int) {
	if depth >= s.options.MaxDepth {
		s.problem(collection, "depth_limit", "nested PKCS#12 bag limit reached")
		return
	}
	var sequence asn1.RawValue
	if err := unmarshalExact(data, &sequence); err != nil || sequence.Tag != asn1.TagSequence || sequence.Class != asn1.ClassUniversal {
		s.problem(collection, "malformed_store", "invalid PKCS#12 safe contents sequence")
		return
	}
	for remaining := sequence.Bytes; len(remaining) > 0; {
		if err := s.ctx.Err(); err != nil {
			s.problem(collection, "canceled", err.Error())
			return
		}
		if s.entries >= s.options.MaxEntries {
			s.problem(collection, "store_limit", "PKCS#12 bag limit reached")
			return
		}
		s.entries++
		var bag safeBag
		rest, err := asn1.Unmarshal(remaining, &bag)
		if err != nil {
			s.problem(collection, "malformed_store", err.Error())
			return
		}
		remaining = rest
		if !s.pkcs12Bag(bag, collection, depth) {
			return
		}
	}
}

func (s *scanner) pkcs12Bag(bag safeBag, collection *Collection, depth int) bool {
	switch {
	case bag.ID.Equal(oidCertBag):
		var certificate certBag
		if err := unmarshalExact(bag.Value.Bytes, &certificate); err != nil {
			s.problem(collection, "malformed_store", err.Error())
			return true
		}
		if !certificate.ID.Equal(oidX509Bag) {
			s.problem(collection, "unsupported_certificate", "unsupported PKCS#12 certificate type")
			return true
		}
		occurrence, err := bagOccurrence(bag.Attributes)
		if err != nil {
			s.problem(collection, "malformed_attributes", err.Error())
		}
		return s.addCertificate(certificate.Value, collection, occurrence)
	case bag.ID.Equal(oidSafeContentsBag):
		s.safeContents(bag.Value.Bytes, collection, depth+1)
	case bag.ID.Equal(oidKeyBag), bag.ID.Equal(oidShroudedKeyBag):
		// Key bags contain no certificate inventory.
	default:
		s.problem(collection, "unsupported_store", "unsupported PKCS#12 bag type: "+bag.ID.String())
	}
	return true
}

func bagOccurrence(attributes []bagAttribute) (Occurrence, error) {
	occurrence := Occurrence{EntryType: "certificate_bag"}
	for _, attribute := range attributes {
		switch {
		case attribute.ID.Equal(oidFriendlyName):
			var value asn1.RawValue
			if err := unmarshalExact(attribute.Values.Bytes, &value); err != nil {
				return occurrence, err
			}
			if value.Tag != asn1.TagBMPString || len(value.Bytes)%2 != 0 {
				return occurrence, errors.New("invalid PKCS#12 friendly name")
			}
			units := make([]uint16, len(value.Bytes)/uint16Bytes)
			for i := range units {
				units[i] = binary.BigEndian.Uint16(value.Bytes[i*2:])
			}
			occurrence.Alias = string(utf16.Decode(units))
		case attribute.ID.Equal(oidJavaTrust):
			for remaining := attribute.Values.Bytes; len(remaining) > 0; {
				var oid asn1.ObjectIdentifier
				rest, err := asn1.Unmarshal(remaining, &oid)
				if err != nil {
					return occurrence, err
				}
				remaining = rest
				occurrence.TrustOIDs = append(occurrence.TrustOIDs, oid.String())
			}
			if len(occurrence.TrustOIDs) > 0 {
				occurrence.EntryType = "trusted_certificate"
			}
		}
	}
	return occurrence, nil
}

func unmarshalExact(data []byte, target any) error {
	rest, err := asn1.Unmarshal(data, target)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected trailing ASN.1 data")
	}
	return nil
}
