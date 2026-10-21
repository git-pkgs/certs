package certs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
)

const (
	jksPrivateKey         = 1
	jksTrustedCertificate = 2
	jksDigestBytes        = 20
	jksTimestampBytes     = 8
	jksTypedVersion       = 2
	uint32Bytes           = 4
	uint16Bytes           = 2
	utf8TwoByteMask       = 0x1f
	utf8ThreeByteMask     = 0x0f
	utf8ThreeByteMinimum  = 0x800
	utf8ContinuationMask  = 0x3f
	utf8ContinuationBits  = 6
	utf8ThreeByteShift    = 12
)

type jksReader struct {
	data   []byte
	offset int
	err    error
}

func (s *scanner) jks(data []byte, collection *Collection) {
	collection.Integrity = "not_checked"
	r := &jksReader{data: data}
	_ = r.uint32()
	version := r.uint32()
	if version != 1 && version != 2 {
		s.problem(collection, "unsupported_store", "unsupported JKS format version")
		return
	}
	count := r.uint32()
	for i := uint32(0); i < count && r.err == nil; i++ {
		if s.entries >= s.options.MaxEntries {
			s.problem(collection, "store_limit", "JKS entry limit reached")
			return
		}
		s.entries++
		if !s.jksEntry(r, version, collection) {
			return
		}
	}
	_ = r.take(jksDigestBytes)
	if r.err != nil {
		s.problem(collection, "malformed_store", r.err.Error())
	} else if r.offset != len(data) {
		s.problem(collection, "malformed_store", "trailing data after JKS digest")
	}
}

func (s *scanner) jksEntry(r *jksReader, version uint32, collection *Collection) bool {
	tag := r.uint32()
	alias := r.text()
	_ = r.take(jksTimestampBytes)
	entryType := "trusted_certificate"
	count := uint32(1)
	switch tag {
	case jksPrivateKey:
		_ = r.take(int(r.uint32()))
		count = r.uint32()
		entryType = "key_certificate_chain"
	case jksTrustedCertificate:
	default:
		s.problem(collection, "malformed_store", fmt.Sprintf("unknown JKS entry tag %d", tag))
		return false
	}
	for i := uint32(0); i < count && r.err == nil; i++ {
		if s.occurrences >= s.options.MaxCertificates {
			s.problem(collection, "certificate_limit", "certificate occurrence limit reached")
			return false
		}
		typeName := "X.509"
		if version == jksTypedVersion {
			typeName = r.text()
		}
		size := r.uint32()
		offset := int64(r.offset)
		der := r.take(int(size))
		if r.err != nil {
			break
		}
		if typeName != "X.509" {
			s.problem(collection, "unsupported_certificate", "unsupported JKS certificate type: "+typeName)
			continue
		}
		if !s.addCertificate(der, collection, Occurrence{Offset: &offset, Alias: alias, EntryType: entryType}) {
			return false
		}
	}
	return true
}

func (r *jksReader) take(size int) []byte {
	if r.err != nil {
		return nil
	}
	if size < 0 || size > len(r.data)-r.offset {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	data := r.data[r.offset : r.offset+size]
	r.offset += size
	return data
}

func (r *jksReader) uint32() uint32 {
	data := r.take(uint32Bytes)
	if len(data) != uint32Bytes {
		return 0
	}
	return binary.BigEndian.Uint32(data)
}

func (r *jksReader) text() string {
	length := r.take(uint16Bytes)
	if len(length) != uint16Bytes {
		return ""
	}
	data := r.take(int(binary.BigEndian.Uint16(length)))
	text, err := modifiedUTF8(data)
	if err != nil {
		r.err = err
	}
	return text
}

// Java's modified UTF-8 encodes UTF-16 code units, including surrogate pairs.
func modifiedUTF8(data []byte) (string, error) {
	units := make([]uint16, 0, len(data))
	for len(data) > 0 {
		b := data[0]
		switch {
		case b > 0 && b < 0x80:
			units = append(units, uint16(b))
			data = data[1:]
		case b&0xe0 == 0xc0 && len(data) >= 2 && data[1]&0xc0 == 0x80:
			unit := uint16(b&utf8TwoByteMask)<<utf8ContinuationBits | uint16(data[1]&utf8ContinuationMask)
			if unit != 0 && unit < 0x80 {
				return "", errors.New("invalid JKS modified UTF-8")
			}
			units = append(units, unit)
			data = data[2:]
		case b&0xf0 == 0xe0 && len(data) >= 3 && data[1]&0xc0 == 0x80 && data[2]&0xc0 == 0x80:
			unit := uint16(b&utf8ThreeByteMask)<<utf8ThreeByteShift | uint16(data[1]&utf8ContinuationMask)<<utf8ContinuationBits | uint16(data[2]&utf8ContinuationMask)
			if unit < utf8ThreeByteMinimum {
				return "", errors.New("invalid JKS modified UTF-8")
			}
			units = append(units, unit)
			data = data[3:]
		default:
			return "", errors.New("invalid JKS modified UTF-8")
		}
	}
	return string(utf16.Decode(units)), nil
}
