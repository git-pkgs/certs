package certs

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"

	"github.com/git-pkgs/magic"
)

const (
	formatPEM     = "pem"
	formatDER     = "der"
	formatJKS     = "jks"
	formatPKCS12  = "pkcs12"
	jksMagic      = 0xfeedfeed
	jceksMagic    = 0xcececece
	codeMalformed = "malformed_certificate"
	hexRadix      = 16
)

func (s *scanner) parse(data []byte, location []Member, detection magic.Result) {
	collection := Collection{Location: slices.Clone(location), Complete: true, Occurrences: []Occurrence{}}
	switch {
	case len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == jksMagic:
		collection.Format = formatJKS
		s.jks(data, &collection)
	case len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == jceksMagic:
		collection.Format = "jceks"
		s.problem(&collection, "unsupported_store", "JCEKS entries are not parsed")
	case len(data) > 0 && data[0] == 0x30 && detection.Kind != magic.KindText:
		collection.Format = formatDER
		if looksLikePFX(data) {
			collection.Format = formatPKCS12
			s.pkcs12(data, &collection)
		} else if !s.der(data, &collection) {
			return
		}
	default:
		collection.Format = formatPEM
		if detection.Kind == magic.KindBinary {
			s.problem(&collection, "unrecognized_binary", "binary content outside supported certificate formats was not inventoried")
			return
		}
		if bytes.Contains(data, []byte("-----BEGIN ")) {
			s.pem(data, &collection)
		}
		s.sourceCertificates(data, &collection)
		if len(collection.Occurrences) == 0 {
			return
		}
	}
	collection.SHA256 = digest(data)
	if len(collection.Occurrences) > 0 {
		collection.SetSHA256 = setDigest(collection.Occurrences)
		collection.Matches = s.options.Catalog.MatchCollection(collection)
	}
	s.result.Collections = append(s.result.Collections, collection)
}

func (s *scanner) pem(data []byte, collection *Collection) {
	const begin = "-----BEGIN "
	for pos := 0; pos < len(data); {
		rel := bytes.Index(data[pos:], []byte(begin))
		if rel < 0 {
			break
		}
		start := pos + rel
		if !pemLineStart(data, start) {
			pos = start + len(begin)
			continue
		}
		end := len(data)
		if next := bytes.Index(data[start+len(begin):], []byte(begin)); next >= 0 {
			end = start + len(begin) + next
		}
		chunk := data[start:end]
		pos = end
		if !certificatePEM(chunk) {
			if block, _ := pem.Decode(chunk); block != nil && certificateContainerPEM(block.Type) {
				s.diagnostic(collection.Location, "unsupported_pem", "unsupported PEM block: "+block.Type)
				collection.Complete = false
			}
			continue
		}
		if placeholderPEM(chunk) {
			continue
		}
		block, _ := pem.Decode(chunk)
		if block == nil {
			s.problem(collection, codeMalformed, fmt.Sprintf("invalid PEM certificate at offset %d", start))
			continue
		}
		der := block.Bytes
		if block.Type == "TRUSTED CERTIFICATE" {
			var value asn1.RawValue
			trailing, err := asn1.Unmarshal(der, &value)
			if err == nil && len(trailing) > 0 {
				der = value.FullBytes
				s.problem(collection, "unsupported_trust_attributes", "OpenSSL auxiliary trust attributes were not inventoried")
			}
		}
		offset := int64(start)
		if !s.addCertificate(der, collection, Occurrence{Offset: &offset}) {
			break
		}
	}
}

func pemLineStart(data []byte, offset int) bool {
	for offset > 0 {
		offset--
		switch data[offset] {
		case '\n':
			return true
		case ' ', '\t', '\r':
		default:
			return false
		}
	}
	return true
}

func certificateContainerPEM(label string) bool {
	switch label {
	case "PKCS7", "CMS", "CERTIFICATE PAIR", "PKCS #7 SIGNED DATA":
		return true
	default:
		return false
	}
}

func placeholderPEM(data []byte) bool {
	header, rest, _ := bytes.Cut(data, []byte{'\n'})
	footer := bytes.Replace(bytes.TrimSpace(header), []byte("BEGIN"), []byte("END"), 1)
	body, _, found := bytes.Cut(rest, footer)
	body = bytes.TrimSpace(body)
	return found && (bytes.Equal(body, []byte("...")) || bytes.Equal(body, []byte("…")))
}

func certificatePEM(data []byte) bool {
	for _, label := range []string{"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"} {
		header := []byte("-----BEGIN " + label + "-----")
		if bytes.HasPrefix(data, header) {
			line, _, _ := bytes.Cut(data[len(header):], []byte{'\n'})
			return len(bytes.Trim(line, " \t\r")) == 0
		}
	}
	return false
}

func (s *scanner) der(data []byte, collection *Collection) bool {
	unrecognized := -1
	flush := func() {
		if unrecognized >= 0 {
			s.problem(collection, "unrecognized_asn1", fmt.Sprintf("unsupported ASN.1 or trailing data at offset %d", unrecognized))
			unrecognized = -1
		}
	}
	for offset := 0; offset < len(data); {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data[offset:], &value)
		if err != nil {
			if unrecognized < 0 {
				unrecognized = offset
			}
			break
		}
		if !looksLikeCertificate(value) {
			if unrecognized < 0 {
				unrecognized = offset
			}
			offset = len(data) - len(rest)
			continue
		}
		flush()
		at := int64(offset)
		if !s.addCertificate(value.FullBytes, collection, Occurrence{Offset: &at}) {
			break
		}
		offset = len(data) - len(rest)
	}
	flush()
	return len(collection.Occurrences) > 0
}

func looksLikeCertificate(value asn1.RawValue) bool {
	if value.Tag != asn1.TagSequence || value.Class != asn1.ClassUniversal {
		return false
	}
	var tbs asn1.RawValue
	_, err := asn1.Unmarshal(value.Bytes, &tbs)
	return err == nil && tbs.Tag == asn1.TagSequence && tbs.Class == asn1.ClassUniversal
}

func (s *scanner) addCertificate(data []byte, collection *Collection, occurrence Occurrence) bool {
	if s.occurrences >= s.options.MaxCertificates {
		s.problem(collection, "certificate_limit", "certificate occurrence limit reached")
		return false
	}
	if err := s.ctx.Err(); err != nil {
		s.problem(collection, "canceled", err.Error())
		return false
	}
	sha := digest(data)
	if !s.identities[sha] {
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			if collection.Format == formatDER {
				if _, crlErr := x509.ParseRevocationList(data); crlErr == nil {
					return true
				}
			}
			s.problem(collection, codeMalformed, err.Error())
			return true
		}
		s.result.Certificates = append(s.result.Certificates, Certificate{
			SHA256: sha, SPKISHA256: digest(certificate.RawSubjectPublicKeyInfo),
			Subject: certificate.Subject.String(), Issuer: certificate.Issuer.String(),
			Serial: certificate.SerialNumber.Text(hexRadix), NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter,
			IsCA: certificate.IsCA, BasicConstraints: certificate.BasicConstraintsValid,
		})
		s.identities[sha] = true
	}
	occurrence.SHA256 = sha
	collection.Occurrences = append(collection.Occurrences, occurrence)
	s.occurrences++
	return true
}

func (s *scanner) problem(collection *Collection, code, message string) {
	collection.Complete = false
	s.diagnostic(collection.Location, code, message)
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func setDigest(occurrences []Occurrence) string {
	identities := certificateSet(occurrences)
	return digest([]byte(joinFingerprints(identities)))
}
