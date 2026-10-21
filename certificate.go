package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

func inventoryCertificate(data []byte) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(data)
	if err == nil {
		return certificate, nil
	}
	var outer, tbs, field asn1.RawValue
	if rest, parseErr := asn1.Unmarshal(data, &outer); parseErr != nil || len(rest) != 0 {
		return nil, err
	}
	if _, parseErr := asn1.Unmarshal(outer.Bytes, &tbs); parseErr != nil {
		return nil, err
	}
	rest, parseErr := asn1.Unmarshal(tbs.Bytes, &field)
	if parseErr != nil {
		return nil, err
	}
	offset := len(outer.FullBytes) - len(outer.Bytes) + len(tbs.FullBytes) - len(tbs.Bytes)
	if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
		offset += len(field.FullBytes)
		if _, parseErr = asn1.Unmarshal(rest, &field); parseErr != nil {
			return nil, err
		}
	}
	var serial *big.Int
	if _, parseErr = asn1.Unmarshal(field.FullBytes, &serial); parseErr != nil || serial.Sign() >= 0 {
		return nil, err
	}
	offset += len(field.FullBytes) - len(field.Bytes)
	// Parse legacy serials without changing process-wide x509 policy. Only the
	// serial is substituted; all original signed bytes are restored afterward.
	positive := bytes.Clone(data)
	positive[offset] = 1
	certificate, parseErr = x509.ParseCertificate(positive)
	if parseErr != nil {
		return nil, parseErr
	}
	certificate.SerialNumber = serial
	certificate.Raw = data
	certificate.RawTBSCertificate = tbs.FullBytes
	return certificate, nil
}
