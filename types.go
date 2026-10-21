// Package certs inventories certificates and certificate collections in files
// and archives. Presence does not establish application trust or usage.
package certs

import "time"

// Options bounds one scan, including all nested archives. Zero limits use defaults.
type Options struct {
	MaxInputBytes    int64
	MaxFileBytes     int64
	MaxExpandedBytes int64
	MaxEntries       int
	MaxDepth         int
	MaxCertificates  int
	MaxDiagnostics   int
	// A nil Catalog uses the built-in references; a zero PreparedCatalog disables matching.
	Catalog *PreparedCatalog
}

// Inventory retains certificate identities once and every occurrence in Collections.
type Inventory struct {
	Path         string        `json:"path"`
	SHA256       string        `json:"sha256,omitempty"`
	Size         int64         `json:"size"`
	Complete     bool          `json:"complete"`
	Files        int           `json:"files"`
	Certificates []Certificate `json:"certificates"`
	Collections  []Collection  `json:"collections"`
	Diagnostics  []Diagnostic  `json:"diagnostics"`
}

type Certificate struct {
	SHA256           string    `json:"sha256"`
	SPKISHA256       string    `json:"spki_sha256"`
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	Serial           string    `json:"serial"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	IsCA             bool      `json:"is_ca"`
	BasicConstraints bool      `json:"basic_constraints_valid"`
}

// Member paths are labels, never filesystem extraction destinations.
// Entry is a one-based archive ordinal, or zero for the input file.
type Member struct {
	Path  string `json:"path"`
	Entry int    `json:"entry,omitempty"`
}

type Collection struct {
	Location    []Member     `json:"location"`
	Format      string       `json:"format"`
	SHA256      string       `json:"sha256"`
	SetSHA256   string       `json:"set_sha256,omitempty"`
	Complete    bool         `json:"complete"`
	Integrity   string       `json:"integrity,omitempty"`
	Occurrences []Occurrence `json:"occurrences"`
	Matches     []Match      `json:"matches,omitempty"`
}

type Occurrence struct {
	SHA256    string   `json:"sha256"`
	Offset    *int64   `json:"offset,omitempty"`
	Alias     string   `json:"alias,omitempty"`
	EntryType string   `json:"entry_type,omitempty"`
	TrustOIDs []string `json:"trust_oids,omitempty"`
}

type Diagnostic struct {
	Location []Member `json:"location"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

// Reference describes observed bundle contents, not a trust policy.
type Reference struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	SHA256       string   `json:"sha256"`
	Certificates []string `json:"certificates"`
}

type Match struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Kind       string   `json:"kind"`
	Shared     int      `json:"shared"`
	Missing    []string `json:"missing,omitempty"`
	Additional []string `json:"additional,omitempty"`
}
