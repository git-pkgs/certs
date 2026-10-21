package certs

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
)

//go:embed catalog.json
var catalogJSON []byte

// PreparedCatalog is immutable and safe to share between concurrent scans.
// Its zero value disables matching.
type PreparedCatalog struct {
	references []Reference
}

// PrepareCatalog validates and copies references for reuse across scans.
func PrepareCatalog(references []Reference) (*PreparedCatalog, error) {
	if err := validateCatalog(references); err != nil {
		return nil, err
	}
	return &PreparedCatalog{references: normalizeCatalog(references)}, nil
}

// MatchCollection compares a collection against the prepared references.
func (c *PreparedCatalog) MatchCollection(collection Collection) []Match {
	return matchCollection(collection, c.references)
}

var defaultCatalog = sync.OnceValue(func() *PreparedCatalog {
	var references []Reference
	if err := json.Unmarshal(catalogJSON, &references); err != nil {
		panic(err)
	}
	catalog, err := PrepareCatalog(references)
	if err != nil {
		panic(err)
	}
	return catalog
})

// DefaultCatalog returns an independent copy of the bundled reference data.
func DefaultCatalog() []Reference {
	return normalizeCatalog(defaultCatalog().references)
}

func normalizeCatalog(references []Reference) []Reference {
	normalized := slices.Clone(references)
	for i := range normalized {
		fingerprints := slices.Clone(normalized[i].Certificates)
		if !slices.IsSorted(fingerprints) {
			slices.Sort(fingerprints)
		}
		normalized[i].Certificates = slices.Compact(fingerprints)
	}
	return normalized
}

// MatchCollection compares observed membership without inferring origin or use.
// Incomplete collections can only produce overlap matches.
func MatchCollection(collection Collection, references []Reference) []Match {
	return matchCollection(collection, normalizeCatalog(references))
}

func matchCollection(collection Collection, references []Reference) []Match {
	observed := certificateSet(collection.Occurrences)
	var matches []Match
	for _, reference := range references {
		match := compareSets(observed, reference.Certificates)
		if match.Shared == 0 {
			continue
		}
		match.Name, match.Source, match.Kind = reference.Name, reference.Source, "overlap"
		if collection.Complete && len(match.Missing) == 0 && len(match.Additional) == 0 {
			match.Kind = "certificate_set"
			if collection.SHA256 == reference.SHA256 {
				match.Kind = "file"
			}
		}
		matches = append(matches, match)
	}
	return matches
}

func compareSets(observed, expected []string) Match {
	var result Match
	for _, fingerprint := range observed {
		if _, found := slices.BinarySearch(expected, fingerprint); found {
			result.Shared++
		} else {
			result.Additional = append(result.Additional, fingerprint)
		}
	}
	for _, fingerprint := range expected {
		if _, found := slices.BinarySearch(observed, fingerprint); !found {
			result.Missing = append(result.Missing, fingerprint)
		}
	}
	return result
}

func certificateSet(occurrences []Occurrence) []string {
	identities := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		identities = append(identities, occurrence.SHA256)
	}
	slices.Sort(identities)
	return slices.Compact(identities)
}

func joinFingerprints(identities []string) string {
	return strings.Join(identities, "\n")
}

func validateCatalog(references []Reference) error {
	for _, reference := range references {
		if reference.Name == "" || reference.Source == "" {
			return fmt.Errorf("catalog references require a name and source")
		}
		fingerprints := slices.Clone(reference.Certificates)
		if reference.SHA256 != "" {
			fingerprints = append(fingerprints, reference.SHA256)
		}
		for _, value := range fingerprints {
			if len(value) != 64 || strings.ToLower(value) != value {
				return fmt.Errorf("catalog %q: expected a lowercase SHA-256 digest", reference.Name)
			}
			if _, err := hex.DecodeString(value); err != nil {
				return fmt.Errorf("catalog %q: %w", reference.Name, err)
			}
		}
	}
	return nil
}
