package certs_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/git-pkgs/certs"
)

func TestCatalogOverlapAndIncompleteEvidence(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	collection := certs.Collection{Complete: true, SHA256: a, Occurrences: []certs.Occurrence{{SHA256: a}, {SHA256: b}}}
	references := []certs.Reference{{Name: "one", Source: "fixture", SHA256: a, Certificates: []string{a, b}}, {Name: "two", Source: "fixture", Certificates: []string{a, c}}}
	matches := certs.MatchCollection(collection, references)
	if len(matches) != 2 || matches[0].Kind != "file" || matches[1].Kind != "overlap" {
		t.Fatal(matches)
	}
	if matches[1].Shared != 1 || matches[1].Missing[0] != c || matches[1].Additional[0] != b {
		t.Fatal(matches)
	}
	collection.Complete = false
	matches = certs.MatchCollection(collection, references)
	if matches[0].Kind != "overlap" {
		t.Fatal("incomplete membership reported as exact")
	}
}

func TestPreparedCatalogReuse(t *testing.T) {
	der := certificate(t, 1)
	fingerprint := sha(der)
	references := []certs.Reference{{Name: "fixture", Source: "test", Certificates: []string{fingerprint, fingerprint}}}
	prepared, err := certs.PrepareCatalog(references)
	if err != nil {
		t.Fatal(err)
	}
	references[0].Name = "changed"
	references[0].Certificates[0] = "invalid"
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			result, err := certs.Scan(context.Background(), "root", bytes.NewReader(der), certs.Options{Catalog: prepared})
			if err != nil || result == nil || len(result.Collections) != 1 {
				t.Errorf("scan: %+v, error: %v", result, err)
				return
			}
			matches := result.Collections[0].Matches
			if len(matches) != 1 || matches[0].Name != "fixture" || matches[0].Kind != "certificate_set" {
				t.Errorf("matches: %+v", matches)
			}
			matches = prepared.MatchCollection(result.Collections[0])
			if len(matches) != 1 || matches[0].Shared != 1 {
				t.Errorf("repeated match: %+v", matches)
			}
		})
	}
	wg.Wait()
	if _, err := certs.PrepareCatalog(references); err == nil {
		t.Fatal("invalid reference accepted")
	}
	result := scan(t, "root", der, certs.Options{Catalog: &certs.PreparedCatalog{}})
	if len(result.Collections) != 1 || len(result.Collections[0].Matches) != 0 {
		t.Fatal("zero prepared catalog should disable matching")
	}
}

func TestDefaultCatalogCopiesAndValidation(t *testing.T) {
	one := certs.DefaultCatalog()
	if len(one) < 2 {
		t.Fatal("expected known bundle references")
	}
	one[0].Certificates[0] = "modified"
	two := certs.DefaultCatalog()
	if two[0].Certificates[0] == "modified" {
		t.Fatal("shared catalogue storage")
	}
	result := scan(t, "empty", nil, certs.Options{})
	if !result.Complete {
		t.Fatal(result)
	}
}
