# certs

A pure Go library and CLI for inventorying X.509 certificates in local files and
package archives. Detects PEM, DER, JKS and readable PKCS#12 certificate bags by
content, preserves duplicate occurrences, and matches known CA bundles. Scans
run offline without CGo or native libraries.

## Installation

Build and install the CLI from this checkout:

```bash
CGO_ENABLED=0 go install ./cmd/certs
```

## Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/git-pkgs/certs"
)

func main() {
    result, err := certs.ScanFile(context.Background(), "package.whl", certs.Options{})
    if result != nil {
        for _, certificate := range result.Certificates {
            fmt.Println(certificate.Subject, certificate.SHA256, certificate.SPKISHA256)
        }
        for _, collection := range result.Collections {
            fmt.Println(collection.Location, collection.Format, collection.SetSHA256)
        }
    }
    if err != nil {
        log.Fatal(err)
    }
}
```

`Scan(ctx, name, reader, options)` accepts caller-supplied content and leaves the
reader open. `ScanFile` accepts regular files and rejects symlink inputs. Unix
opens use no-follow and nonblocking flags; Windows opens reparse points directly.
Both check the opened file's type and identity against the initial path lookup.
Other platforms can use `Scan`; `ScanFile` returns an unsupported-operation error.

Scans have independent state and can run concurrently with separate readers.
Prepared catalogues are immutable and can be shared between scans. The library does not
enumerate registries or download packages; callers can attach package coordinates
to each returned inventory.

## CLI

```bash
certs roots.pem application.jar package.whl
certs -catalog references.json bundle.pem.gz
certs -max-file-bytes 33554432 package.whl
certs -help
```

Output is JSON Lines, with one inventory per input. Place flags before input
paths, and use `--` before paths starting with a dash. Diagnostics appear inside
the inventory; command errors go to stderr. Partial results remain on stdout.

| Exit status | Meaning |
|---|---|
| 0 | Complete scans |
| 2 | Incomplete coverage |
| 1 | Input, configuration or output error |

## Results

Certificate identities appear once in `certificates`. Each collection retains
every occurrence by certificate fingerprint, including duplicates. Locations
contain the input path and each nested member path, with a one-based archive
entry ordinal to distinguish repeated paths. Offsets are bytes within the member.
Archive paths are labels and are never extracted to disk.

Certificate fingerprints are SHA-256 hashes of the original DER certificate.
SPKI hashes cover the original DER SubjectPublicKeyInfo, including its sequence
wrapper. Collection set hashes cover sorted, unique lowercase certificate
fingerprints joined with a newline and no trailing newline. Equivalent sets can
be found despite renamed files, reordered bundles or repeated certificates.

JKS aliases and entry types distinguish trusted-certificate entries from chains
attached to private-key entries. PKCS#12 certificate bags retain aliases and Java
trust-purpose attributes. Keys are neither decoded nor reported. Store integrity
is recorded as unchecked or absent; certificate presence and equal membership
do not establish application usage, trust policy or vulnerability.

## Catalogue matching

The built-in catalogue includes certifi 2026.10.19 and curl snapshots from
2026-10-20 and 2026-09-25. [catalog.json](catalog.json) records source locations,
file digests and certificate fingerprints. Historical snapshots remain useful
for identifying vendored copies.

Matches distinguish identical file bytes (`file`), identical certificate sets
(`certificate_set`), and shared membership (`overlap`). Overlap results include
shared counts, missing certificates and additional certificates. Multiple sources
can match; these comparisons provide provenance candidates. Incomplete collections
only produce overlap matches.

Call `MatchCollection(collection, references)` to apply new reference data without
rescanning files. `DefaultCatalog()` returns an independent copy of the bundled
references. Scans share a cached, validated default catalogue. Call
`PrepareCatalog(references)` once and pass the result as `Options.Catalog` to use
custom references. Prepared catalogues copy their inputs and support concurrent
scans and `MatchCollection` calls. A nil `Catalog` selects the built-in references;
`&PreparedCatalog{}` disables matching. The CLI prepares `-catalog` references
once for all input files.

A custom catalogue replaces the built-in references. Each JSON entry has `name`,
`source`, `sha256` for the bundle file, and `certificates`, an array of lowercase
certificate SHA-256 fingerprints. The file hash can be empty when only membership
is known. An empty JSON array disables matching.

## Supported formats

- PEM certificates and bundles, including OpenSSL `TRUSTED CERTIFICATE` blocks
- DER certificates and concatenated collections
- JKS trusted-certificate entries and key-associated certificate chains
- Readable PKCS#12 certificate bags
- ZIP-based wheels, JARs and NuGet packages; TAR, gem, Hex and conda archives
- gzip, bzip2, xz and zstd compressed TAR or single files

Nested archives use `git-pkgs/archives`. Gem and conda wrappers use their packaging
extensions. Compressed single files expose a member named `content`. Failed ZIP
members produce diagnostics while later members remain available; errors in
sequential archive formats may prevent further traversal.

Encrypted PKCS#12 contents are detected but not decrypted. Readable bags in the
same store are still inventoried. JCEKS, unsupported PEM containers such as
PKCS#7, and OpenSSL auxiliary trust attributes produce coverage diagnostics.
Malformed certificates do not discard later PEM blocks or recovered identities.
PEM blocks outside the supported certificate labels and known certificate
containers are skipped. CRLs are skipped in both PEM and DER encodings. Explicit
ellipsis placeholders in documentation are ignored; actual certificates in
documentation are inventoried. PEM headers must start a line apart from whitespace;
headers prefixed with source-comment markers are skipped.

Generated source lists are supported for Node-style adjacent quoted PEM strings
and Rust `CertificateDer::from_slice(b"...")` byte literals, including renamed
files and archive members. Collections use format `source`; occurrences identify
the encoding as `c-string-pem` or `rust-byte-der`. Offsets point to the opening
quote of a PEM string group or the Rust constructor in the original file. File
hashes cover the original source bytes, while certificate and SPKI hashes cover
the decoded DER. Comments are skipped and source code is never executed.

This supports the literal syntax in Node's generated root header and
`webpki-root-certs`. Arbitrary expressions, includes, macros and other source
encodings are not evaluated. Recognized certificate literals with invalid or
unsupported syntax produce diagnostics. Preprocessor conditions are not evaluated;
presence does not establish that a certificate is included in a particular build.

`magic` identifies PNG, JPEG, GIF, PDF and Java class files so they can be skipped before
certificate buffering. Embedded material in those formats is outside this scan.
Native binaries, WebAssembly and static libraries are skipped with diagnostics;
compiled trust anchors, stripped `webpki-roots` anchors and other encoded source
literals are not decoded. Unrecognized
binary or ASN.1 content, archive links, unsupported stores and limits also make
`complete` false. This field describes parser coverage, not runtime trust or the
absence of every possible certificate representation.

## Limits

Zero options select these defaults; negative limits are rejected:

| Option | Default |
|---|---|
| `MaxInputBytes` | 512 MiB of input |
| `MaxFileBytes` | 16 MiB per certificate file or store |
| `MaxExpandedBytes` | 1 GiB of cumulative archive member sizes |
| `MaxEntries` | 100,000 archive entries and store records |
| `MaxDepth` | 8 archive levels; 8 PKCS#12 bag levels |
| `MaxCertificates` | 100,000 certificate occurrences |
| `MaxDiagnostics` | 1,000 diagnostics, followed by an omission notice |

Expansion and entry limits are shared across nesting. Entries skipped by ZIP
metadata still count toward entry limits but are not decompressed or charged
against the expansion budget. Other skipped bodies count toward expansion limits.
Expanded bytes count both nested containers and their contents; unknown sizes are
counted during reading. ZIP and conda readers buffer compressed input. Individual
candidate files are buffered within `MaxFileBytes`; decoder workspace and inventory
metadata require additional memory. These limits are not a total heap cap.

Archive limits produce incomplete inventories, including when an unknown-sized
compressed member reaches a limit during reading. A nested archive limit allows
outer traversal to continue while shared budget remains. Oversized unread ZIP
members are skipped so smaller siblings can use the remaining budget. TAR-based
formats stop at oversized entries because traversal requires reading their bodies.
The remaining raw input is read within `MaxInputBytes` to finish its hash.
Exceeding `MaxInputBytes` produces `input_limit`, exit 2 and no full-input hash;
input read failures and cancellation still return errors.

At the diagnostic cap, parsing and read errors replace routine coverage notices
before being omitted. An omission notice records dropped diagnostics. The input
digest is emitted only after consuming the entire input, including compressed
bytes and trailing data. Context cancellation is checked between reads and parsing
steps; it cannot interrupt a caller's already-blocked `Read`.

## Development

```bash
make test
make lint
make bench
make fuzz
```

`CGO_ENABLED=0 go test ./...` exercises the suite without CGo. Go's race detector
uses a separate CGo-enabled test build.

## License

[MIT](LICENSE).
