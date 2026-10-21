package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/git-pkgs/certs"
)

const (
	exitFailure     = 1
	exitIncomplete  = 2
	maxCatalogBytes = 8 << 20
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	status := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(status)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("certs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := certs.Options{}
	flags.Int64Var(&options.MaxInputBytes, "max-input-bytes", certs.DefaultMaxInputBytes, "Maximum bytes per input")
	flags.Int64Var(&options.MaxFileBytes, "max-file-bytes", certs.DefaultMaxFileBytes, "Maximum bytes parsed per certificate file or store")
	flags.Int64Var(&options.MaxExpandedBytes, "max-expanded-bytes", certs.DefaultMaxExpandedBytes, "Maximum cumulative archive member sizes, including nested containers")
	flags.IntVar(&options.MaxEntries, "max-entries", certs.DefaultMaxEntries, "Maximum archive entries and store bags")
	flags.IntVar(&options.MaxDepth, "max-depth", certs.DefaultMaxDepth, "Maximum archive and store nesting depth")
	flags.IntVar(&options.MaxCertificates, "max-certificates", certs.DefaultMaxCertificates, "Maximum certificate occurrences")
	flags.IntVar(&options.MaxDiagnostics, "max-diagnostics", certs.DefaultMaxDiagnostics, "Maximum diagnostics before an omission notice")
	catalogPath := flags.String("catalog", "", "JSON reference catalogue (replaces built-in references)")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: certs [options] file [file ...]\nOutputs one JSON inventory per input. Exit 2 indicates incomplete coverage.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitFailure
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return exitFailure
	}
	if *catalogPath != "" {
		catalog, err := readCatalog(*catalogPath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitFailure
		}
		options.Catalog, err = certs.PrepareCatalog(catalog)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitFailure
		}
	}
	encoder := json.NewEncoder(stdout)
	status := 0
	for _, path := range flags.Args() {
		result, err := certs.ScanFile(ctx, path, options)
		if result != nil {
			if encodeErr := encoder.Encode(result); encodeErr != nil {
				_, _ = fmt.Fprintln(stderr, encodeErr)
				return exitFailure
			}
			if !result.Complete && status == 0 {
				status = exitIncomplete
			}
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %v\n", path, err)
			status = exitFailure
		}
		if ctx.Err() != nil {
			break
		}
	}
	return status
}

func readCatalog(path string) ([]certs.Reference, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCatalogBytes {
		return nil, fmt.Errorf("catalog exceeds size limit")
	}
	var references []certs.Reference
	if err := json.Unmarshal(data, &references); err != nil {
		return nil, err
	}
	if references == nil {
		return nil, fmt.Errorf("catalog must be a JSON array")
	}
	return references, nil
}
