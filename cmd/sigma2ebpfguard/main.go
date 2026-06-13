// sigma2ebpfguard converts Sigma detection rules to ebpf-guard YAML format.
//
// Usage:
//
//	sigma2ebpfguard ./sigma-rules/ --out ./rules/imported/
//	sigma2ebpfguard rule.yml --validate
//	sigma2ebpfguard --dir ./sigma-rules/ --out ./out/
//	sigma2ebpfguard --dir ./sigma-rules/ --dry-run
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zugolO/ebpf-guard/internal/migration"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		outDir   string
		dryRun   bool
		dirArg   string
		validate bool
	)

	cmd := &cobra.Command{
		Use:   "sigma2ebpfguard [PATH]",
		Short: "Convert Sigma detection rules to ebpf-guard YAML format",
		Long: `sigma2ebpfguard converts Sigma open-standard detection rules (https://sigmahq.io)
to ebpf-guard correlator rule YAML.

The input PATH may be a single .yaml/.yml file or a directory. For directories,
all .yaml/.yml files found directly in the directory are processed.
Use --dir as an alternative to the positional argument.

Supported logsource categories:
  process_creation  → ebpf-guard syscall event
  network_connection → ebpf-guard network event
  file_event        → ebpf-guard file event
  dns_query         → ebpf-guard dns event

Supported modifiers: |contains, |startswith, |endswith, |re, |cidr, |all
Supported conditions: and, or, 1 of X*, all of X*

Examples:
  sigma2ebpfguard ./sigma-rules/ --out ./rules/imported/
  sigma2ebpfguard rule.yml --validate
  sigma2ebpfguard --dir ./rules/sigma/ --out ./converted/ --dry-run`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			var inputPath string
			switch {
			case dirArg != "":
				inputPath = dirArg
			case len(args) == 1:
				inputPath = args[0]
			default:
				return fmt.Errorf("input path is required — provide as positional argument or via --dir")
			}

			info, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("stat input path: %w", err)
			}

			imp := migration.NewSigmaImporter()

			var result *migration.SigmaImportResult
			if info.IsDir() {
				result, err = imp.ImportDir(inputPath)
			} else {
				result, err = imp.ImportFile(inputPath)
			}
			if err != nil {
				return fmt.Errorf("import sigma rules: %w", err)
			}

			fmt.Printf("sigma2ebpfguard import summary:\n")
			fmt.Printf("  Converted:   %d\n", result.Converted)
			fmt.Printf("  Unsupported: %d\n", result.Unsupported)
			fmt.Printf("  Disabled:    %d\n\n", result.Disabled)

			for _, r := range result.Results {
				indicator := "CONV"
				switch r.Status {
				case "converted":
				case "unsupported":
					indicator = "SKIP"
				case "disabled":
					indicator = "OFF"
				}
				fmt.Printf("  [%s] %s\n", indicator, r.SourceRule)
				for _, reason := range r.UnsupportedReasons {
					fmt.Printf("         reason: %s\n", reason)
				}
			}

			if validate {
				if result.Unsupported > 0 {
					return fmt.Errorf("validate: %d rule(s) could not be converted", result.Unsupported)
				}
				fmt.Printf("\nAll %d rule(s) converted successfully.\n", result.Converted)
				return nil
			}

			if outDir == "" && !dryRun {
				if result.Converted == 0 {
					fmt.Printf("\nNo rules were converted.\n")
					return nil
				}
				fmt.Printf("\nNo output directory specified. Use --out DIR to write converted rules.\n")
				return nil
			}

			out, err := imp.WriteOutput(result)
			if err != nil {
				return fmt.Errorf("serialize output: %w", err)
			}

			if dryRun {
				fmt.Printf("\n-- dry-run: not writing files --\n\n%s\n", string(out))
				return nil
			}

			if result.Converted == 0 {
				fmt.Printf("\nNo rules were converted.\n")
				return nil
			}

			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			// Use the source file name if converting a single file.
			outName := "sigma-imported.yaml"
			if !info.IsDir() {
				base := filepath.Base(inputPath)
				ext := filepath.Ext(base)
				outName = strings.TrimSuffix(base, ext) + "-imported.yaml"
			}

			outPath := filepath.Join(outDir, outName)
			if err := os.WriteFile(outPath, out, 0o640); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
			fmt.Printf("\nWritten %d rule(s) to %s\n", result.Converted, outPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outDir, "out", "o", "", "Output directory for converted rules")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print converted rules to stdout without writing files")
	cmd.Flags().StringVar(&dirArg, "dir", "", "Input directory with Sigma rule files (alternative to positional argument)")
	cmd.Flags().BoolVar(&validate, "validate", false, "Report unconvertible rules and exit non-zero if any are unsupported")

	return cmd
}
