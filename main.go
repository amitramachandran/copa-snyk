package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/amitramachandran/copa-snyk/snyk"
)

// Copa runs `copa-snyk <report-file>` and reads stdout and stderr together,
// so on success nothing but the manifest JSON may be written.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <snyk-json-report>\n", os.Args[0])
		os.Exit(1)
	}

	manifest, err := snyk.NewParser().Parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing snyk report: %v\n", err)
		os.Exit(1)
	}

	out, err := json.Marshal(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serializing manifest: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
