package main

import (
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var bad []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == "dist" || entry.Name() == ".git") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		formatted, err := format.Source(raw)
		if err != nil || string(formatted) != string(raw) {
			bad = append(bad, path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(bad) > 0 {
		fmt.Fprintln(os.Stderr, "Go files require gofmt:")
		for _, path := range bad {
			fmt.Fprintln(os.Stderr, path)
		}
		os.Exit(1)
	}
}
