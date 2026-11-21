package main

import (
  "os"
  "path/filepath"
  "testing"
)

func TestLintReportsDuplicatesAndEmptyValues(t *testing.T) {
  p := filepath.Join(t.TempDir(), ".env")
  if err := os.WriteFile(p, []byte("TOKEN=abc\\nTOKEN=def\\nEMPTY=\\n"), 0600); err != nil { t.Fatal(err) }
  if got := lint(p, map[string]bool{"MISSING": true}); got != 3 { t.Fatalf("got %d errors, want 3", got) }
}
