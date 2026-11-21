package main

import (
  "bufio"
  "flag"
  "fmt"
  "os"
  "regexp"
  "strings"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func lint(path string, required map[string]bool) int {
  f, err := os.Open(path)
  if err != nil { fmt.Fprintf(os.Stderr, "%s: %v\n", path, err); return 1 }
  defer f.Close()
  seen := map[string]int{}
  failed := 0
  scanner := bufio.NewScanner(f)
  line := 0
  for scanner.Scan() {
    line++
    raw := strings.TrimSpace(scanner.Text())
    if raw == "" || strings.HasPrefix(raw, "#") { continue }
    raw = strings.TrimSpace(strings.TrimPrefix(raw, "export "))
    key, value, ok := strings.Cut(raw, "=")
    key, value = strings.TrimSpace(key), strings.TrimSpace(value)
    if !ok || !keyPattern.MatchString(key) {
      fmt.Printf("%s:%d: invalid assignment\n", path, line); failed++; continue
    }
    if previous, exists := seen[key]; exists {
      fmt.Printf("%s:%d: duplicate key %s (first at line %d)\n", path, line, key, previous); failed++
    } else { seen[key] = line }
    if value == "" {
      fmt.Printf("%s:%d: %s has an empty value\n", path, line, key); failed++
    }
  }
  if err := scanner.Err(); err != nil { fmt.Fprintf(os.Stderr, "%s: read error: %v\n", path, err); failed++ }
  for key := range required {
    if _, ok := seen[key]; !ok { fmt.Printf("%s: required key %s is missing\n", path, key); failed++ }
  }
  if failed == 0 { fmt.Printf("%s: OK (%d keys)\n", path, len(seen)) }
  return failed
}

func main() {
  requiredFlag := flag.String("required", "", "comma-separated required keys")
  flag.Parse()
  files := flag.Args()
  if len(files) == 0 { files = []string{".env"} }
  required := map[string]bool{}
  for _, k := range strings.Split(*requiredFlag, ",") { if k = strings.TrimSpace(k); k != "" { required[k] = true } }
  failures := 0
  for _, path := range files { failures += lint(path, required) }
  if failures > 0 { os.Exit(1) }
}
