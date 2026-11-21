package main

import (
  "encoding/json"
  "flag"
  "fmt"
  "io"
  "net/http"
  "os"
  "strings"
  "time"
)

type Check struct {
  Name string `json:"name"`
  URL string `json:"url"`
  Method string `json:"method"`
  Headers map[string]string `json:"headers"`
  ExpectedStatus int `json:"expected_status"`
  ExpectedBodyContains string `json:"expected_body_contains"`
  TimeoutMS int `json:"timeout_ms"`
}
type Suite struct { Checks []Check `json:"checks"` }

func expand(s string) string {
  return os.Expand(s, func(k string) string { return os.Getenv(k) })
}
func run(path string) int {
  data, err := os.ReadFile(path)
  if err != nil { fmt.Fprintln(os.Stderr, err); return 1 }
  var suite Suite
  if err := json.Unmarshal(data, &suite); err != nil { fmt.Fprintf(os.Stderr, "suite must be JSON: %v\\n", err); return 1 }
  if len(suite.Checks) == 0 { fmt.Fprintln(os.Stderr, "suite has no checks"); return 1 }
  failures := 0
  for i, c := range suite.Checks {
    name := c.Name; if name == "" { name = fmt.Sprintf("check-%d", i+1) }
    method := c.Method; if method == "" { method = http.MethodGet }
    timeout := time.Duration(c.TimeoutMS) * time.Millisecond; if timeout <= 0 { timeout = 10 * time.Second }
    req, err := http.NewRequest(method, expand(c.URL), nil)
    if err != nil { fmt.Printf("FAIL %s: %v\\n", name, err); failures++; continue }
    for k, v := range c.Headers { req.Header.Set(k, expand(v)) }
    client := &http.Client{Timeout: timeout}
    resp, err := client.Do(req)
    if err != nil { fmt.Printf("FAIL %s: %v\\n", name, err); failures++; continue }
    body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20)); resp.Body.Close()
    expected := c.ExpectedStatus; if expected == 0 { expected = http.StatusOK }
    if readErr != nil { fmt.Printf("FAIL %s: response read: %v\\n", name, readErr); failures++; continue }
    if resp.StatusCode != expected { fmt.Printf("FAIL %s: status %d, expected %d\\n", name, resp.StatusCode, expected); failures++; continue }
    if c.ExpectedBodyContains != "" && !strings.Contains(string(body), c.ExpectedBodyContains) {
      fmt.Printf("FAIL %s: response body did not contain expected text\\n", name); failures++; continue
    }
    fmt.Printf("PASS %s (%d)\\n", name, resp.StatusCode)
  }
  fmt.Printf("%d check(s), %d failure(s)\\n", len(suite.Checks), failures)
  return failures
}
func main() {
  if len(os.Args) < 2 || os.Args[1] != "run" { fmt.Fprintln(os.Stderr, "usage: smoke-probe run --suite suite.json"); os.Exit(2) }
  fs := flag.NewFlagSet("run", flag.ExitOnError)
  suite := fs.String("suite", "", "path to JSON suite")
  _ = fs.Parse(os.Args[2:])
  if *suite == "" { fmt.Fprintln(os.Stderr, "--suite is required"); os.Exit(2) }
  if run(*suite) > 0 { os.Exit(1) }
}
