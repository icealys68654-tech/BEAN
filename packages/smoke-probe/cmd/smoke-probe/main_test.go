package main

import (
  "encoding/json"
  "testing"
)

func TestSuiteShape(t *testing.T) {
  var s Suite
  if err := json.Unmarshal([]byte(`{"checks":[{"url":"http://127.0.0.1:3000/api/health","expected_status":200}]}`), &s); err != nil { t.Fatal(err) }
  if len(s.Checks) != 1 || s.Checks[0].ExpectedStatus != 200 { t.Fatalf("unexpected suite: %#v", s) }
}
