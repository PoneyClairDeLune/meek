package main

import (
	"os"
	"testing"
)

func TestGetProxyURL(t *testing.T) {
	badTests := [...]string{
		"bogus",
		"://localhost",
		"//localhost",
		"http:",
		"http:localhost",
	}
	goodTests := [...]struct {
		input, expected string
	}{
		{"http://localhost", "http://localhost"},
		{"http://localhost:3128", "http://localhost:3128"},
		{"http://localhost:3128/", "http://localhost:3128/"},
		{"http://localhost:3128/path", "http://localhost:3128/path"},
		{"http://user@localhost:3128", "http://user@localhost:3128"},
		{"http://user:password@localhost:3128", "http://user:password@localhost:3128"},
		{"unknown://localhost/whatever", "unknown://localhost/whatever"},
	}

	os.Clearenv()
	u, err := PtGetProxyURL()
	if err != nil {
		t.Errorf("empty environment unexpectedly returned an error: %s", err)
	}
	if u != nil {
		t.Errorf("empty environment returned %q", u)
	}

	for _, input := range badTests {
		os.Setenv("TOR_PT_PROXY", input)
		u, err = PtGetProxyURL()
		if err == nil {
			t.Errorf("TOR_PT_PROXY=%q unexpectedly succeeded and returned %q", input, u)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_PROXY", test.input)
		u, err := PtGetProxyURL()
		if err != nil {
			t.Errorf("TOR_PT_PROXY=%q unexpectedly returned an error: %s", test.input, err)
		}
		if u == nil || u.String() != test.expected {
			t.Errorf("TOR_PT_PROXY=%q → %q (expected %q)", test.input, u, test.expected)
		}
	}
}
