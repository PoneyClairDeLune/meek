package main

import (
	"net/url"
	"testing"
)

// Test that addrForDial returns a numeric port number. It needs to be numeric
// because we pass it as part of the authority-form URL in HTTP proxy requests.
// https://tools.ietf.org/html/rfc7230#section-5.3.3 authority-form
// https://tools.ietf.org/html/rfc3986#section-3.2.3 port
func TestAddrForDial(t *testing.T) {
	// good tests
	for _, test := range []struct {
		URL  string
		Addr string
	}{
		{"http://example.com", "example.com:80"},
		{"http://example.com/", "example.com:80"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com:443/", "example.com:443"},
		{"ftp://example.com:21/", "example.com:21"},
	} {
		u, err := url.Parse(test.URL)
		if err != nil {
			panic(err)
		}
		addr, err := addrForDial(u)
		if err != nil {
			t.Errorf("%q → error %v", test.URL, err)
			continue
		}
		if addr != test.Addr {
			t.Errorf("%q → %q, expected %q", test.URL, addr, test.Addr)
		}
	}

	// bad tests
	for _, input := range []string{
		"example.com",
		"example.com:80",
		"ftp://example.com/",
	} {
		u, err := url.Parse(input)
		if err != nil {
			panic(err)
		}
		addr, err := addrForDial(u)
		if err == nil {
			t.Errorf("%q → %q, expected error", input, addr)
			continue
		}
	}
}
