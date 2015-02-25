package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"net/url"
	"testing"
)

// Write chunks and read them out again, and ensure that they match.
func roundTripChunked(t *testing.T, chunks [][]byte) {
	buf := &bytes.Buffer{}
	cr := newChunkedReader(buf)
	cw := newChunkedWriter(buf)

	var err error
	for _, chunk := range chunks {
		_, err = cw.Write(chunk)
		if err != nil {
			t.Errorf("error %v when writing %v", err, chunks)
			return
		}
	}
	err = cw.Terminate()
	if err != nil {
		t.Errorf("error %v when terminating %v", err, chunks)
		return
	}

	p, err := ioutil.ReadAll(cr)
	if err != nil {
		t.Errorf("error %v when reading %v", err, chunks)
		return
	}
	// Read again to make sure error is consistent.
	q, err := ioutil.ReadAll(cr)
	if len(q) != 0 {
		t.Errorf("reading after EOF yielded %v from %v", q, chunks)
	}
	if err != nil {
		t.Errorf("reading after EOF gave error %v from %v", err, chunks)
		return
	}

	expected := bytes.Join(chunks, []byte{})
	if !bytes.Equal(p, expected) {
		t.Errorf("received %v, expected %v", p, expected)
		return
	}
}

func randArray(n int) []byte {
	p := make([]byte, n)
	_, err := rand.Read(p)
	if err != nil {
		panic(err)
	}
	return p
}

func TestChunkedRoundtrip(t *testing.T) {
	roundTripChunked(t, [][]byte{})
	roundTripChunked(t, [][]byte{{}, {}, {}})
	roundTripChunked(t, [][]byte{[]byte("hello")})
	roundTripChunked(t, [][]byte{randArray(65535), randArray(65536), randArray(65537)})
}

func TestChunkedReader(t *testing.T) {
	tests := []struct {
		input    []byte
		err      error
		expected []byte
	}{
		{[]byte{0x01}, io.ErrUnexpectedEOF, []byte{}},
		{[]byte("\x00\x0ahello"), io.ErrUnexpectedEOF, []byte("hello")},
	}

	for _, test := range tests {
		cr := newChunkedReader(bytes.NewReader(test.input))
		p, err := ioutil.ReadAll(cr)
		if err != test.err {
			t.Errorf("reading from %v gave error %v, not %v", test.input, err, test.err)
		}
		if !bytes.Equal(p, test.expected) {
			t.Errorf("reading from %v returned %v, not %v", test.input, p, test.expected)
		}
	}
}

// Just remember when Close has been called.
type closer struct {
	io.Reader
	closed *bool
}

func (r *closer) Close() error {
	*r.closed = true
	return nil
}

// Check that chunkedReadCloser.Close also closes the underlying io.Reader.
func TestChunkedReadCloser(t *testing.T) {
	var closed bool
	cr := chunkedReadCloser{newChunkedReader(&closer{bytes.NewReader([]byte{}), &closed})}
	cr.Close()
	if !closed {
		t.Errorf("chunkedReadCloser did not close underlying io.Reader")
	}
}

func TestMakeProxySpec(t *testing.T) {
	badTests := [...]url.URL{
		{Scheme: "http"},
		{Scheme: "http", Host: ":"},
		{Scheme: "http", Host: "localhost"},
		{Scheme: "http", Host: "localhost:"},
		{Scheme: "http", Host: ":8080"},
		{Scheme: "http", Host: "localhost:https"},
		{Scheme: "http", Host: "localhost:8080", User: url.User("username")},
		{Scheme: "http", Host: "localhost:8080", User: url.UserPassword("username", "password")},
		{Scheme: "http", User: url.User("username"), Host: "localhost:8080"},
		{Scheme: "http", User: url.UserPassword("username", "password"), Host: "localhost:8080"},
		{Scheme: "http", Host: "localhost:-1"},
		{Scheme: "http", Host: "localhost:65536"},
		{Scheme: "socks5", Host: ":"},
		{Scheme: "socks4a", Host: ":"},
		// "socks" and "socks4" are unknown types.
		{Scheme: "socks", Host: "localhost:1080"},
		{Scheme: "socks4", Host: "localhost:1080"},
		{Scheme: "unknown", Host: "localhost:9999"},
	}
	goodTests := [...]struct {
		input    url.URL
		expected ProxySpec
	}{
		{
			url.URL{Scheme: "http", Host: "localhost:8080"},
			ProxySpec{"http", "localhost", 8080},
		},
		{
			url.URL{Scheme: "socks5", Host: "localhost:1080"},
			ProxySpec{"socks5", "localhost", 1080},
		},
		{
			url.URL{Scheme: "socks4a", Host: "localhost:1080"},
			ProxySpec{"socks4a", "localhost", 1080},
		},
	}

	for _, input := range badTests {
		_, err := makeProxySpec(&input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		spec, err := makeProxySpec(&test.input)
		if err != nil {
			t.Fatalf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if *spec != test.expected {
			t.Errorf("%q → %q (expected %q)", test.input, spec, test.expected)
		}
	}
}
