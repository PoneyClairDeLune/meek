package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestCopyPublicFieldsHTTPTransport(t *testing.T) {
	src := http.DefaultTransport.(*http.Transport)
	dst := &http.Transport{}
	copyPublicFields(dst, src)
	// Test various fields that we might care about a copy of http.Transport
	// having.
	if dst.DisableKeepAlives != src.DisableKeepAlives {
		t.Errorf("mismatch on DisableKeepAlives")
	}
	if dst.DisableCompression != src.DisableCompression {
		t.Errorf("mismatch on DisableCompression")
	}
	if dst.MaxIdleConns != src.MaxIdleConns {
		t.Errorf("mismatch on MaxIdleConns")
	}
	if dst.MaxIdleConnsPerHost != src.MaxIdleConnsPerHost {
		t.Errorf("mismatch on MaxIdleConnsPerHost")
	}
	if dst.MaxConnsPerHost != src.MaxConnsPerHost {
		t.Errorf("mismatch on MaxConnsPerHost")
	}
	if dst.IdleConnTimeout != src.IdleConnTimeout {
		t.Errorf("mismatch on IdleConnTimeout")
	}
	if dst.ResponseHeaderTimeout != src.ResponseHeaderTimeout {
		t.Errorf("mismatch on ResponseHeaderTimeout")
	}
	if dst.ExpectContinueTimeout != src.ExpectContinueTimeout {
		t.Errorf("mismatch on ExpectContinueTimeout")
	}
	if dst.MaxResponseHeaderBytes != src.MaxResponseHeaderBytes {
		t.Errorf("mismatch on MaxResponseHeaderBytes")
	}
}

// Return a byte slice which is the ClientHello sent when rt does a RoundTrip.
// Opens a temporary listener on an ephemeral port on localhost. The host you
// provide can be an IP address like "127.0.0.1" or a name like "localhost", but
// it has to resolve to localhost.
func clientHelloResultingFromRoundTrip(t *testing.T, host string, rt *UTLSRoundTripper) ([]byte, error) {
	ch := make(chan []byte, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	go func() {
		defer func() {
			close(ch)
		}()
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- buf[:n]
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return nil, err
	}
	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
	}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	// The RoundTrip fails because the goroutine "server" hangs up. So
	// ignore an EOF error.
	_, err = rt.RoundTrip(req)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return <-ch, nil
}

func TestUTLSServerName(t *testing.T) {
	const clientHelloIDName = "HelloFirefox_63"

	// No ServerName, dial IP address. Results in an invalid server_name
	// extension with a 0-length host_name. Not sure if that's what it
	// should do, but check if the behavior ever changes.
	rt, err := NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	buf, err := clientHelloResultingFromRoundTrip(t, "127.0.0.1", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x05\x00\x03\x00\x00\x00")) {
		t.Errorf("expected 0-length server_name extension with no ServerName and IP address dial")
	}

	// No ServerName, dial hostname. server_name extension should come from
	// the dial address.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "localhost", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x09localhost")) {
		t.Errorf("expected \"localhost\" server_name extension with no ServerName and hostname dial")
	}

	// Given ServerName, dial IP address. server_name extension should from
	// the ServerName.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true, ServerName: "test.example"}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "127.0.0.1", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x11\x00\x0f\x00\x00\x0ctest.example")) {
		t.Errorf("expected \"test.example\" server_name extension with given ServerName and IP address dial")
	}

	// Given ServerName, dial hostname. server_name extension should from
	// the ServerName.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true, ServerName: "test.example"}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "localhost", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x11\x00\x0f\x00\x00\x0ctest.example")) {
		t.Errorf("expected \"test.example\" server_name extension with given ServerName and hostname dial")
	}
}
