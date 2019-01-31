package main

import (
	"net/http"
	"testing"
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
