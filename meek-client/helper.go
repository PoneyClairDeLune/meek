package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The code in this file has to do with communication between meek-client and
// the meek-http-helper browser extension.

// chunkedReader decodes a stream, where each chunk of data is preceded by a
// 16-byte big-endian length. EOF is marked by a chunk of length 0.
type chunkedReader struct {
	io.Reader
	buf []byte
	err error
}

func newChunkedReader(r io.Reader) *chunkedReader {
	return &chunkedReader{r, nil, nil}
}

// Read from a chunked stream. Returns io.EOF after reading a chunk length of 0.
// If there is an io.EOF in the underlying io.Reader, returns
// io.ErrUnexpectedEOF.
func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	if len(r.buf) == 0 {
		// Refill the buffer.
		var length uint16
		r.err = binary.Read(r.Reader, binary.BigEndian, &length)
		if r.err == io.EOF {
			r.err = io.ErrUnexpectedEOF
		}
		if r.err != nil {
			return 0, r.err
		}

		if length == 0 {
			r.err = io.EOF
			return 0, r.err
		}

		var n int
		r.buf = make([]byte, length)
		n, r.err = io.ReadFull(r.Reader, r.buf)
		r.buf = r.buf[:n]
		if r.err == io.EOF {
			r.err = io.ErrUnexpectedEOF
		}
	}

	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, r.err
}

// chunkedReadCloser adds a Close method to chunkedReader, if the
// chunkedReader's underlying io.Reader is an io.Closer.
type chunkedReadCloser struct {
	*chunkedReader
}

func (rc *chunkedReadCloser) Close() error {
	if r, ok := rc.chunkedReader.Reader.(io.Closer); ok {
		return r.Close()
	}
	return nil
}

// chunkedWriter encodes a stream, where each chunk of data is preceded by a
// 16-byte big-endian length.
type chunkedWriter struct {
	io.Writer
}

func newChunkedWriter(w io.Writer) *chunkedWriter {
	return &chunkedWriter{w}
}

// Write to a chunked stream.
func (w *chunkedWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		err := binary.Write(w.Writer, binary.BigEndian, uint16(len(chunk)))
		if err != nil {
			return n, err
		}
		_, err = w.Writer.Write(chunk)
		p = p[len(chunk):]
		n += len(chunk)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Write the EOF marker, a chunk with length 0. You can do further Write calls
// after calling this function in order to start a new chunked stream.
func (w *chunkedWriter) Terminate() error {
	return binary.Write(w.Writer, binary.BigEndian, uint16(0))
}

// Calls Terminate after calling Write.
func (w *chunkedWriter) WriteAndTerminate(p []byte) (int, error) {
	n, err := w.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.Terminate()
}

type JSONRequest struct {
	Method string            `json:"method,omitempty"`
	URL    string            `json:"url,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Proxy  *ProxySpec        `json:"proxy,omitempty"`
}

type JSONResponse struct {
	Error  string `json:"error,omitempty"`
	Status int    `json:"status"`
}

// ProxySpec encodes information we need to connect through a proxy.
type ProxySpec struct {
	// Acceptable values for Type are as in proposal 232: "http", "socks5",
	// or "socks4a".
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Return a ProxySpec suitable for the proxy URL in u.
func makeProxySpec(u *url.URL) (*ProxySpec, error) {
	spec := new(ProxySpec)
	var err error
	var portStr string
	var port uint64

	if u == nil {
		// No proxy.
		return nil, nil
	}

	// Firefox's nsIProxyInfo doesn't allow credentials.
	if u.User != nil {
		return nil, fmt.Errorf("proxy URLs with a username or password can't be used with the helper")
	}

	switch u.Scheme {
	case "http", "socks5", "socks4a":
		spec.Type = u.Scheme
	default:
		return nil, fmt.Errorf("unknown scheme")
	}

	spec.Host, portStr, err = net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	if spec.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	spec.Port = int(port)

	return spec, nil
}

// Do an HTTP roundtrip through the configured browser extension, using the
// payload data in buf and the request metadata in info.
func roundTripWithHelper(buf []byte, info *RequestInfo) (*http.Response, error) {
	s, err := net.DialTCP("tcp", nil, options.HelperAddr)
	if err != nil {
		return nil, err
	}

	// Encode our JSON.
	req := JSONRequest{
		Method: "POST",
		URL:    info.URL.String(),
		Header: make(map[string]string),
	}
	req.Header["X-Session-Id"] = info.SessionID
	if info.Host != "" {
		req.Header["Host"] = info.Host
	}
	req.Proxy, err = makeProxySpec(options.ProxyURL)
	if err != nil {
		return nil, err
	}
	encReq, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}
	// log.Printf("encoded %s", encReq)

	// Send the request.
	s.SetWriteDeadline(time.Now().Add(helperWriteTimeout))
	cw := newChunkedWriter(s)
	_, err = cw.WriteAndTerminate(encReq)
	if err != nil {
		return nil, err
	}
	cw = newChunkedWriter(s)
	_, err = cw.WriteAndTerminate(buf)
	if err != nil {
		return nil, err
	}

	// Read the response.
	cr := newChunkedReader(io.LimitReader(s, maxHelperResponseLength))
	encResp, err := ioutil.ReadAll(cr)
	if err != nil {
		return nil, err
	}
	// log.Printf("received %s", encResp)

	// Decode their JSON.
	var jsonResp JSONResponse
	err = json.Unmarshal(encResp, &jsonResp)
	if err != nil {
		return nil, err
	}
	if jsonResp.Error != "" {
		return nil, fmt.Errorf("helper returned error: %s", jsonResp.Error)
	}

	// Mock up an HTTP response.
	resp := http.Response{
		Status:     http.StatusText(jsonResp.Status),
		StatusCode: jsonResp.Status,
		Body:       &chunkedReadCloser{newChunkedReader(s)},
	}
	return &resp, nil
}
