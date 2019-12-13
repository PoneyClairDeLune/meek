// meek-client is the client transport plugin for the meek pluggable transport.
//
// Sample usage in torrc:
// 	Bridge meek 0.0.2.0:1 url=https://forbidden.example/ front=allowed.example
// 	ClientTransportPlugin meek exec ./meek-client
// The transport ignores the bridge address 0.0.2.0:1 and instead connects to
// the URL given by url=. When front= is given, the domain in the URL is
// replaced by the front domain for the purpose of the DNS lookup, TCP
// connection, and TLS SNI, but the HTTP Host header in the request will be the
// one in url=.
//
// Most user configuration can happen either through SOCKS args (i.e., args on a
// Bridge line) or through command line options. SOCKS args take precedence
// per-connection over command line options. For example, this configuration
// using SOCKS args:
// 	Bridge meek 0.0.2.0:1 url=https://forbidden.example/ front=allowed.example
// 	ClientTransportPlugin meek exec ./meek-client
// is the same as this one using command line options:
// 	Bridge meek 0.0.2.0:1
// 	ClientTransportPlugin meek exec ./meek-client --url=https://forbidden.example/ --front=allowed.example
// The command-line configuration interface is for compatibility with tor 0.2.4
// and older, which doesn't support parameters on Bridge lines.
//
// The --helper option prevents this program from doing any network operations
// itself. Rather, it will send all requests through a browser extension that
// makes HTTP requests.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/lucas-clemente/quic-go"
)

const (
	ptMethodName = "meek"
	// Safety limits on interaction with the HTTP helper.
	maxHelperResponseLength = 10000000
	helperReadTimeout       = 60 * time.Second
	helperWriteTimeout      = 2 * time.Second

	// The ALPN field value for the tunnelled QUIC–TLS connection.
	quicNextProto = "meek-quic"
	// How long to wait for a handshake to complete at the inner QUIC layer.
	quicHandshakeTimeout = 30 * time.Second
	// How long before timing out connections at the inner QUIC layer.
	quicIdleTimeout = 30 * time.Minute
)

// We use this RoundTripper to make all our requests when neither --helper nor
// utls is in effect. We use the defaults, except we take control of the Proxy
// setting (notably, disabling the default ProxyFromEnvironment).
var httpRoundTripper *http.Transport = http.DefaultTransport.(*http.Transport)

// We use this RoundTripper when --helper is in effect.
var helperRoundTripper = &HelperRoundTripper{
	ReadTimeout:  helperReadTimeout,
	WriteTimeout: helperWriteTimeout,
}

// Store for command line options.
var options struct {
	URL                 string
	Front               string
	ProxyURL            *url.URL
	UseHelper           bool
	UTLSName            string
	QUICTLSPubkeyHashes []string
}

// urlAddr is a net.Addr representation of a url.URL.
type urlAddr struct{ *url.URL }

func (addr urlAddr) Network() string { return "url" }
func (addr urlAddr) String() string  { return addr.URL.String() }

// RequestInfo encapsulates all the configuration used for a request–response
// roundtrip, including variables that may come from SOCKS args or from the
// command line.
type RequestInfo struct {
	// The URL to request.
	URL *url.URL
	// The Host header to put in the HTTP request (optional and may be
	// different from the host name in URL).
	Host string
	// The RoundTripper to use to send requests. This may vary depending on
	// the value of global options like --helper.
	RoundTripper http.RoundTripper
}

func (info *RequestInfo) Poll(out io.Reader) (in io.ReadCloser, err error) {
	req, err := http.NewRequest("POST", info.URL.String(), out)
	// Prevent Content-Type sniffing by net/http and middleboxes.
	req.Header.Set("Content-Type", "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if info.Host != "" {
		req.Host = info.Host
	}
	if err != nil {
		return nil, err
	}
	resp, err := info.RoundTripper.RoundTrip(req)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("status code %d", resp.StatusCode)
	}
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Callback for new SOCKS requests.
func handleSOCKS(conn *pt.SocksConn) error {
	var info RequestInfo

	// First check url= SOCKS arg, then --url option.
	urlArg, ok := conn.Req.Args.Get("url")
	if ok {
	} else if options.URL != "" {
		urlArg = options.URL
	} else {
		return fmt.Errorf("no URL for SOCKS request")
	}
	var err error
	info.URL, err = url.Parse(urlArg)
	if err != nil {
		return err
	}

	// First check front= SOCKS arg, then --front option.
	front, ok := conn.Req.Args.Get("front")
	if ok {
	} else if options.Front != "" {
		front = options.Front
		ok = true
	}
	if ok {
		info.Host = info.URL.Host
		info.URL.Host = front
	}

	// First check utls= SOCKS arg, then --utls option.
	utlsName, utlsOK := conn.Req.Args.Get("utls")
	if utlsOK {
	} else if options.UTLSName != "" {
		utlsName = options.UTLSName
		utlsOK = true
	}

	var pubkeyHashes []string
	if arg, ok := conn.Req.Args["quic-tls-pubkey"]; ok {
		pubkeyHashes = arg
	} else {
		pubkeyHashes = options.QUICTLSPubkeyHashes
	}

	// First we check --helper: if it was specified, then we always use the
	// helper, and utls is disallowed. Otherwise, we use utls if requested;
	// or else fall back to native net/http.
	if options.UseHelper {
		if utlsOK {
			return fmt.Errorf("cannot use utls with --helper")
		}
		info.RoundTripper = helperRoundTripper
	} else if utlsOK {
		info.RoundTripper, err = NewUTLSRoundTripper(utlsName, nil, options.ProxyURL)
		if err != nil {
			return err
		}
	} else {
		info.RoundTripper = httpRoundTripper
	}

	// Each SOCKS connection corresponds to a single QUIC session with a
	// single stream inside it.
	pconn := NewPollingPacketConn(urlAddr{info.URL}, &info)
	defer pconn.Close()

	// The TLS configuration of the inner QUIC layer (this has nothing to do
	// with the domain-fronted outer HTTPS layer).
	tlsConfig := &tls.Config{
		// We set InsecureSkipVerify and VerifyPeerCertificate so as to
		// do our own certificate verification, using direct lookup
		// against the quic-tls-pubkey hashes rather than signatures by
		// root CAs.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: makeVerifyPeerPublicKey(pubkeyHashes),
		NextProtos:            []string{quicNextProto},
	}
	quicConfig := &quic.Config{
		HandshakeTimeout: quicHandshakeTimeout,
		IdleTimeout:      quicIdleTimeout,
	}
	sess, err := quic.Dial(pconn, pconn.RemoteAddr(), "", tlsConfig, quicConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	err = conn.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, stream)
		if err != nil {
			log.Printf("recv error: %v", err)
		}
		err = conn.Close()
		if err != nil {
			log.Printf("conn shutdown error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, conn)
		if err != nil {
			log.Printf("send error: %v", err)
		}
		err = stream.Close()
		if err != nil {
			log.Printf("stream close error: %v", err)
		}
	}()
	wg.Wait()

	return nil
}

func acceptSOCKS(ln *pt.SocksListener) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			log.Printf("error in AcceptSocks: %s", err)
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer conn.Close()
			err := handleSOCKS(conn)
			if err != nil {
				conn.Reject()
				log.Printf("error in handling request: %s", err)
			}
		}()
	}
	return nil
}

// Return an error if this proxy URL doesn't work with the rest of the
// configuration.
func checkProxyURL(u *url.URL) error {
	if !options.UseHelper {
		// Without the helper, we use net/http's built-in proxy support,
		// which allows "http", "https", and "socks5".
		// socks5 requires go1.9: https://golang.org/doc/go1.9#net/http
		// https requires go1.10: https://golang.org/doc/go1.10#net/http
		// If using an older version of Go, the proxy won't be bypassed;
		// you'll just get an error at connection time rather than
		// TOR_PT_PROXY time.
		switch u.Scheme {
		case "http", "https", "socks5":
		default:
			return fmt.Errorf("don't understand proxy URL scheme %q", u.Scheme)
		}
	} else {
		// With the helper we can use HTTP and SOCKS (because it is the
		// browser that does the proxying, not us).
		// For the HTTP proxy with the Firefox helper: versions of
		// Firefox before 32, and Tor Browser before 3.6.2, leak the
		// covert Host header in HTTP proxy CONNECT requests. Using an
		// HTTP proxy cannot provide effective obfuscation without such
		// a patched Firefox.
		// https://bugs.torproject.org/12146
		// https://gitweb.torproject.org/tor-browser.git/commit/?id=e08b91c78d919f66dd5161561ca1ad7bcec9a563
		// https://bugzilla.mozilla.org/show_bug.cgi?id=1017769
		// https://hg.mozilla.org/mozilla-central/rev/a1f6458800d4
		switch u.Scheme {
		case "http", "socks5", "socks4a":
		default:
			return fmt.Errorf("don't understand proxy URL scheme %q", u.Scheme)
		}
		if u.User != nil {
			return fmt.Errorf("a proxy URL with a username or password can't be used with --helper")
		}
	}
	return nil
}

func main() {
	var helperAddr string
	var logFilename string
	var quicTLSPubkey string
	var proxy string
	var err error

	flag.StringVar(&options.Front, "front", "", "front domain name if no front= SOCKS arg")
	flag.StringVar(&helperAddr, "helper", "", "address of HTTP helper (browser extension)")
	flag.StringVar(&logFilename, "log", "", "name of log file")
	flag.StringVar(&proxy, "proxy", "", "proxy URL")
	flag.StringVar(&quicTLSPubkey, "quic-tls-pubkey", "", "server public key hashes for QUIC TLS")
	flag.StringVar(&options.URL, "url", "", "URL to request if no url= SOCKS arg")
	flag.StringVar(&options.UTLSName, "utls", "", "uTLS Client Hello ID")
	flag.Parse()

	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatalf("error in ClientSetup: %s", err)
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			// If we fail to open the log, emit a message that will
			// appear in tor's log.
			pt.CmethodError(ptMethodName, fmt.Sprintf("error opening log file: %s", err))
			log.Fatalf("error opening log file: %s", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	if helperAddr != "" {
		options.UseHelper = true
		helperRoundTripper.HelperAddr, err = net.ResolveTCPAddr("tcp", helperAddr)
		if err != nil {
			log.Fatalf("can't resolve helper address: %s", err)
		}
		log.Printf("using helper on %s", helperRoundTripper.HelperAddr)
	}

	if proxy != "" {
		options.ProxyURL, err = url.Parse(proxy)
		if err != nil {
			log.Fatalf("can't parse proxy URL: %s", err)
		}
	}

	options.QUICTLSPubkeyHashes = strings.Split(quicTLSPubkey, ",")

	// Disable the default ProxyFromEnvironment setting.
	// httpRoundTripper.Proxy is overridden below if options.ProxyURL is
	// set.
	httpRoundTripper.Proxy = nil

	// Command-line proxy overrides managed configuration.
	if options.ProxyURL == nil {
		options.ProxyURL = ptInfo.ProxyURL
	}
	// Check whether we support this kind of proxy.
	if options.ProxyURL != nil {
		err = checkProxyURL(options.ProxyURL)
		if err != nil {
			pt.ProxyError(err.Error())
			log.Fatal(fmt.Sprintf("proxy error: %s", err))
		}
		log.Printf("using proxy %s", options.ProxyURL.String())
		httpRoundTripper.Proxy = http.ProxyURL(options.ProxyURL)
		if options.UseHelper {
			err = helperRoundTripper.SetProxy(options.ProxyURL)
			if err != nil {
				pt.ProxyError(err.Error())
				log.Fatal(fmt.Sprintf("proxy error: %s", err))
			}
		}
		if ptInfo.ProxyURL != nil {
			pt.ProxyDone()
		}
	}

	listeners := make([]net.Listener, 0)
	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case ptMethodName:
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			go acceptSOCKS(ln)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			log.Printf("listening on %s", ln.Addr())
			listeners = append(listeners, ln)
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			io.Copy(ioutil.Discard, os.Stdin)
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// Wait for a signal.
	sig := <-sigChan
	log.Printf("got signal %s", sig)

	for _, ln := range listeners {
		ln.Close()
	}

	log.Printf("done")
}
