// meek-server is the server transport plugin for the meek pluggable transport.
// It acts as an HTTP server, keeps track of session ids, and forwards received
// data to a local OR port.
//
// Sample usage in torrc:
// 	ServerTransportListenAddr meek 0.0.0.0:443
// 	ServerTransportPlugin meek exec ./meek-server --acme-hostnames meek-server.example --acme-email admin@meek-server.example --log meek-server.log
// Using your own TLS certificate:
// 	ServerTransportListenAddr meek 0.0.0.0:8443
// 	ServerTransportPlugin meek exec ./meek-server --cert cert.pem --key key.pem --log meek-server.log
// Plain HTTP usage:
// 	ServerTransportListenAddr meek 0.0.0.0:8080
// 	ServerTransportPlugin meek exec ./meek-server --disable-tls --log meek-server.log
//
// The server runs in HTTPS mode by default, getting certificates from Let's
// Encrypt automatically. The server opens an auxiliary ACME listener on port 80
// in order for the automatic certificates to work. If you have your own
// certificate, use the --cert and --key options. Use --disable-tls option to
// run with plain HTTP.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/meek.git/common/encapsulation"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

const (
	programVersion = "0.34"

	ptMethodName = "meek"
	// The largest request body we are willing to process, and the largest
	// chunk of data we'll send back in a response.
	maxPayloadLength = 0x10000
	// How long we try to read from the OR port before closing a response.
	turnaroundTimeout = 10 * time.Millisecond
	// Passed as ReadTimeout and WriteTimeout when constructing the
	// http.Server.
	readWriteTimeout = 20 * time.Second
	// How long to wait for ListenAndServe or ListenAndServeTLS to return an
	// error before deciding that it's not going to return.
	listenAndServeErrorTimeout = 100 * time.Millisecond

	// The ALPN field value for the tunnelled QUIC–TLS connection.
	quicNextProto = "meek-quic"
	// How long to wait for a handshake to complete at the inner QUIC layer.
	quicHandshakeTimeout = 30 * time.Second
	// How long before timing out connections at the inner QUIC layer.
	quicIdleTimeout = 30 * time.Minute
)

var ptInfo pt.ServerInfo

func httpBadRequest(w http.ResponseWriter) {
	http.Error(w, "Bad request.", http.StatusBadRequest)
}

func httpInternalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal server error.", http.StatusInternalServerError)
}

// There is one state per HTTP listener. In the usual case there is just one
// listener, so there is just one global state. State also serves as the http
// Handler.
type State struct {
	conn *QueuePacketConn
}

func NewState(
	localAddr net.Addr,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) (*State, error) {
	pconn := NewQueuePacketConn(localAddr, quicIdleTimeout)

	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
		NextProtos:   []string{quicNextProto},
	}
	quicConfig := &quic.Config{
		HandshakeTimeout: quicHandshakeTimeout,
		IdleTimeout:      quicIdleTimeout,
	}
	ln, err := quic.Listen(pconn, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	go func() {
		defer ln.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := acceptSessions(ctx, ln)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	return &State{pconn}, nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		state.Get(w, req)
	case "POST":
		state.Post(w, req)
	default:
		httpBadRequest(w)
	}
}

// Handle a GET request. This doesn't have any purpose apart from diagnostics.
func (state *State) Get(w http.ResponseWriter, req *http.Request) {
	if path.Clean(req.URL.Path) != "/" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("I’m just a happy little web server.\n"))
}

// scrubbedAddr is a phony net.Addr that returns "[scrubbed]" for all calls.
type scrubbedAddr struct{}

func (a scrubbedAddr) Network() string { return "[scrubbed]" }
func (a scrubbedAddr) String() string  { return "[scrubbed]" }

// Replace the Addr in a net.OpError with "[scrubbed]" for logging.
func scrubError(err error) error {
	if err, ok := err.(*net.OpError); ok {
		// net.OpError contains Op, Net, Addr, and a subsidiary Err. The
		// (Op, Net, Addr) part is responsible for error text prefixes
		// like "read tcp X.X.X.X:YYYY:". We want that information but
		// don't want to log the literal address.
		err.Addr = scrubbedAddr{}
	}
	return err
}

// Handle a POST request.
func (state *State) Post(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body := http.MaxBytesReader(w, req.Body, maxPayloadLength+1)

	var clientID ClientID
	_, err := io.ReadFull(body, clientID[:])
	if err != nil {
		// The request body didn't even contain enough bytes for the
		// ClientID. This could be because the client is shaping its
		// request sizes, or we're being talked to by a non-meek client,
		// or a receive error occurred. In any case, we cannot proceed
		// without a ClientID. We could do something like send padding
		// here.
		return
	}

	// Read incoming packets.
	for {
		p, err := encapsulation.ReadData(body)
		if err != nil {
			break
		}
		state.conn.QueueIncoming(p, clientID)
	}

	// Write outgoing packets, if any, up to turnaroundTimeout.
	w.Header().Set("Content-Type", "application/octet-stream")
	outgoing := state.conn.OutgoingQueue(clientID)
	timer := time.NewTimer(turnaroundTimeout)
loop:
	for {
		select {
		case <-timer.C:
			break loop
		case p := <-outgoing:
			_, err := encapsulation.WriteData(w, p)
			if err != nil {
				break loop
			}
			// Flush after each chunk, this is important for
			// latency.
			if w, ok := w.(http.Flusher); ok {
				w.Flush()
			}
		}
	}
}

func acceptSessions(ctx context.Context, ln quic.Listener) error {
	for {
		sess, err := ln.Accept(ctx)
		if err != nil {
			if err, ok := err.(*net.OpError); ok && err.Temporary() {
				continue
			}
			return err
		}

		go func() {
			defer sess.Close()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			err := acceptStreams(ctx, sess)
			if err != nil {
				log.Printf("error in acceptStreams: %v", err)
			}
		}()
	}
}

func acceptStreams(ctx context.Context, sess quic.Session) error {
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			if err, ok := err.(*net.OpError); ok && err.Temporary() {
				continue
			}
			return err
		}

		go func() {
			defer stream.Close()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			err := handleStream(ctx, stream)
			if err != nil {
				log.Printf("error in handleStream: %v", err)
			}
		}()
	}
}

func handleStream(ctx context.Context, stream quic.Stream) error {
	// TODO: USERADDR
	or, err := pt.DialOr(&ptInfo, "", ptMethodName)
	if err != nil {
		return err
	}
	defer or.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(or, stream)
		or.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, or)
		stream.Close()
		or.Close()
	}()

	wgChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgChan)
	}()
	select {
	case <-wgChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func initServer(addr *net.TCPAddr,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	quicTLSGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	listenAndServe func(*http.Server, chan<- error)) (*http.Server, error) {
	// We're not capable of listening on port 0 (i.e., an ephemeral port
	// unknown in advance). The reason is that while the net/http package
	// exposes ListenAndServe and ListenAndServeTLS, those functions never
	// return, so there's no opportunity to find out what the port number
	// is, in between the Listen and Serve steps.
	// https://groups.google.com/d/msg/Golang-nuts/3F1VRCCENp8/3hcayZiwYM8J
	if addr.Port == 0 {
		return nil, fmt.Errorf("cannot listen on port %d; configure a port using ServerTransportListenAddr", addr.Port)
	}

	state, err := NewState(addr, quicTLSGetCertificate)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:         addr.String(),
		Handler:      state,
		ReadTimeout:  readWriteTimeout,
		WriteTimeout: readWriteTimeout,
	}
	// We need to override server.TLSConfig.GetCertificate--but first
	// server.TLSConfig needs to be non-nil. If we just create our own new
	// &tls.Config, it will lack the default settings that the net/http
	// package sets up for things like HTTP/2. Therefore we first call
	// http2.ConfigureServer for its side effect of initializing
	// server.TLSConfig properly. An alternative would be to make a dummy
	// net.Listener, call Serve on it, and let it return.
	// https://github.com/golang/go/issues/16588#issuecomment-237386446
	err = http2.ConfigureServer(server, nil)
	if err != nil {
		return server, err
	}
	server.TLSConfig.GetCertificate = getCertificate

	// Another unfortunate effect of the inseparable net/http ListenAndServe
	// is that we can't check for Listen errors like "permission denied" and
	// "address already in use" without potentially entering the infinite
	// loop of Serve. The hack we apply here is to wait a short time,
	// listenAndServeErrorTimeout, to see if an error is returned (because
	// it's better if the error message goes to the tor log through
	// SMETHOD-ERROR than if it only goes to the meek-server log).
	errChan := make(chan error)
	go listenAndServe(server, errChan)
	select {
	case err = <-errChan:
		break
	case <-time.After(listenAndServeErrorTimeout):
		break
	}

	return server, err
}

func startServer(
	addr *net.TCPAddr,
	quicTLSGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) (*http.Server, error) {
	return initServer(addr, nil, quicTLSGetCertificate, func(server *http.Server, errChan chan<- error) {
		log.Printf("listening with plain HTTP on %s", addr)
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("Error in ListenAndServe: %s", err)
		}
		errChan <- err
	})
}

func startServerTLS(
	addr *net.TCPAddr,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	quicTLSGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) (*http.Server, error) {
	return initServer(addr, getCertificate, quicTLSGetCertificate, func(server *http.Server, errChan chan<- error) {
		log.Printf("listening with HTTPS on %s", addr)
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("Error in ListenAndServeTLS: %s", err)
		}
		errChan <- err
	})
}

func getCertificateCacheDir() (string, error) {
	stateDir, err := pt.MakeStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, "meek-certificate-cache"), nil
}

func main() {
	var acmeEmail string
	var acmeHostnamesCommas string
	var disableTLS bool
	var certFilename, keyFilename string
	var logFilename string
	var port int
	var quicTLSCertFilename, quicTLSKeyFilename string

	flag.StringVar(&acmeEmail, "acme-email", "", "optional contact email for Let's Encrypt notifications")
	flag.StringVar(&acmeHostnamesCommas, "acme-hostnames", "", "comma-separated hostnames for automatic TLS certificate")
	flag.BoolVar(&disableTLS, "disable-tls", false, "don't use HTTPS")
	flag.StringVar(&certFilename, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFilename, "key", "", "TLS private key file")
	flag.StringVar(&logFilename, "log", "", "name of log file")
	flag.IntVar(&port, "port", 0, "port to listen on")
	flag.StringVar(&quicTLSCertFilename, "quic-tls-cert", "", "certificate file for QUIC TLS")
	flag.StringVar(&quicTLSKeyFilename, "quic-tls-key", "", "private key file for QUIC TLS")
	flag.Parse()

	var err error
	ptInfo, err = pt.ServerSetup(nil)
	if err != nil {
		log.Fatalf("error in ServerSetup: %s", err)
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			// If we fail to open the log, emit a message that will
			// appear in tor's log.
			pt.SmethodError(ptMethodName, fmt.Sprintf("error opening log file: %s", err))
			log.Fatalf("error opening log file: %s", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Handle the various ways of setting up TLS. The legal configurations
	// are:
	//   --acme-hostnames (with optional --acme-email)
	//   --cert and --key together
	//   --disable-tls
	// The outputs of this block of code are the disableTLS,
	// needHTTP01Listener, certManager, and getCertificate variables.
	var needHTTP01Listener = false
	var certManager *autocert.Manager
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if disableTLS {
		if acmeEmail != "" || acmeHostnamesCommas != "" || certFilename != "" || keyFilename != "" {
			log.Fatalf("The --acme-email, --acme-hostnames, --cert, and --key options are not allowed with --disable-tls.")
		}
	} else if certFilename != "" && keyFilename != "" {
		if acmeEmail != "" || acmeHostnamesCommas != "" {
			log.Fatalf("The --cert and --key options are not allowed with --acme-email or --acme-hostnames.")
		}
		ctx, err := newCertContext(certFilename, keyFilename)
		if err != nil {
			log.Fatal(err)
		}
		getCertificate = ctx.GetCertificate
	} else if acmeHostnamesCommas != "" {
		acmeHostnames := strings.Split(acmeHostnamesCommas, ",")
		log.Printf("ACME hostnames: %q", acmeHostnames)

		// The ACME HTTP-01 responder only works when it is running on
		// port 80.
		// https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#http-challenge
		needHTTP01Listener = true

		var cache autocert.Cache
		cacheDir, err := getCertificateCacheDir()
		if err == nil {
			log.Printf("caching ACME certificates in directory %q", cacheDir)
			cache = autocert.DirCache(cacheDir)
		} else {
			log.Printf("disabling ACME certificate cache: %s", err)
		}

		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeHostnames...),
			Email:      acmeEmail,
			Cache:      cache,
		}
		getCertificate = certManager.GetCertificate
	} else {
		log.Fatalf("You must use either --acme-hostnames, or --cert and --key.")
	}

	// Set up the certificate and private key for the inner QUIC TLS layer.
	// This is entirely separate from the HTTPS-layer TLS that is set up
	// just above.
	var quicTLSGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if quicTLSCertFilename != "" && quicTLSKeyFilename != "" {
		ctx, err := newCertContext(quicTLSCertFilename, quicTLSKeyFilename)
		if err != nil {
			log.Fatal(err)
		}
		quicTLSGetCertificate = ctx.GetCertificate
	} else {
		log.Fatal("The --quic-tls-cert and --quic-tls-key options are required.")
	}

	log.Printf("starting version %s (%s)", programVersion, runtime.Version())
	servers := make([]*http.Server, 0)
	for _, bindaddr := range ptInfo.Bindaddrs {
		if port != 0 {
			bindaddr.Addr.Port = port
		}
		switch bindaddr.MethodName {
		case ptMethodName:
			if needHTTP01Listener {
				needHTTP01Listener = false
				addr := *bindaddr.Addr
				addr.Port = 80
				log.Printf("starting HTTP-01 ACME listener on %s", addr.String())
				lnHTTP01, err := net.ListenTCP("tcp", &addr)
				if err != nil {
					log.Printf("error opening HTTP-01 ACME listener: %s", err)
					pt.SmethodError(bindaddr.MethodName, "HTTP-01 ACME listener: "+err.Error())
					continue
				}
				go func() {
					log.Fatal(http.Serve(lnHTTP01, certManager.HTTPHandler(nil)))
				}()
			}

			var server *http.Server
			if disableTLS {
				server, err = startServer(bindaddr.Addr, quicTLSGetCertificate)
			} else {
				server, err = startServerTLS(bindaddr.Addr, getCertificate, quicTLSGetCertificate)
			}
			if err != nil {
				pt.SmethodError(bindaddr.MethodName, err.Error())
				break
			}
			pt.Smethod(bindaddr.MethodName, bindaddr.Addr)
			servers = append(servers, server)
		default:
			pt.SmethodError(bindaddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

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

	// Keep track of handlers and wait for a signal.
	sig := <-sigChan
	log.Printf("got signal %s", sig)

	for _, server := range servers {
		server.Close()
	}

	log.Printf("done")
}
