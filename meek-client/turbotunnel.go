// The code in this file provides a compatibility layer between an underlying
// packet-based connection and our polling-based domain-fronted HTTP carrier.
// The main interface is PollingPacketConn, which abstracts over a polling
// medium like HTTP. Each request consists of an 8-byte Client ID, followed by a
// sequence of packets and padding encapsulated according to the rules of the
// common/encapsulation package. The downstream direction is the same, except
// that this is no Client ID prefix.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"git.torproject.org/pluggable-transports/meek.git/common/encapsulation"
)

const (
	// The size of receive and send queues.
	queueSize = 32

	// The size of the largest bundle of packets we will send in a poll.
	// (Actually it's not quite a maximum, we will quit bundling as soon as
	// it is exceeded.)
	maxSendBundleLength = 0x10000

	// How many goroutines stand ready to do a poll when an outgoing packet
	// needs to be sent.
	numRequestLoops = 32

	// We must poll the server to see if it has anything to send; there is
	// no way for the server to push data back to us until we poll it. When
	// a timer expires, we send a request even if it has an empty body. The
	// interval starts at this value and then grows.
	initPollDelay = 500 * time.Millisecond
	// Maximum polling interval.
	maxPollDelay = 10 * time.Second
	// Geometric increase in the polling interval each time we fail to read
	// data.
	pollDelayMultiplier = 2.0
)

// ClientID plays the role in PollingPacketConn that an (IP address, port) tuple
// plays in a net.UDPConn. It is a persistent identifier that binds together all
// the HTTP transactions that occur as part of a session. The ClientID is sent
// along with all HTTP requests, and the server uses the ClientID to
// disambiguate requests among its many clients. ClientID implements the
// net.Addr interface.
//
// ClientID duplicates the functionality of the QUIC connection ID, but quic-go
// does not provide accessors for the connection ID.
type ClientID [8]byte

func newClientID() ClientID {
	var id ClientID
	_, err := rand.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

func (id ClientID) Network() string { return "clientid" }
func (id ClientID) String() string  { return hex.EncodeToString(id[:]) }

// Poller is an abstract interface over an operation that writes a stream of
// bytes and reads a stream of bytes in return, like an HTTP request.
type Poller interface {
	Poll(out io.Reader) (in io.ReadCloser, err error)
}

// PollingPacketConn implements the net.PacketConn interface over a carrier of
// HTTP requests and responses. Packets passed to WriteTo are batched,
// encapsulated, and sent in the bodies of HTTP POST requests. Downstream
// packets are unencapsulated and unbatched from HTTP response bodies and put in
// a queue to be returned by ReadFrom.
//
// HTTP interaction is done using an abstract Poller function whose Poll method
// takes a byte slice (an HTTP request body) and returns an io.ReadCloser (an
// HTTP response body). The Poller can apply HTTP request customizations such as
// domain fronting.
type PollingPacketConn struct {
	clientID   ClientID
	remoteAddr net.Addr
	poller     Poller
	recvQueue  chan []byte
	sendQueue  chan []byte
	// Sending on pollChan permits requestLoop to send an empty polling
	// query. requestLoop also does its own polling according to a time
	// schedule.
	pollChan  chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
	// What error to return when the PollingPacketConn is closed.
	err atomic.Value
}

// NewPollingPacketConn creates a PollingPacketConn with a random ClientID as
// the local address. remoteAddr is used only in errors, the return value of
// ReadFrom, and the RemoteAddr method; is is poller that really controls the
// effective remote address.
func NewPollingPacketConn(remoteAddr net.Addr, poller Poller) *PollingPacketConn {
	c := &PollingPacketConn{
		clientID:   newClientID(),
		remoteAddr: remoteAddr,
		poller:     poller,
		recvQueue:  make(chan []byte, queueSize),
		sendQueue:  make(chan []byte, queueSize),
		pollChan:   make(chan struct{}),
		closed:     make(chan struct{}),
	}
	for i := 0; i < numRequestLoops; i++ {
		go c.requestLoop()
	}
	return c
}

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// ReadFrom returns a packet received from a previous poll, blocking until there
// is a packet to return. Unless the returned error is non-nil, the returned
// net.Addr is always c.RemoteAddr(),
func (c *PollingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: c.RemoteAddr().Network(), Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: c.err.Load().(error)}
	default:
	}
	select {
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: c.RemoteAddr().Network(), Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: c.err.Load().(error)}
	case buf := <-c.recvQueue:
		return copy(p, buf), c.RemoteAddr(), nil
	}
}

// WriteTo queues a packet to be sent (possibly batched) by the underlying
// poller.
func (c *PollingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// The addr argument is ignored.
	select {
	case <-c.closed:
		return 0, &net.OpError{Op: "write", Net: c.RemoteAddr().Network(), Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: c.err.Load().(error)}
	default:
	}
	// Copy the slice so that the caller may reuse it.
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.sendQueue <- buf:
		return len(buf), nil
	default:
		// Drop the outgoing packet if the send queue is full.
		return len(buf), nil
	}
}

// closeWithError unblocks pending operations and makes future operations fail
// with the given error. If err is nil, it becomes errClosedPacketConn.
func (c *PollingPacketConn) closeWithError(err error) error {
	var newlyClosed bool
	c.closeOnce.Do(func() {
		newlyClosed = true
		// Store the error to be returned by future PacketConn
		// operations.
		if err == nil {
			err = errClosedPacketConn
		}
		c.err.Store(err)
		close(c.closed)
	})
	if !newlyClosed {
		return &net.OpError{Op: "close", Net: c.LocalAddr().Network(), Addr: c.LocalAddr(), Err: c.err.Load().(error)}
	}
	return nil
}

// Close unblocks pending operations and makes future operations fail with a
// "closed connection" error.
func (c *PollingPacketConn) Close() error {
	return c.closeWithError(nil)
}

// LocalAddr returns this connection's random Client ID.
func (c *PollingPacketConn) LocalAddr() net.Addr { return c.clientID }

// RemoteAddr returns the remoteAddr value that was passed to
// NewPollingPacketConn.
func (c *PollingPacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *PollingPacketConn) SetDeadline(t time.Time) error      { return errNotImplemented }
func (c *PollingPacketConn) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (c *PollingPacketConn) SetWriteDeadline(t time.Time) error { return errNotImplemented }

func (c *PollingPacketConn) requestLoop() {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var body bytes.Buffer
		body.Write(c.clientID[:])

		var p []byte
		pollTimerExpired := false
		// Block, waiting for at least one packet.
		select {
		case <-c.closed:
			return
		case p = <-c.sendQueue:
		default:
			select {
			case <-c.closed:
				return
			case p = <-c.sendQueue:
			case <-c.pollChan:
				p = nil
			case <-pollTimer.C:
				p = nil
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// Encapsulate the packet into the request body.
			encapsulation.WriteData(&body, p)

			// A data-carrying request displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		// Send any other packets that are immediately available, up to
		// maxSendBundleLength.
	loop:
		// TODO: It would be better if maxSendBundleLength were a true
		// maximum (we don't remove a packet from c.sendQueue unless it
		// fits in the remaining length). That would also allow for
		// arbitrary shaping, along with encapsulation.WritePadding.
		for body.Len() < maxSendBundleLength {
			select {
			case <-c.closed:
				return
			case p := <-c.sendQueue:
				encapsulation.WriteData(&body, p)
			default:
				break loop
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		resp, err := c.poller.Poll(&body)
		if err != nil {
			c.closeWithError(err)
			return
		}
		defer resp.Close()

		queuedPoll := false
		for {
			p, err := encapsulation.ReadData(resp)
			if err == io.EOF {
				break
			} else if err != nil {
				c.closeWithError(err)
				break
			}
			select {
			case c.recvQueue <- p:
			default:
				// Drop incoming packets when queue is full.
			}
			if !queuedPoll {
				queuedPoll = true
				for i := 0; i < 2; i++ {
					select {
					case c.pollChan <- struct{}{}:
					default:
					}
				}
			}
		}
	}
}
