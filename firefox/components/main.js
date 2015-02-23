// This is an extension that allows external programs to make HTTP requests
// using the browser's networking libraries.
//
// The extension opens a TCP socket listening on localhost on an ephemeral port.
// It writes the port number in a recognizable format to stdout so that a parent
// process can read it and connect.
//
// The protocol is based on chunked streams. A chunked stream is a sequence of
// byte chunks, each preceded by a 2-byte big-endian length. The stream ends
// with a chunk of length 0. (Kind of like the "chunked" transfer encoding in
// HTTP.) The client sends its request in two chunked streams. The first stream
// contains a JSON representation of the request metadata (HTTP method, URL,
// header, etc.), and the second is the raw bytes of the request body. This
// extension likewise sends back its response as two chunked streams. The first
// contains a JSON representation of the response status (the status code and
// error message, if any), and the second is the response body. In summary, both
// sides send data like:
// XX XX <XXXX bytes of JSON> 00 00 [YY YY <YYYY bytes of body> [ZZ ZZ <ZZZZ bytes of body>...]] 00 00
//
// The JSON representation of a request is of the form:
//  {
//      "method": "POST",
//      "url": "https://www.google.com/",
//      "header": {
//          "Host": "meek-reflect.appspot.com",
//          "X-Session-Id": "XXXXXXXXXXX"}
//      },
//      "proxy": {
//          "type": "http",
//          "host": "proxy.example.com",
//          "port": 8080
//      },
//  }
//
// The JSON representation of a response is of the form:
//  {
//      "status": 200,
//  }
// If there is a network error, the "error" key will be defined. A 404 response
// or similar from the target web server is not considered such an error.
//  {
//      "error": "NS_ERROR_UNKNOWN_HOST"
//  }
//
// The extension closes the connection after each transaction, and the client
// must reconnect in order to make another request.

// https://developer.mozilla.org/en-US/docs/How_to_Build_an_XPCOM_Component_in_Javascript#Using_XPCOMUtils
// https://developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/XPCOMUtils.jsm
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

// https://developer.mozilla.org/en-US/docs/Tools/Browser_Console#Console.jsm
Components.utils.import("resource://gre/modules/devtools/Console.jsm");

// Everything resides within the MeekHTTPHelper namespace. MeekHTTPHelper is
// also the type from which NSGetFactory is constructed, and it is the top-level
// nsIServerSocketListener.
function MeekHTTPHelper() {
    this.wrappedJSObject = this;
    this.handlers = [];
}
MeekHTTPHelper.prototype = {
    classDescription: "meek HTTP helper component",
    classID: Components.ID("{e7bc2b9c-f454-49f3-a19f-14848a4d871d}"),
    contractID: "@bamsoftware.com/meek-http-helper;1",

    // https://developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/XPCOMUtils.jsm#generateQI%28%29
    QueryInterface: XPCOMUtils.generateQI([
        Components.interfaces.nsIObserver,
        Components.interfaces.nsIServerSocketListener,
    ]),

    // nsIObserver implementation.
    observe: function(subject, topic, data) {
        if (topic !== "profile-after-change")
            return;

        try {
            // Flush the preferences to disk so that pref values that were
            // updated during startup are not lost, e.g., ones related to
            // browser updates.
            // We do this before we change the network.proxy.socks_remote_dns
            // value since we do not want that change to be permanent. See
            // https://trac.torproject.org/projects/tor/ticket/16269.
            let prefSvc = Components.classes["@mozilla.org/preferences-service;1"]
                .getService(Components.interfaces.nsIPrefService);
            prefSvc.savePrefFile(null);

            let prefs = Components.classes["@mozilla.org/preferences-service;1"]
                .getService(Components.interfaces.nsIPrefBranch);
            // Allow unproxied DNS, working around a Tor Browser patch:
            // https://trac.torproject.org/projects/tor/ticket/11183#comment:6.
            // We set TRANSPARENT_PROXY_RESOLVES_HOST whenever we are asked to
            // use a proxy, so name resolution uses the proxy despite this pref.
            prefs.setBoolPref("network.proxy.socks_remote_dns", false);

            // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIServerSocket
            let serverSocket = Components.classes["@mozilla.org/network/server-socket;1"]
                .createInstance(Components.interfaces.nsIServerSocket);
            // Listen on an ephemeral port, loopback only, with default backlog.
            serverSocket.init(-1, true, -1);
            serverSocket.asyncListen(this);
            // This output line is used by a controller program to find out what
            // address the helper is listening on. For the dump call to have any
            // effect, the pref browser.dom.window.dump.enabled must be true.
            dump("meek-http-helper: listen 127.0.0.1:" + serverSocket.port + "\n");

            // Block forever.
            // https://developer.mozilla.org/en-US/Add-ons/Code_snippets/Threads#Waiting_for_a_background_task_to_complete
            let thread = Components.classes["@mozilla.org/thread-manager;1"].getService().currentThread;
            while (true)
                thread.processNextEvent(true);
        } finally {
            let app = Components.classes["@mozilla.org/toolkit/app-startup;1"]
                .getService(Components.interfaces.nsIAppStartup);
            app.quit(app.eForceQuit);
        }
    },

    // nsIServerSocketListener implementation.
    onSocketAccepted: function(server, transport) {
        // dump("onSocketAccepted " + transport.host + ":" + transport.port + "\n");
        // Stop referencing handlers that are no longer alive.
        this.handlers = this.handlers.filter(function(h) { return h.transport.isAlive(); });
        this.handlers.push(new MeekHTTPHelper.LocalConnectionHandler(transport));
    },
    onStopListening: function(server, status) {
        // dump("onStopListening status " + status + "\n");
    },
};

// Global variables and functions.

MeekHTTPHelper.LOCAL_READ_TIMEOUT = 2.0;
MeekHTTPHelper.LOCAL_WRITE_TIMEOUT = 2.0;

// https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIProtocolProxyService
MeekHTTPHelper.proxyProtocolService = Components.classes["@mozilla.org/network/protocol-proxy-service;1"]
    .getService(Components.interfaces.nsIProtocolProxyService);

// https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIIOService
MeekHTTPHelper.ioService = Components.classes["@mozilla.org/network/io-service;1"]
    .getService(Components.interfaces.nsIIOService);
MeekHTTPHelper.httpProtocolHandler = MeekHTTPHelper.ioService.getProtocolHandler("http")
    .QueryInterface(Components.interfaces.nsIHttpProtocolHandler);

// Set the transport to time out at the given absolute deadline.
MeekHTTPHelper.refreshDeadline = function(transport, deadline) {
    let timeout;
    if (deadline === null)
        timeout = 0xffffffff;
    else
        timeout = Math.max(0.0, Math.ceil((deadline - Date.now()) / 1000.0));
    transport.setTimeout(Components.interfaces.nsISocketTransport.TIMEOUT_READ_WRITE, timeout);
};

// Reverse-index the Components.results table.
MeekHTTPHelper.lookupStatus = function(status) {
    for (let name in Components.results) {
        if (Components.results[name] === status)
            return name;
    }
    return null;
};

// Enforce restrictions on what requests we are willing to make. These can
// probably be loosened up. Try and rule out anything unexpected until we
// know we need otherwise.
MeekHTTPHelper.requestOk = function(req) {
    if (req.method === undefined) {
        dump("req missing \"method\".\n");
        return false;
    }
    if (req.url === undefined) {
        dump("req missing \"url\".\n");
        return false;
    }

    if (req.method !== "POST") {
        dump("req.method is " + JSON.stringify(req.method) + ", not \"POST\".\n");
        return false;
    }
    if (!(req.url.startsWith("http://") || req.url.startsWith("https://"))) {
        dump("req.url doesn't start with \"http://\" or \"https://\".\n");
        return false;
    }

    return true;
};

// Return an nsIProxyInfo according to the given specification. Returns null on
// error.
// https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIProxyInfo
// The specification may look like:
//   undefined
//   {"type": "http", "host": "example.com", "port": 8080}
//   {"type": "socks5", "host": "example.com", "port": 1080}
//   {"type": "socks4a", "host": "example.com", "port": 1080}
MeekHTTPHelper.buildProxyInfo = function(spec) {
    // https://developer.mozilla.org/en-US/docs/Mozilla/Tech/XPCOM/Reference/Interface/nsIProxyInfo#Constants
    let flags = Components.interfaces.nsIProxyInfo.TRANSPARENT_PROXY_RESOLVES_HOST;
    if (spec === undefined) {
        // "direct"; i.e., no proxy. This is the default.
        return MeekHTTPHelper.proxyProtocolService.newProxyInfo("direct", "", 0, flags, 0xffffffff, null);
    } else if (spec.type === "http") {
        // "http" proxy. Versions of Firefox before 32, and Tor Browser before
        // 3.6.2, leak the covert Host header in HTTP proxy CONNECT requests.
        // Using an HTTP proxy cannot provide effective obfuscation without such
        // a patched Firefox.
        // https://trac.torproject.org/projects/tor/ticket/12146
        // https://gitweb.torproject.org/tor-browser.git/commit/?id=e08b91c78d919f66dd5161561ca1ad7bcec9a563
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1017769
        // https://hg.mozilla.org/mozilla-central/rev/a1f6458800d4
        return MeekHTTPHelper.proxyProtocolService.newProxyInfo("http", spec.host, spec.port, flags, 0xffffffff, null);
    } else if (spec.type === "socks5") {
        // "socks5" is tor's name. "socks" is XPCOM's name.
        return MeekHTTPHelper.proxyProtocolService.newProxyInfo("socks", spec.host, spec.port, flags, 0xffffffff, null);
    } else if (spec.type === "socks4a") {
        // "socks4a" is tor's name. "socks4" is XPCOM's name.
        return MeekHTTPHelper.proxyProtocolService.newProxyInfo("socks4", spec.host, spec.port, flags, 0xffffffff, null);
    }
    return null;
};

// Transmit an HTTP response info blob over the given nsIOutputStream. resp is
// an object with keys perhaps including "status" and "error".
MeekHTTPHelper.sendResponse = function(outputStream, resp) {
    // dump("sendResponse " + JSON.stringify(resp) + "\n");
    let output = Components.classes["@mozilla.org/binaryoutputstream;1"]
        .createInstance(Components.interfaces.nsIBinaryOutputStream);
    output.setOutputStream(outputStream);

    let converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
        .createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";
    let data = JSON.stringify(resp);

    if (data.length > 65535)
        throw Components.Exception("Object is too large for chunking (" + data.length + " bytes)", Components.results.NS_ERROR_ILLEGAL_VALUE);
    output.write16(data.length);
    output.writeBytes(data, data.length);
    output.write16(0);
};

// LocalConnectionHandler handles each new client connection received on the
// socket opened by MeekHTTPHelper. It reads a JSON request, makes the request
// on the Internet, and writes the result back to the socket. Error handling
// happens within callbacks.
MeekHTTPHelper.LocalConnectionHandler = function(transport) {
    this.transport = transport;
    this.requestReader = null;
    this.channel = null;
    this.listener = null;
    this.readRequest(this.makeRequest.bind(this));
};
MeekHTTPHelper.LocalConnectionHandler.prototype = {
    readRequest: function(callback) {
        this.requestReader = new MeekHTTPHelper.RequestReader(this.transport, callback);
    },

    makeRequest: function(req) {
        // dump("makeRequest " + JSON.stringify(req) + "\n");
        if (!MeekHTTPHelper.requestOk(req))
            return this.sendError("request failed validation");

        // Check what proxy to use, if any.
        // dump("using proxy " + JSON.stringify(req.proxy) + "\n");
        let proxyInfo = MeekHTTPHelper.buildProxyInfo(req.proxy);
        if (proxyInfo === null)
            return this.sendError("can't create nsIProxyInfo from " + JSON.stringify(req.proxy));

        // Construct an HTTP channel with the given nsIProxyInfo.
        // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIHttpChannel
        let uri = MeekHTTPHelper.ioService.newURI(req.url, null, null);
        this.channel = MeekHTTPHelper.httpProtocolHandler.newProxiedChannel(uri, proxyInfo, 0, null)
            .QueryInterface(Components.interfaces.nsIHttpChannel);
        // Remove pre-set headers. Firefox's AddStandardRequestHeaders adds
        // User-Agent, Accept, Accept-Language, and Accept-Encoding, and perhaps
        // others. Just remove all of them.
        let headers = [];
        // https://developer.mozilla.org/en-US/docs/Mozilla/Tech/XPCOM/Reference/Interface/nsIHttpChannel#visitRequestHeaders%28%29
        // https://developer.mozilla.org/en-US/docs/Mozilla/Tech/XPCOM/Reference/Interface/nsIHttpHeaderVisitor
        this.channel.visitRequestHeaders({visitHeader: function(key, value) { headers.push(key); }})
        for (let i = 0; i < headers.length; i++) {
            if (headers[i] !== "Host")
                this.channel.setRequestHeader(headers[i], "", false);
        }
        // Set our own headers.
        if (req.header !== undefined) {
            for (let key in req.header) {
                this.channel.setRequestHeader(key, req.header[key], false);
            }
        }
        let inputStream = Components.classes["@mozilla.org/io/string-input-stream;1"]
            .createInstance(Components.interfaces.nsIStringInputStream);
        inputStream.setData(req.body, req.body.length);
        let uploadChannel = this.channel.QueryInterface(Components.interfaces.nsIUploadChannel);
        uploadChannel.setUploadStream(inputStream, "application/octet-stream", req.body.length);
        // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIUploadChannel
        // says we must set requestMethod after calling setUploadStream.
        this.channel.requestMethod = req.method;
        this.channel.redirectionLimit = 0;

        this.listener = new MeekHTTPHelper.HttpStreamListener(this.transport);
        this.channel.asyncOpen(this.listener, this.channel);
    },

    sendError: function(msg) {
        let output = this.transport.openOutputStream(Components.interfaces.nsITransport.OPEN_BLOCKING, 0, 0);
        let deadline = Date.now() + MeekHTTPHelper.LOCAL_WRITE_TIMEOUT * 1000;
        MeekHTTPHelper.refreshDeadline(this.transport, deadline);
        MeekHTTPHelper.sendResponse(output, {"error": msg});
        this.transport.close(0);
    },
};

// ChunkedReader reads a chunked stream, which is a sequence of byte chunks,
// each preceded by a 16-bit big-endian length. The end of a stream is marked by
// a zero-length chunk.
MeekHTTPHelper.ChunkedReader = function(transport) {
    this.transport = transport;

    this.inputStream = this.transport.openInputStream(Components.interfaces.nsITransport.OPEN_BLOCKING, 0, 0);
    this.curThread = Components.classes["@mozilla.org/thread-manager;1"].getService().currentThread;
};
MeekHTTPHelper.ChunkedReader.prototype = {
    // The onInputStreamReady callback is called for all read events. These
    // constants keep track of the state of parsing.
    STATE_READING_LENGTH: 1,
    STATE_READING_DATA: 2,
    STATE_DONE: 3,

    read: function(deadline, callback) {
        this.deadline = deadline;
        this.callback = callback;
        // An array of chunks (as Uint8Arrays) that are concatenated before
        // being passed to the callback.
        this.chunks = [];
        // Initially size buf to read the 2-byte length.
        this.buf = new Uint8Array(2);
        this.bytesToRead = this.buf.length;
        this.state = this.STATE_READING_LENGTH;
        this.asyncWait();
    },

    // Do an asyncWait and handle the result.
    asyncWait: function() {
        MeekHTTPHelper.refreshDeadline(this.transport, this.deadline);
        this.inputStream.asyncWait(this, 0, 0, this.curThread);
    },

    // Read into this.buf (up to its capacity) and decrement this.bytesToRead.
    readIntoBuf: function(input) {
        let n = Math.min(input.available(), this.bytesToRead);
        let data = input.readByteArray(n);
        this.buf.subarray(this.buf.length - this.bytesToRead).set(data);
        this.bytesToRead -= n;
    },

    // nsIInputStreamCallback implementation.
    onInputStreamReady: function(inputStream) {
        let input = Components.classes["@mozilla.org/binaryinputstream;1"]
            .createInstance(Components.interfaces.nsIBinaryInputStream);
        input.setInputStream(inputStream);

        try {
            switch (this.state) {
            case this.STATE_READING_LENGTH:
                this.doStateReadingLength(input);
                break;
            case this.STATE_READING_DATA:
                this.doStateReadingData(input);
                break;
            }

            if (this.state === this.STATE_DONE) {
                let length = 0;
                for (let i = 0; i < this.chunks.length; i++)
                    length += this.chunks[i].length;
                let data = new Uint8Array(length);
                let n = 0;
                for (let i = 0; i < this.chunks.length; i++) {
                    data.set(this.chunks[i], n);
                    n += this.chunks[i].length;
                }
                this.callback(data);
            } else {
                this.asyncWait();
            }
        } catch (e) {
            this.transport.close(0);
            throw e;
        }
    },

    doStateReadingLength: function(input) {
        this.readIntoBuf(input);
        if (this.bytesToRead > 0)
            return;

        let len = (this.buf[0] << 8) | this.buf[1];
        if (len == 0) {
            this.state = this.STATE_DONE;
        } else {
            this.buf = new Uint8Array(len);
            this.bytesToRead = this.buf.length;
            this.state = this.STATE_READING_DATA;
        }
    },

    doStateReadingData: function(input) {
        this.readIntoBuf(input);
        if (this.bytesToRead > 0)
            return;

        this.chunks.push(this.buf);
        this.buf = new Uint8Array(2);
        this.bytesToRead = this.buf.length;
        this.state = this.STATE_READING_LENGTH;
    },
};

// RequestReader reads an encoded request from the given transport, then calls
// the given callback with the request object as an argument. In case of error,
// the transport is closed and the callback is not called.
MeekHTTPHelper.RequestReader = function(transport, callback) {
    this.callback = callback;
    this.req = null;

    this.deadline = Date.now() + MeekHTTPHelper.LOCAL_READ_TIMEOUT * 1000;
    this.reader = new MeekHTTPHelper.ChunkedReader(transport);
    this.reader.read(this.deadline, this.handleJSON.bind(this));
};
MeekHTTPHelper.RequestReader.prototype = {
    handleJSON: function(data) {
        let converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
            .createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
        converter.charset = "UTF-8";
        let s = converter.convertFromByteArray(data, data.length);
        this.req = JSON.parse(s);
        if (this.req.body !== undefined) {
            // Fail fast on clients that use an older version of this protocol.
            throw Components.Exception("req has body defined in info blob", Components.results.NS_ERROR_ILLEGAL_VALUE);
        }
        // Now read the body.
        this.reader.read(this.deadline, this.handleBody.bind(this));
    },

    handleBody: function(data) {
        this.req.body = String.fromCharCode.apply(null, data);
        this.callback(this.req);
    },
};

// HttpStreamListener listens to an HTTP response and writes it back to the
// given transport. The "error" key of the written response object is present if
// and only if there was an error.
MeekHTTPHelper.HttpStreamListener = function(transport) {
    this.transport = transport;
    this.resp = {};
    this.respSent = false;

    // No timeouts while writing response.
    MeekHTTPHelper.refreshDeadline(this.transport, null);

    this.outputStream = this.transport.openOutputStream(Components.interfaces.nsITransport.OPEN_BLOCKING, 0, 0);
    this.output = Components.classes["@mozilla.org/binaryoutputstream;1"]
        .createInstance(Components.interfaces.nsIBinaryOutputStream);
    this.output.setOutputStream(this.outputStream);
};
// https://developer.mozilla.org/en-US/docs/Creating_Sandboxed_HTTP_Connections
MeekHTTPHelper.HttpStreamListener.prototype = {
    // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIRequestObserver
    onStartRequest: function(req, context) {
        // dump("onStartRequest\n");
        try {
            this.resp.status = context.responseStatus;
        } catch (e) {
            // Reading context.responseStatus can fail in this way when there is
            // no HTTP response; e.g., when the connection is reset.
            if (!(e instanceof Components.interfaces.nsIXPCException
                  && e.result === Components.results.NS_ERROR_NOT_AVAILABLE)) {
                throw(e);
            }
        }
    },
    onStopRequest: function(req, context, status) {
        // dump("onStopRequest " + status + "\n");
        if (!Components.isSuccessCode(status)) {
            // If there was an error, let's hope we didn't send the body yet, or
            // else we can't report the error.
            let err = MeekHTTPHelper.lookupStatus(status);
            if (err !== null)
                this.resp.error = err;
            else
                this.resp.error = "error " + String(status);
        }
        if (!this.respSent)
            this.sendResp();
        this.output.write16(0);
        this.output.close();
    },

    // Copy the response body to the transport as it arrives.
    // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIStreamListener
    onDataAvailable: function(request, context, stream, sourceOffset, length) {
        // dump("onDataAvailable " + length + " bytes\n");
        if (!this.respSent)
            this.sendResp();
        while (length > 65535) {
            this.output.write16(65535);
            this.outputStream.writeFrom(stream, 65535);
            length -= 65535;
        }
        this.output.write16(length);
        this.outputStream.writeFrom(stream, length);
    },

    sendResp: function() {
        MeekHTTPHelper.sendResponse(this.output, this.resp);
        this.respSent = true;
    },
};

let NSGetFactory = XPCOMUtils.generateNSGetFactory([MeekHTTPHelper]);
