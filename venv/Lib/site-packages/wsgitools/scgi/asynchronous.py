__all__ = []

import asyncore
import io
import socket
import sys
import errno

from wsgitools.internal import bytes2str, str2bytes
from wsgitools.scgi import _convert_environ, FileWrapper

if sys.version_info[0] >= 3:
    def exc_info_for_raise(exc_info):
        return exc_info[0](exc_info[1]).with_traceback(exc_info[2])
else:
    def exc_info_for_raise(exc_info):
        return exc_info[0], exc_info[1], exc_info[2]

class SCGIConnection(asyncore.dispatcher):
    """SCGI connection class used by L{SCGIServer}."""
    # connection states
    NEW    = 0*4 | 1 # connection established, waiting for request
    HEADER = 1*4 | 1 # the request length was received, waiting for the rest
    BODY   = 2*4 | 1 # the request header was received, waiting for the body,
                     # to RESP or RESPH
    RESP   = 3*4 | 2 # sending response, end state
    RESPH  = 4*4 | 2 # buffered response headers, sending headers only, to TRANS
    TRANS  = 5*4 | 2 # transferring using FileWrapper, end state
    def __init__(self, server, connection, addr, maxrequestsize=65536,
                 maxpostsize=8<<20, blocksize=4096, config={}):
        asyncore.dispatcher.__init__(self, connection)

        self.server = server # WSGISCGIServer instance
        self.addr = addr # scgi client address
        self.maxrequestsize = maxrequestsize
        self.maxpostsize = maxpostsize
        self.blocksize = blocksize
        self.state = SCGIConnection.NEW # internal state
        self.environ = config.copy() # environment passed to wsgi app
        self.reqlen = -1 # request length used in two different meanings
        self.inbuff = b"" # input buffer
        self.outbuff = b"" # output buffer
        self.wsgihandler = None # wsgi application
        self.wsgiiterator = None # wsgi application iterator
        self.outheaders = () # headers to be sent
                             # () -> unset, (..,..) -> set, True -> sent
        self.body = io.BytesIO() # request body

    def _try_send_headers(self):
        if self.outheaders != True:
            assert not self.outbuff
            status, headers = self.outheaders
            headdata = "".join(map("%s: %s\r\n".__mod__, headers))
            headdata = "Status: %s\r\n%s\r\n" % (status, headdata)
            self.outbuff = str2bytes(headdata)
            self.outheaders = True

    def _wsgi_write(self, data):
        assert self.state >= SCGIConnection.RESP
        assert self.state < SCGIConnection.TRANS
        assert isinstance(data, bytes)
        if data:
            self._try_send_headers()
            self.outbuff += data

    def readable(self):
        """C{asyncore} interface"""
        return self.state & 1 == 1

    def writable(self):
        """C{asyncore} interface"""
        return self.state & 2 == 2

    def handle_read(self):
        """C{asyncore} interface"""
        data = self.recv(self.blocksize)
        self.inbuff += data
        if self.state == SCGIConnection.NEW:
            if b':' in self.inbuff:
                reqlen, self.inbuff = self.inbuff.split(b':', 1)
                try:
                    reqlen = int(reqlen)
                except ValueError:  # invalid request format
                    self.close()
                    return
                if reqlen > self.maxrequestsize:
                    self.close()
                    return # request too long
                self.reqlen = reqlen
                self.state = SCGIConnection.HEADER
            elif len(self.inbuff) > self.maxrequestsize:
                self.close()
                return # request too long

        if self.state == SCGIConnection.HEADER:
            buff = self.inbuff[:self.reqlen]
            remainder = self.inbuff[self.reqlen:]

            while buff.count(b'\0') >= 2:
                key, value, buff = buff.split(b'\0', 2)
                self.environ[bytes2str(key)] = bytes2str(value)
                self.reqlen -= len(key) + len(value) + 2

            self.inbuff = buff + remainder

            if self.reqlen == 0:
                if self.inbuff.startswith(b','):
                    self.inbuff = self.inbuff[1:]
                    try:
                        self.reqlen = int(self.environ["CONTENT_LENGTH"])
                    except ValueError:
                        self.close()
                        return
                    if self.reqlen > self.maxpostsize:
                        self.close()
                        return
                    self.state = SCGIConnection.BODY
                else:
                    self.close()
                    return # protocol violation

        if self.state == SCGIConnection.BODY:
            if len(self.inbuff) >= self.reqlen:
                self.body.write(self.inbuff[:self.reqlen])
                self.body.seek(0)
                self.inbuff = b""
                self.reqlen = 0
                _convert_environ(self.environ)
                self.environ["wsgi.input"] = self.body
                self.environ["wsgi.errors"] = self.server.error
                self.wsgihandler = self.server.wsgiapp(self.environ,
                        self.start_response)
                if isinstance(self.wsgihandler, FileWrapper) and \
                        self.wsgihandler.can_transfer():
                    self._try_send_headers()
                    self.state = SCGIConnection.RESPH
                else:
                    self.wsgiiterator = iter(self.wsgihandler)
                    self.state = SCGIConnection.RESP
            else:
                self.body.write(self.inbuff)
                self.reqlen -= len(self.inbuff)
                self.inbuff = b""

    def start_response(self, status, headers, exc_info=None):
        assert isinstance(status, str)
        assert isinstance(headers, list)
        if exc_info:
            if self.outheaders == True:
                try:
                    raise exc_info_for_raise(exc_info)
                finally:
                    exc_info = None
        assert self.outheaders != True # unsent
        self.outheaders = (status, headers)
        return self._wsgi_write

    def send_buff(self):
        try:
            sentbytes = self.send(self.outbuff[:self.blocksize])
        except socket.error:
            self.close()
        else:
            self.outbuff = self.outbuff[sentbytes:]

    def handle_write(self):
        """C{asyncore} interface"""
        if self.state == SCGIConnection.RESP:
            if len(self.outbuff) < self.blocksize:
                self._try_send_headers()
                for data in self.wsgiiterator:
                    assert isinstance(data, bytes)
                    if data:
                        self.outbuff += data
                        break
                if len(self.outbuff) == 0:
                    self.close()
                    return
            self.send_buff()
        elif self.state == SCGIConnection.RESPH:
            assert len(self.outbuff) > 0
            self.send_buff()
            if not self.outbuff:
                self.state = SCGIConnection.TRANS
        else:
            assert self.state == SCGIConnection.TRANS
            assert self.wsgihandler.can_transfer()
            sent = self.wsgihandler.transfer(self.socket, self.blocksize)
            if sent <= 0:
                self.close()

    def close(self):
        # None doesn't have a close attribute
        if hasattr(self.wsgihandler, "close"):
            self.wsgihandler.close()
        asyncore.dispatcher.close(self)

    def handle_close(self):
        """C{asyncore} interface"""
        self.close()

__all__.append("SCGIServer")
class SCGIServer(asyncore.dispatcher):
    """SCGI Server for WSGI applications. It does not use multiple processes or
    multiple threads."""
    def __init__(self, wsgiapp, port, interface="localhost", error=sys.stderr,
                 maxrequestsize=None, maxpostsize=None, blocksize=None,
                 config={}, reusesocket=None):
        """
        @param wsgiapp: is the wsgi application to be run.
        @type port: int
        @param port: is an int representing the TCP port number to be used.
        @type interface: str
        @param interface: is a string specifying the network interface to bind
                which defaults to C{"localhost"} making the server inaccessible
                over network.
        @param error: is a file-like object being passed as C{wsgi.error} in the
                environ parameter defaulting to stderr.
        @type maxrequestsize: int
        @param maxrequestsize: limit the size of request blocks in scgi
                connections. Connections are dropped when this limit is hit.
        @type maxpostsize: int
        @param maxpostsize: limit the size of post bodies that may be processed
                by this instance. Connections are dropped when this limit is
                hit.
        @type blocksize: int
        @param blocksize: is amount of data to read or write from or to the
                network at once
        @type config: {}
        @param config: the environ dictionary is updated using these values for
                each request.
        @type reusesocket: None or socket.socket
        @param reusesocket: If a socket is passed, do not create a socket.
                Instead use given socket as listen socket. The passed socket
                must be set up for accepting tcp connections (i.e. C{AF_INET},
                C{SOCK_STREAM} with bind and listen called).
        """
        if reusesocket is None:
            asyncore.dispatcher.__init__(self)
        else:
            asyncore.dispatcher.__init__(self, reusesocket)

        self.wsgiapp = wsgiapp
        self.error = error
        self.conf = {}
        if maxrequestsize is not None:
            self.conf["maxrequestsize"] = maxrequestsize
        if maxpostsize is not None:
            self.conf["maxpostsize"] = maxpostsize
        if blocksize is not None:
            self.conf["blocksize"] = blocksize
        self.conf["config"] = config

        if reusesocket is None:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind((interface, port))
            self.listen(5)

    def handle_accept(self):
        """asyncore interface"""
        try:
            ret = self.accept()
        except socket.error as err:
            # See http://bugs.python.org/issue6706
            if err.args[0] not in (errno.ECONNABORTED, errno.EAGAIN):
                raise
        else:
            if ret is not None:
                conn, addr = ret
                SCGIConnection(self, conn, addr, **self.conf)

    def run(self):
        """Runs the server. It will not return and you can invoke
        C{asyncore.loop()} instead achieving the same effect."""
        asyncore.loop()
