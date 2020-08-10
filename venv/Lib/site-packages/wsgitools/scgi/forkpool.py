"""
The L{forkpool.SCGIServer} adapts a wsgi application to a scgi service.

It works with multiple processes that are periodically cleaned up to prevent
memory leaks having an impact to the system.
"""

try:
    import resource
except ImportError:
    resource = None
import socket
import os
import select
import sys
import errno
import signal

from wsgitools.internal import bytes2str, str2bytes
from wsgitools.scgi import _convert_environ, FileWrapper

if sys.version_info[0] >= 3:
    def exc_info_for_raise(exc_info):
        return exc_info[0](exc_info[1]).with_traceback(exc_info[2])
else:
    def exc_info_for_raise(exc_info):
        return exc_info[0], exc_info[1], exc_info[2]

__all__ = []

class SocketFileWrapper(object):
    """Wraps a socket to a wsgi-compliant file-like object."""
    def __init__(self, sock, toread):
        """@param sock: is a C{socket.socket()}"""
        self.sock = sock
        self.buff = b""
        self.toread = toread

    def _recv(self, size=4096):
        """
        internal method for receiving and counting incoming data
        @raises socket.error:
        """
        toread = min(size, self.toread)
        if not toread:
            return b""
        try:
            data = self.sock.recv(toread)
        except socket.error as why:
            if why[0] in (errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                data = b""
            else:
                raise
        self.toread -= len(data)
        return data

    def close(self):
        """Does not close the socket, because it might still be needed. It
        reads all data that should have been read as given by C{CONTENT_LENGTH}.
        """
        try:
            while self.toread > 0:
                if not self._recv(min(self.toread, 4096)):
                    return
        except socket.error:
            pass

    def read(self, size=None):
        """
        see pep333
        @raises socket.error:
        """
        if size is None:
            retl = []
            data = self.buff
            self.buff = b""
            while True:
                retl.append(data)
                try:
                    data = self._recv()
                except socket.error:
                    break
                if not data:
                    break
            return b"".join(retl)
        datalist = [self.buff]
        datalen = len(self.buff)
        while datalen < size:
            try:
                data = self._recv(min(4096, size - datalen))
            except socket.error:
                break
            if not data:
                break
            datalist.append(data)
            datalen += len(data)
        self.buff = b"".join(datalist)

        if size <= len(self.buff):
            ret, self.buff = self.buff[:size], self.buff[size:]
            return ret
        ret, self.buff = self.buff, b""
        return ret

    def readline(self, size=None):
        """
        see pep333
        @raises socket.error:
        """
        while True:
            try:
                split = self.buff.index(b'\n') + 1
                if size is not None and split > size:
                    split = size
                ret, self.buff = self.buff[:split], self.buff[split:]
                return ret
            except ValueError:
                if size is not None:
                    if len(self.buff) < size:
                        data = self._recv(size - len(self.buff))
                    else:
                        ret, self.buff = self.buff[:size], self.buff[size:]
                        return ret
                else:
                    data = self._recv(4096)
                if not data:
                    ret, self.buff = self.buff, b""
                    return ret
                self.buff += data

    def readlines(self):
        """
        see pep333
        @raises socket.error:
        """
        data = self.readline()
        while data:
            yield data
            data = self.readline()
    def __iter__(self):
        """see pep333"""
        return self
    def __next__(self):
        """
        see pep333
        @raises socket.error:
        """
        data = self.read(4096)
        if not data:
            raise StopIteration
        return data
    def next(self):
        return self.__next__()
    def flush(self):
        """see pep333"""
    def write(self, data):
        """see pep333"""
        assert isinstance(data, bytes)
        try:
            self.sock.sendall(data)
        except socket.error:
            # ignore all socket errors: there is no way to report
            return
    def writelines(self, lines):
        """see pep333"""
        for line in lines:
            self.write(line)

__all__.append("SCGIServer")
class SCGIServer(object):
    """Usage: create an L{SCGIServer} object and invoke the run method which
    will then turn this process into an scgi server."""
    class WorkerState(object):
        """state: 0 means idle and 1 means working.
        These values are also sent as strings '0' and '1' over the socket."""
        def __init__(self, pid, sock, state):
            """
            @type pid: int
            @type state: int
            """
            self.pid = pid
            self.sock = sock
            self.state = state

    def __init__(self, wsgiapp, port, interface="localhost", error=sys.stderr,
                 minworkers=2, maxworkers=32, maxrequests=1000, config={},
                 reusesocket=None, cpulimit=None, timelimit=None):
        """
        @param wsgiapp: is the WSGI application to be run.
        @type port: int
        @param port: is the tcp port to listen on
        @type interface: str
        @param interface: is the interface to bind to (default: C{"localhost"})
        @param error: is a file-like object beeing passed as C{wsgi.errors} in
                environ
        @type minworkers: int
        @param minworkers: is the number of worker processes to spawn
        @type maxworkers: int
        @param maxworkers: is the maximum number of workers that can be spawned
                on demand
        @type maxrequests: int
        @param maxrequests: is the number of requests a worker processes before
                dying
        @type config: {}
        @param config: the environ dictionary is updated using these values for
                each request.
        @type reusesocket: None or socket.socket
        @param reusesocket: If a socket is passed, do not create a socket.
                Instead use given socket as listen socket. The passed socket
                must be set up for accepting tcp connections (i.e. C{AF_INET},
                C{SOCK_STREAM} with bind and listen called).
        @type cpulimit: (int, int)
        @param cpulimit: a pair of soft and hard cpu time limit in seconds.
                This limit is installed for each worker using RLIMIT_CPU if
                resource limits are available to this platform. After reaching
                the soft limit workers will continue to process the current
                request and then cleanly terminate.
        @type timelimit: int
        @param timelimit: The maximum number of wall clock seconds processing
                a request should take. If this is specified, an alarm timer is
                installed and the default action is to kill the worker.
        """
        assert hasattr(error, "write")
        self.wsgiapp = wsgiapp
        self.bind_address = (interface, port)
        self.minworkers = minworkers
        self.maxworkers = maxworkers
        self.maxrequests = maxrequests
        self.config = config.copy()
        self.config["wsgi.errors"] = error
        self.reusesocket = reusesocket
        # cpulimit changes meaning:
        # master: None or a tuple denoting the limit to be configured.
        # worker: boolean denoting whether the limit is reached.
        self.cpulimit = cpulimit
        self.timelimit = timelimit
        self.server = None # becomes a socket
        self.sigpipe = None  # becomes a pair socketpair endpoints
        # maps filedescriptors to WorkerStates
        self.workers = {}
        self.running = False
        self.ischild = False

    def enable_sighandler(self, sig=signal.SIGTERM):
        """
        Changes the signal handler for the given signal to terminate the run()
        loop.
        @param sig: is the signal to handle
        @returns: self
        """
        signal.signal(sig, self.shutdownhandler)
        return self

    def run(self):
        """
        Serve the wsgi application.
        """
        if self.reusesocket is None:
            self.server = socket.socket()
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(self.bind_address)
            self.server.listen(5)
        else:
            self.server = self.reusesocket
        self.sigpipe = socket.socketpair()
        self.running = True
        while self.running:
            while (len(self.workers) < self.minworkers or # less than min
                    (len(self.workers) < self.maxworkers and # less than max
                        not len([w for w in # no inactive
                                 self.workers.values() if w.state == 0]))):
                self.spawnworker()
            rs = list(self.workers.keys())
            rs.append(self.sigpipe[0])
            try:
                rs, _, _ = select.select(rs, [], [])
            except select.error as e:
                if e[0] != errno.EINTR:
                    raise
                rs = []
            for s in rs:
                if s == self.sigpipe[0]:
                    self.sigpipe[0].recv(1)
                    continue
                try:
                    data = self.workers[s].sock.recv(1)
                except socket.error:
                    # we cannot handle errors here, so drop the connection.
                    data = b''
                if data == b'':
                    self.workers[s].sock.close()
                    del self.workers[s]
                elif data in (b'0', b'1'):
                    self.workers[s].state = int(data)
                else:
                    raise RuntimeError("unexpected data from worker")
            try:
                pid = 1
                while pid > 0:
                    pid, _ = os.waitpid(0, os.WNOHANG)
            except OSError:
                pass
        if self.reusesocket is None:
            self.server.close()
        self.server = None
        self.sigpipe[0].close()
        self.sigpipe[1].close()
        self.sigpipe = None
        self.killworkers()

    def killworkers(self, sig=signal.SIGTERM):
        """
        Kills all worker children.
        @param sig: is the signal used to kill the children
        """
        while self.workers:
            _, state = self.workers.popitem()
            state.sock.close()
            os.kill(state.pid, sig)
            # TODO: handle working children with a timeout

    def shutdownhandler(self, sig=None, stackframe=None):
        """
        Signal handler function for stopping the run() loop. It works by
        setting a variable that run() evaluates in each loop. As a signal
        interrupts accept the loop is terminated, the accepting socket is
        closed and the workers are killed.
        @param sig: ignored for usage with signal.signal
        @param stackframe: ignored for usage with signal.signal
        """
        if self.ischild:
            sys.exit()
        elif self.running:
            self.running = False
            self.sigpipe[1].send(b' ')

    def sigxcpuhandler(self, sig=None, stackframe=None):
        """
        Signal hanlder function for the SIGXCUP signal. It is sent to a
        worker when the soft RLIMIT_CPU is crossed.
        @param sig: ignored for usage with signal.signal
        @param stackframe: ignored for usage with signal.signal
        """
        self.cpulimit = True

    def spawnworker(self):
        """
        internal! spawns a single worker
        """
        srvsock, worksock = socket.socketpair()

        pid = os.fork()
        if pid == 0:
            self.ischild = True
            # close unneeded sockets
            srvsock.close()
            for worker in self.workers.values():
                worker.sock.close()
            del self.workers

            if self.cpulimit and resource:
                signal.signal(signal.SIGXCPU, self.sigxcpuhandler)
                resource.setrlimit(resource.RLIMIT_CPU, self.cpulimit)
            self.cpulimit = False

            try:
                self.work(worksock)
            except socket.error:
                pass

            sys.exit()
        elif pid > 0:
            # close unneeded sockets
            worksock.close()

            self.workers[srvsock.fileno()] = SCGIServer.\
                                             WorkerState(pid, srvsock, 0)
        else:
            raise RuntimeError("fork failed")

    def work(self, worksock):
        """
        internal! serves maxrequests times
        @raises socket.error:
        """
        for _ in range(self.maxrequests):
            (con, addr) = self.server.accept()
            # we cannot handle socket.errors here.
            worksock.sendall(b'1') # tell server we're working
            if self.timelimit:
                signal.alarm(self.timelimit)
            self.process(con)
            if self.timelimit:
                signal.alarm(0)
            worksock.sendall(b'0') # tell server we've finished
            if self.cpulimit:
                break

    def process(self, con):
        """
        internal! processes a single request on the connection con.
        """
        # This is a little bit ugly:
        # The server has to send the length of the request followed by a colon.
        # We assume that 1. the colon is within the first seven bytes.
        # 2. the packet isn't fragmented.
        # Furthermore 1 implies that the request isn't longer than 999999 bytes.
        # This method however works. :-)
        try:
            data = con.recv(7)
        except socket.error:
            con.close()
            return
        if not b':' in data:
            con.close()
            return
        length, data = data.split(b':', 1)
        try:
            length = int(length)
        except ValueError:  # clear protocol violation
            con.close()
            return

        while len(data) != length + 1: # read one byte beyond
            try:
                t = con.recv(min(4096, length + 1 - len(data)))
            except socket.error:
                con.close()
                return
            if not t: # request too short
                con.close()
                return
            data += t

        # netstrings!
        data = data.split(b'\0')
        # the byte beyond has to be a ','.
        # and the number of netstrings excluding the final ',' has to be even
        if data.pop() != b',' or len(data) % 2 != 0:
            con.close()
            return

        environ = self.config.copy()
        while data:
            key = bytes2str(data.pop(0))
            value = bytes2str(data.pop(0))
            environ[key] = value

        # elements:
        # 0 -> None: no headers set
        # 0 -> False: set but unsent
        # 0 -> True: sent
        # 1 -> bytes of the complete header
        response_head = [None, None]

        def sendheaders():
            assert response_head[0] is not None # headers set
            if response_head[0] != True:
                response_head[0] = True
                try:
                    con.sendall(response_head[1])
                except socket.error:
                    pass

        def dumbsend(data):
            sendheaders()
            try:
                con.sendall(data)
            except socket.error:
                pass

        def start_response(status, headers, exc_info=None):
            if exc_info and response_head[0]:
                try:
                    raise exc_info_for_raise(exc_info)
                finally:
                    exc_info = None
            assert isinstance(status, str)
            assert isinstance(headers, list)
            assert all(isinstance(k, str) and isinstance(v, str)
                       for (k, v) in headers)
            assert not response_head[0] # unset or not sent
            headers = "".join(map("%s: %s\r\n".__mod__, headers))
            full_header = "Status: %s\r\n%s\r\n" % (status, headers)
            response_head[1] = str2bytes(full_header)
            response_head[0] = False # set but nothing sent
            return dumbsend

        try:
            content_length = int(environ["CONTENT_LENGTH"])
        except ValueError:
            con.close()
            return

        _convert_environ(environ, multiprocess=True)
        sfw = SocketFileWrapper(con, content_length)
        environ["wsgi.input"] = sfw

        result = self.wsgiapp(environ, start_response)
        assert hasattr(result, "__iter__")

        if isinstance(result, FileWrapper) and result.can_transfer():
            sendheaders()
            sent = 1
            while sent > 0:
                sent = result.transfer(con)
        else:
            result_iter = iter(result)
            for data in result_iter:
                assert response_head[0] is not None
                assert isinstance(data, bytes)
                dumbsend(data)
            if response_head[0] != True:
                sendheaders()
        if hasattr(result, "close"):
            result.close()
        sfw.close()
        con.close()
