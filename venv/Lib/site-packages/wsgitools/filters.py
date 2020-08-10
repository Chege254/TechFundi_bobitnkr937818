"""
This module contains a generic way to create middelwares that filter data.
The work is mainly done by the L{WSGIFilterMiddleware} class. One can write
filters by extending the L{BaseWSGIFilter} class and passing this class
(not an instance) to the L{WSGIFilterMiddleware} constructor.
"""

__all__ = []

import sys
import time
import gzip
import io

from wsgitools.internal import str2bytes

__all__.append("CloseableIterator")
class CloseableIterator(object):
    """Concatenating iterator with close attribute."""
    def __init__(self, close_function, *iterators):
        """If close_function is not C{None}, it will be the C{close} attribute
        of the created iterator object. Further parameters specify iterators
        that are to be concatenated.
        @type close_function: a function or C{None}
        """
        if close_function is not None:
            self.close = close_function
        self.iterators = list(map(iter, iterators))
    def __iter__(self):
        """iterator interface
        @rtype: gen()
        """
        return self
    def __next__(self):
        """iterator interface"""
        if not self.iterators:
            raise StopIteration
        try:
            return next(self.iterators[0])
        except StopIteration:
            self.iterators.pop(0)
            return next(self)
    def next(self):
        return self.__next__()

__all__.append("CloseableList")
class CloseableList(list):
    """A list with a close attribute."""
    def __init__(self, close_function, *args):
        """If close_function is not C{None}, it will be the C{close} attribute
        of the created list object. Other parameters are passed to the list
        constructor.
        @type close_function: a function or C{None}
        """
        if close_function is not None:
            self.close = close_function
        list.__init__(self, *args)
    def __iter__(self):
        """iterator interface"""
        return CloseableIterator(getattr(self, "close", None),
                                 list.__iter__(self))

__all__.append("BaseWSGIFilter")
class BaseWSGIFilter(object):
    """Generic WSGI filter class to be used with L{WSGIFilterMiddleware}.

    For each request a filter object gets created.
    The environment is then passed through L{filter_environ}.
    Possible exceptions are filtered by L{filter_exc_info}.
    After that for each C{(header, value)} tuple L{filter_header} is used.
    The resulting list is filtered through L{filter_headers}.
    Any data is filtered through L{filter_data}.
    In order to possibly append data the L{append_data} method is invoked.
    When the request has finished L{handle_close} is invoked.

    All methods do not modify the passed data by default. Passing the
    L{BaseWSGIFilter} class to a L{WSGIFilterMiddleware} will result in not
    modifying requests at all.
    """
    def __init__(self):
        """This constructor does nothing and can safely be overwritten. It is
        only listed here to document that it must be callable without additional
        parameters."""
    def filter_environ(self, environ):
        """Receives a dict with the environment passed to the wsgi application
        and a C{dict} must be returned. The default is to return the same dict.
        @type environ: {str: str}
        @rtype: {str: str}
        """
        return environ
    def filter_exc_info(self, exc_info):
        """Receives either C{None} or a tuple passed as third argument to
        C{start_response} from the wrapped wsgi application. Either C{None} or
        such a tuple must be returned."""
        return exc_info
    def filter_status(self, status):
        """Receives a status string passed as first argument to
        C{start_response} from the wrapped wsgi application. A valid HTTP status
        string must be returned.
        @type status: str
        @rtype: str
        """
        return status
    def filter_header(self, headername, headervalue):
        """This function is invoked for each C{(headername, headervalue)} tuple
        in the second argument to the C{start_response} from the wrapped wsgi
        application. Such a value or C{None} for discarding the header must be
        returned.
        @type headername: str
        @type headervalue: str
        @rtype: (str, str)
        """
        return (headername, headervalue)
    def filter_headers(self, headers):
        """A list of headers passed as the second argument to the
        C{start_response} from the wrapped wsgi application is passed to this
        function and such a list must also be returned.
        @type headers: [(str, str)]
        @rtype: [(str, str)]
        """
        return headers
    def filter_data(self, data):
        """For each string that is either written by the C{write} callable or
        returned from the wrapped wsgi application this method is invoked. It
        must return a string.
        @type data: bytes
        @rtype: bytes
        """
        return data
    def append_data(self):
        """This function can be used to append data to the response. A list of
        strings or some kind of iterable yielding strings has to be returned.
        The default is to return an empty list.
        @rtype: gen([bytes])
        """
        return []
    def handle_close(self):
        """This method is invoked after the request has finished."""

__all__.append("WSGIFilterMiddleware")
class WSGIFilterMiddleware(object):
    """This wsgi middleware can be used with specialized L{BaseWSGIFilter}s to
    modify wsgi requests and/or reponses."""
    def __init__(self, app, filterclass):
        """
        @param app: is a wsgi application.
        @type filterclass: L{BaseWSGIFilter}s subclass
        @param filterclass: is a subclass of L{BaseWSGIFilter} or some class
                    that implements the interface."""
        self.app = app
        self.filterclass = filterclass
    def __call__(self, environ, start_response):
        """wsgi interface
        @type environ: {str, str}
        @rtype: gen([bytes])
        """
        assert isinstance(environ, dict)
        reqfilter = self.filterclass()
        environ = reqfilter.filter_environ(environ)

        def modified_start_response(status, headers, exc_info=None):
            assert isinstance(status, str)
            assert isinstance(headers, list)
            exc_info = reqfilter.filter_exc_info(exc_info)
            status = reqfilter.filter_status(status)
            headers = (reqfilter.filter_header(h, v) for h, v in headers)
            headers = [h for h in headers if h]
            headers = reqfilter.filter_headers(headers)
            write = start_response(status, headers, exc_info)
            def modified_write(data):
                write(reqfilter.filter_data(data))
            return modified_write

        ret = self.app(environ, modified_start_response)
        assert hasattr(ret, "__iter__")

        def modified_close():
            reqfilter.handle_close()
            getattr(ret, "close", lambda:0)()

        if isinstance(ret, list):
            return CloseableList(modified_close,
                                 list(map(reqfilter.filter_data, ret))
                                 + list(reqfilter.append_data()))
        ret = iter(ret)
        def late_append_data():
            """Invoke C{reqfilter.append_data()} after C{filter_data()} has seen
            all data."""
            for data in reqfilter.append_data():
                yield data
        return CloseableIterator(modified_close,
                                 (reqfilter.filter_data(data) for data in ret),
                                 late_append_data())

# Using map and lambda here since pylint cannot handle list comprehension in
# default arguments. Also note that neither ' nor " are considered printable.
# For escape_string to be reversible \ is also not considered printable.
def escape_string(string, replacer=list(map(
        lambda i: chr(i) if str2bytes(chr(i)).isalnum() or
                chr(i) in '!#$%&()*+,-./:;<=>?@[]^_`{|}~ ' else
                r"\x%2.2x" % i,
        range(256)))):
    """Encodes non-printable characters in a string using \\xXX escapes.

    @type string: str
    @rtype: str
    """
    return "".join(replacer[ord(char)] for char in string)

__all__.append("RequestLogWSGIFilter")
class RequestLogWSGIFilter(BaseWSGIFilter):
    """This filter logs all requests in the apache log file format."""
    @classmethod
    def creator(cls, log, flush=True):
        """Returns a function creating L{RequestLogWSGIFilter}s on given log
        file. log has to be a file-like object.
        @type log: file-like
        @param log: elements of type str are written to the log. That means in
                Py3.X the contents are decoded and in Py2.X the log is assumed
                to be encoded in latin1. This follows the spirit of WSGI.
        @type flush: bool
        @param flush: if True, invoke the flush method on log after each
                write invocation
        """
        return lambda:cls(log, flush)
    def __init__(self, log=sys.stdout, flush=True):
        """
        @type log: file-like
        @type flush: bool
        @param flush: if True, invoke the flush method on log after each
                write invocation
        """
        BaseWSGIFilter.__init__(self)
        assert hasattr(log, "write")
        assert hasattr(log, "flush") or not flush
        self.log = log
        self.flush = flush
        self.remote = "?"
        self.user = "-"
        self.time = time.strftime("%d/%b/%Y:%T %z")
        self.reqmethod = ""
        self.path = ""
        self.proto = None
        self.status = ""
        self.length = 0
        self.referrer = None
        self.useragent = None
    def filter_environ(self, environ):
        """BaseWSGIFilter interface
        @type environ: {str: str}
        @rtype: {str: str}
        """
        assert isinstance(environ, dict)
        self.remote = environ.get("REMOTE_ADDR", self.remote)
        self.user = environ.get("REMOTE_USER", self.user)
        self.reqmethod = environ["REQUEST_METHOD"]
        self.path = environ["SCRIPT_NAME"] + environ["PATH_INFO"]
        if environ.get("QUERY_STRING"):
            self.path = "%s?%s" % (self.path, environ["QUERY_STRING"])
        self.proto = environ.get("SERVER_PROTOCOL", self.proto)
        self.referrer = environ.get("HTTP_REFERER", self.referrer)
        self.useragent = environ.get("HTTP_USER_AGENT", self.useragent)
        return environ
    def filter_status(self, status):
        """BaseWSGIFilter interface
        @type status: str
        @rtype: str
        """
        assert isinstance(status, str)
        self.status = status.split()[0]
        return status
    def filter_data(self, data):
        assert isinstance(data, bytes)
        self.length += len(data)
        return data
    def handle_close(self):
        """BaseWSGIFilter interface"""
        line = '%s %s - [%s]' % (self.remote, self.user, self.time)
        line = '%s "%s %s' % (line, escape_string(self.reqmethod),
                              escape_string(self.path))
        if self.proto is not None:
            line = "%s %s" % (line, self.proto)
        line = '%s" %s %d' % (line, self.status, self.length)
        if self.referrer is not None:
            line = '%s "%s"' % (line, escape_string(self.referrer))
        else:
            line += " -"
        if self.useragent is not None:
            line = '%s "%s"' % (line, escape_string(self.useragent))
        else:
            line += " -"
        self.log.write("%s\n" % line)
        if self.flush:
            self.log.flush()

__all__.append("TimerWSGIFilter")
class TimerWSGIFilter(BaseWSGIFilter):
    """Replaces a specific string in the data returned from the filtered wsgi
    application with the time the request took. The string has to be exactly
    eight bytes long, defaults to C{"?GenTime"} and must be an element of the
    iterable returned by the filtered application. If the application returns
    something like C{["spam?GenTime", "?GenTime spam", "?GenTime"]} only the
    last occurance get's replaced."""
    @classmethod
    def creator(cls, pattern):
        """Returns a function creating L{TimerWSGIFilter}s with a given pattern
        beeing a string of exactly eight bytes.
        @type pattern: bytes
        """
        return lambda:cls(pattern)
    def __init__(self, pattern=b"?GenTime"):
        """
        @type pattern: str
        """
        BaseWSGIFilter.__init__(self)
        assert isinstance(pattern, bytes)
        self.pattern = pattern
        self.start = time.time()
    def filter_data(self, data):
        """BaseWSGIFilter interface
        @type data: bytes
        @rtype: bytes
        """
        if data == self.pattern:
            return str2bytes("%8.3g" % (time.time() - self.start))
        return data

__all__.append("EncodeWSGIFilter")
class EncodeWSGIFilter(BaseWSGIFilter):
    """Encodes all body data (no headers) with given charset.
    @note: This violates the wsgi standard as it requires unicode objects
           whereas wsgi mandates the use of bytes.
    """
    @classmethod
    def creator(cls, charset):
        """Returns a function creating L{EncodeWSGIFilter}s with a given
        charset.
        @type charset: str
        """
        return lambda:cls(charset)
    def __init__(self, charset="utf-8"):
        """
        @type charset: str
        """
        BaseWSGIFilter.__init__(self)
        self.charset = charset
    def filter_data(self, data):
        """BaseWSGIFilter interface
        @type data: str
        @rtype: bytes
        """
        return data.encode(self.charset)
    def filter_header(self, header, value):
        """BaseWSGIFilter interface
        @type header: str
        @type value: str
        @rtype: (str, str)
        """
        if header.lower() != "content-type":
            return (header, value)
        return (header, "%s; charset=%s" % (value, self.charset))

__all__.append("GzipWSGIFilter")
class GzipWSGIFilter(BaseWSGIFilter):
    """Compresses content using gzip."""
    @classmethod
    def creator(cls, flush=True):
        """
        Returns a function creating L{GzipWSGIFilter}s.
        @type flush: bool
        @param flush: whether or not the filter should always flush the buffer
        """
        return lambda:cls(flush)
    def __init__(self, flush=True):
        """
        @type flush: bool
        @param flush: whether or not the filter should always flush the buffer
        """
        BaseWSGIFilter.__init__(self)
        self.flush = flush
        self.compress = False
        self.sio = None
        self.gzip = None
    def filter_environ(self, environ):
        """BaseWSGIFilter interface
        @type environ: {str: str}
        """
        assert isinstance(environ, dict)
        if "HTTP_ACCEPT_ENCODING" in environ:
            acceptenc = environ["HTTP_ACCEPT_ENCODING"].split(',')
            acceptenc = map(str.strip, acceptenc)
            if "gzip" in acceptenc:
                self.compress = True
                self.sio = io.BytesIO()
                self.gzip = gzip.GzipFile(fileobj=self.sio, mode="w")
        return environ
    def filter_header(self, headername, headervalue):
        """ BaseWSGIFilter interface
        @type headername: str
        @type headervalue: str
        @rtype: (str, str) or None
        """
        if self.compress:
            if headername.lower() == "content-length":
                return None
        return (headername, headervalue)
    def filter_headers(self, headers):
        """BaseWSGIFilter interface
        @type headers: [(str, str)]
        @rtype: [(str, str)]
        """
        assert isinstance(headers, list)
        if self.compress:
            headers.append(("Content-encoding", "gzip"))
        return headers
    def filter_data(self, data):
        if not self.compress:
            return data
        self.gzip.write(data)
        if self.flush:
            self.gzip.flush()
        data = self.sio.getvalue()
        self.sio.truncate(0)
        self.sio.seek(0)
        return data
    def append_data(self):
        if not self.compress:
            return []
        self.gzip.close()
        data = self.sio.getvalue()
        return [data]

class ReusableWSGIInputFilter(BaseWSGIFilter):
    """Make C{environ["wsgi.input"]} readable multiple times. Although this is
    not required by the standard it is sometimes desirable to read C{wsgi.input}
    multiple times. This filter will therefore replace that variable with a
    C{BytesIO} instance which provides a C{seek} method.
    """
    @classmethod
    def creator(cls, maxrequestsize):
        """
        Returns a function creating L{ReusableWSGIInputFilter}s with desired
        maxrequestsize being set. If there is more data than maxrequestsize is
        available in C{wsgi.input} the rest will be ignored. (It is up to the
        adapter to eat this data.)
        @type maxrequestsize: int
        @param maxrequestsize: is the maximum number of bytes to store in the
                C{BytesIO}
        """
        return lambda:cls(maxrequestsize)
    def __init__(self, maxrequestsize=65536):
        """ReusableWSGIInputFilters constructor.
        @type maxrequestsize: int
        @param maxrequestsize: is the maximum number of bytes to store in the
                C{BytesIO}, see L{creator}
        """
        BaseWSGIFilter.__init__(self)
        self.maxrequestsize = maxrequestsize

    def filter_environ(self, environ):
        """BaseWSGIFilter interface
        @type environ: {str: str}
        """

        if isinstance(environ["wsgi.input"], io.BytesIO):
            return environ # nothing to be done

        # XXX: is this really a good idea? use with care
        environ["wsgitools.oldinput"] = environ["wsgi.input"]
        data = io.BytesIO(environ["wsgi.input"].read(self.maxrequestsize))
        environ["wsgi.input"] = data

        return environ
