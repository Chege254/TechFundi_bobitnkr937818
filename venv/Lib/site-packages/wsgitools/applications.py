import os.path

__all__ = []

try:
    basestring
except NameError:
    basestring = str

__all__.append("StaticContent")
class StaticContent(object):
    """
    This wsgi application provides static content on whatever request it
    receives with method GET or HEAD (content stripped). If not present, a
    content-length header is computed.
    """
    def __init__(self, status, headers, content, anymethod=False):
        """
        @type status: str
        @param status: is the HTTP status returned to the browser (ex: "200 OK")
        @type headers: list
        @param headers: is a list of C{(header, value)} pairs being delivered as
                HTTP headers
        @type content: bytes
        @param content: contains the data to be delivered to the client. It is
                either a string or some kind of iterable yielding strings.
        @type anymethod: boolean
        @param anymethod: determines whether any request method should be
                answered with this response instead of a 501
        """
        assert isinstance(status, str)
        assert isinstance(headers, list)
        assert isinstance(content, bytes) or hasattr(content, "__iter__")
        self.status = status
        self.headers = headers
        self.anymethod = anymethod
        length = -1
        if isinstance(content, bytes):
            self.content = [content]
            length = len(content)
        else:
            self.content = content
            if isinstance(self.content, list):
                length = sum(map(len, self.content))
        if length >= 0:
            if  not [v for h, v in headers if h.lower() == "content-length"]:
                headers.append(("Content-length", str(length)))
    def __call__(self, environ, start_response):
        """wsgi interface"""
        assert isinstance(environ, dict)
        if environ["REQUEST_METHOD"].upper() not in ["GET", "HEAD"] and \
                not self.anymethod:
            resp = b"Request method not implemented"
            start_response("501 Not Implemented",
                           [("Content-length", str(len(resp)))])
            return [resp]
        start_response(self.status, list(self.headers))
        if environ["REQUEST_METHOD"].upper() == "HEAD":
            return []
        return self.content

__all__.append("StaticFile")
class StaticFile(object):
    """
    This wsgi application provides the content of a static file on whatever
    request it receives with method GET or HEAD (content stripped). If not
    present, a content-length header is computed.
    """
    def __init__(self, filelike, status="200 OK", headers=list(),
                 blocksize=4096):
        """
        @type status: str
        @param status: is the HTTP status returned to the browser
        @type headers: [(str, str)]
        @param headers: is a list of C{(header, value)} pairs being delivered as
                HTTP headers
        @type filelike: str or file-like
        @param filelike: may either be an path in the local file system or a
                file-like that must support C{read(size)} and C{seek(0)}. If
                C{tell()} is present, C{seek(0, 2)} and C{tell()} will be used
                to compute the content-length.
        @type blocksize: int
        @param blocksize: the content is provided in chunks of this size
        """
        self.filelike = filelike
        self.status = status
        self.headers = headers
        self.blocksize = blocksize

    def _serve_in_chunks(self, stream):
        """internal method yielding data from the given stream"""
        while True:
            data = stream.read(self.blocksize)
            if not data:
                break
            yield data
        if isinstance(self.filelike, basestring):
            stream.close()

    def __call__(self, environ, start_response):
        """wsgi interface"""
        assert isinstance(environ, dict)

        if environ["REQUEST_METHOD"].upper() not in ["GET", "HEAD"]:
            resp = b"Request method not implemented"
            start_response("501 Not Implemented",
                           [("Content-length", str(len(resp)))])
            return [resp]

        stream = None
        size = -1
        try:
            if isinstance(self.filelike, basestring):
                # raises IOError
                stream = open(self.filelike, "rb")
                size = os.path.getsize(self.filelike)
            else:
                stream = self.filelike
                if hasattr(stream, "tell"):
                    stream.seek(0, 2)
                    size = stream.tell()
                stream.seek(0)
        except IOError:
            resp = b"File not found"
            start_response("404 File not found",
                           [("Content-length", str(len(resp)))])
            return [resp]

        headers = list(self.headers)
        if size >= 0:
            if not [v for h, v in headers if h.lower() == "content-length"]:
                headers.append(("Content-length", str(size)))

        start_response(self.status, headers)
        if environ["REQUEST_METHOD"].upper() == "HEAD":
            if isinstance(self.filelike, basestring):
                stream.close()
            return []

        if isinstance(self.filelike, basestring) and 'wsgi.file_wrapper' in environ:
            return environ['wsgi.file_wrapper'](stream, self.blocksize)

        if 0 <= size <= self.blocksize:
            data = stream.read(size)
            if isinstance(self.filelike, basestring):
                stream.close()
            return [data]
        return self._serve_in_chunks(stream)
