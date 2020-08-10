__all__ = []

try:
    import sendfile
except ImportError:
    have_sendfile = False
else:
    have_sendfile = True

class FileWrapper(object):
    """
    @ivar offset: Initially 0. Becomes -1 when reading using next and 
        becomes positive when reading using next. In the latter case it
        counts the number of bytes sent. It also ensures that next and
        transfer are never mixed.
    """
    def __init__(self, filelike, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        self.offset = 0
        if hasattr(filelike, "close"):
            self.close = filelike.close

    def can_transfer(self):
        return have_sendfile and hasattr(self.filelike, "fileno") and \
                self.offset >= 0

    def transfer(self, sock, blksize=None):
        assert self.offset >= 0
        if blksize is None:
            blksize = self.blksize
        else:
            blksize = min(self.blksize, blksize)
        try:
            sent = sendfile.sendfile(sock.fileno(), self.filelike.fileno(),
                    self.offset, blksize)
        except OSError:
            return -1
        # There are two different sendfile libraries. Yeah!
        if isinstance(sent, tuple):
            sent = sent[1]
        self.offset += sent
        return sent

    def __iter__(self):
        return self

    def __next__(self):
        assert self.offset <= 0
        self.offset = -1
        data = self.filelike.read(self.blksize)
        if data:
            return data
        raise StopIteration
    def next(self):
        return self.__next__()

def _convert_environ(environ, multithread=False, multiprocess=False,
        run_once=False):
    environ.update({
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.multithread": multithread,
        "wsgi.multiprocess": multiprocess,
        "wsgi.run_once": run_once})
    if environ.get("HTTPS", "no").lower() in ('yes', 'y', 'on', '1'):
        environ["wsgi.url_scheme"] = "https"
    try:
        environ["CONTENT_TYPE"] = environ.pop("HTTP_CONTENT_TYPE")
    except KeyError:
        pass
    environ.pop("HTTP_CONTENT_LENGTH", None) # TODO: better way?
    if have_sendfile:
        environ["wsgi.file_wrapper"] = FileWrapper
