"""
There are attempts to create a new version of the WSGI standard. These
classes try to adapt the current standard to something that eventually
works out to be the next version of WSGI. For more information see
U{http://wsgi.readthedocs.io/en/latest/proposals-2.0.html}.
"""

__all__ = []

import warnings

from wsgitools.filters import CloseableIterator, CloseableList

warnings.warn("wsgitools.adapters will be removed", DeprecationWarning)

__all__.append("WSGI2to1Adapter")
class WSGI2to1Adapter(object):
    """Adapts an application with an interface that might somewhen be known as
    WSGI 2.0 to the WSGI 1.0 interface."""
    def __init__(self, app):
        """app is an application with an interface that might somewhen be known
        as WSGI 2.0."""
        self.app = app
    def __call__(self, environ, start_response):
        """WSGI 1.0 interface"""
        assert isinstance(environ, dict)
        status, headers, iterable = self.app(environ)
        assert isinstance(status, str)
        assert isinstance(headers, list)
        assert hasattr(iterable, "__iter__")
        start_response(status, headers)
        return iterable

__all__.append("WSGI1to2Adapter")
class WSGI1to2Adapter(object):
    """Adapts a WSGI 1.0 application to something that might somewhen be the
    WSGI 2.0 interface."""
    def __init__(self, app):
        """@param app: is a WSGI 1.0 application"""
        self.app = app
    def __call__(self, environ):
        """some interface that might somewhen be known as WSGI 2.0"""
        assert isinstance(environ, dict)
        results = [None, None, []]
        def start_response(status, headers, exc_info=None):
            assert isinstance(status, str)
            assert isinstance(headers, list)
            results[0] = status
            results[1] = headers
            def write_callable(data):
                results[2].append(data)
            return write_callable
        iterable = self.app(environ, start_response)
        assert hasattr(iterable, "__iter__")
        if not results[2]:
            return results[0], results[1], iterable
        if isinstance(iterable, list):
            # retaining .close attribute this way
            iterable[:0] = results[2]
            return results[0], results[1], iterable
        close_function = getattr(iterable, "close", None)
        iterable = iter(iterable)
        try:
            first = next(iterable)
        except StopIteration:
            return (results[0], results[1],
                    CloseableList(close_function, results[2]))
        results[2].append(first)
        return (results[0], results[1],
                CloseableIterator(close_function, results[2], iterable))
