__all__ = []

import base64
import time
import sys
import cgitb
import collections
import io

from wsgitools.internal import bytes2str, str2bytes

if sys.version_info[0] >= 3:
    def exc_info_for_raise(exc_info):
        return exc_info[0](exc_info[1]).with_traceback(exc_info[2])
else:
    def exc_info_for_raise(exc_info):
        return exc_info[0], exc_info[1], exc_info[2]

from wsgitools.filters import CloseableList, CloseableIterator
from wsgitools.authentication import AuthenticationRequired, \
        ProtocolViolation, AuthenticationMiddleware

__all__.append("SubdirMiddleware")
class SubdirMiddleware(object):
    """Middleware choosing wsgi applications based on a dict."""
    def __init__(self, default, mapping={}):
        """
        @type default: wsgi app
        @type mapping: {str: wsgi app}
        """
        self.default = default
        self.mapping = mapping
    def __call__(self, environ, start_response):
        """wsgi interface
        @type environ: {str: str}
        @rtype: gen([bytes])
        """
        assert isinstance(environ, dict)
        app = None
        script = environ["PATH_INFO"]
        path_info = ""
        while '/' in script:
            if script in self.mapping:
                app = self.mapping[script]
                break
            script, tail = script.rsplit('/', 1)
            path_info = "/%s%s" % (tail, path_info)
        if app is None:
            app = self.mapping.get(script, None)
            if app is None:
                app = self.default
        environ["SCRIPT_NAME"] += script
        environ["PATH_INFO"] = path_info
        return app(environ, start_response)

__all__.append("NoWriteCallableMiddleware")
class NoWriteCallableMiddleware(object):
    """This middleware wraps a wsgi application that needs the return value of
    C{start_response} function to a wsgi application that doesn't need one by
    writing the data to a C{BytesIO} and then making it be the first result
    element."""
    def __init__(self, app):
        """Wraps wsgi application app."""
        self.app = app
    def __call__(self, environ, start_response):
        """wsgi interface
        @type environ: {str, str}
        @rtype: gen([bytes])
        """
        assert isinstance(environ, dict)
        todo = [None]
        sio = io.BytesIO()
        gotiterdata = False
        def write_calleable(data):
            assert not gotiterdata
            sio.write(data)
        def modified_start_response(status, headers, exc_info=None):
            try:
                if sio.tell() > 0 or gotiterdata:
                    assert exc_info is not None
                    raise exc_info_for_raise(exc_info)
            finally:
                exc_info = None
            assert isinstance(status, str)
            assert isinstance(headers, list)
            todo[0] = (status, headers)
            return write_calleable

        ret = self.app(environ, modified_start_response)
        assert hasattr(ret, "__iter__")

        first = b""
        if not isinstance(ret, list):
            ret = iter(ret)
            stopped = False
            while not (stopped or first):
                try:
                    first = next(ret)
                except StopIteration:
                    stopped = True
            gotiterdata = True
            if stopped:
                ret = CloseableList(getattr(ret, "close", None), (first,))
        else:
            gotiterdata = True

        assert todo[0] is not None
        status, headers = todo[0]
        data = sio.getvalue()

        if isinstance(ret, list):
            if data:
                ret.insert(0, data)
            start_response(status, headers)
            return ret

        data += first
        start_response(status, headers)

        return CloseableIterator(getattr(ret, "close", None),
                                 (data,), ret)

__all__.append("ContentLengthMiddleware")
class ContentLengthMiddleware(object):
    """Guesses the content length header if possible.
    @note: The application used must not use the C{write} callable returned by
           C{start_response}."""
    def __init__(self, app, maxstore=0):
        """Wraps wsgi application app. If the application returns a list, the
        total length of strings is available and the content length header is
        set unless there already is one. For an iterator data is accumulated up
        to a total of maxstore bytes (where maxstore=() means infinity). If the
        iterator is exhaused within maxstore bytes a content length header is
        added unless already present.
        @type maxstore: int or ()
        @note: that setting maxstore to a value other than 0 will violate the
               wsgi standard
        """
        self.app = app
        if maxstore == ():
            maxstore = float("inf")
        self.maxstore = maxstore
    def __call__(self, environ, start_response):
        """wsgi interface"""
        assert isinstance(environ, dict)
        todo = []
        gotdata = False
        def modified_start_response(status, headers, exc_info=None):
            try:
                if gotdata:
                    assert exc_info is not None
                    raise exc_info_for_raise(exc_info)
            finally:
                exc_info = None
            assert isinstance(status, str)
            assert isinstance(headers, list)
            todo[:] = ((status, headers),)
            def raise_not_imp(*args):
                raise NotImplementedError
            return raise_not_imp

        ret = self.app(environ, modified_start_response)
        assert hasattr(ret, "__iter__")

        if isinstance(ret, list):
            gotdata = True
            assert bool(todo)
            status, headers = todo[0]
            if all(k.lower() != "content-length" for k, _ in headers):
                length = sum(map(len, ret))
                headers.append(("Content-Length", str(length)))
            start_response(status, headers)
            return ret

        ret = iter(ret)
        first = b""
        stopped = False
        while not (first or stopped):
            try:
                first = next(ret)
            except StopIteration:
                stopped = True
        gotdata = True
        assert bool(todo)
        status, headers = todo[0]
        data = CloseableList(getattr(ret, "close", None))
        if first:
            data.append(first)
        length = len(first)

        if all(k.lower() != "content-length" for k, _ in headers):
            while (not stopped) and length < self.maxstore:
                try:
                    data.append(next(ret))
                    length += len(data[-1])
                except StopIteration:
                    stopped = True

            if stopped:
                headers.append(("Content-length", str(length)))
                start_response(status, headers)
                return data

        start_response(status, headers)

        return CloseableIterator(getattr(ret, "close", None), data, ret)

def storable(environ):
    if environ["REQUEST_METHOD"] != "GET":
        return False
    return True

def cacheable(environ):
    if environ.get("HTTP_CACHE_CONTROL", "") == "max-age=0":
        return False
    return True

__all__.append("CachingMiddleware")
class CachingMiddleware(object):
    """Caches reponses to requests based on C{SCRIPT_NAME}, C{PATH_INFO} and
    C{QUERY_STRING}."""
    def __init__(self, app, maxage=60, storable=storable, cacheable=cacheable):
        """
        @param app: is a wsgi application to be cached.
        @type maxage: int
        @param maxage: is the number of seconds a reponse may be cached.
        @param storable: is a predicate that determines whether the response
                may be cached at all based on the C{environ} dict.
        @param cacheable: is a predicate that determines whether this request
                invalidates the cache."""
        self.app = app
        self.maxage = maxage
        self.storable = storable
        self.cacheable = cacheable
        self.cache = {}
        self.lastcached = collections.deque()

    def insert_cache(self, key, obj, now=None):
        if now is None:
            now = time.time()
        self.cache[key] = obj
        self.lastcached.append((key, now))

    def prune_cache(self, maxclean=16, now=None):
        if now is None:
            now = time.time()
        old = now - self.maxage
        while self.lastcached and maxclean > 0: # don't do too much work at once
            maxclean -= 1
            if self.lastcached[0][1] > old:
                break
            key, _ = self.lastcached.popleft()
            try:
                obj = self.cache[key]
            except KeyError:
                pass
            else:
                if obj[0] <= old:
                    del self.cache[key]

    def __call__(self, environ, start_response):
        """wsgi interface
        @type environ: {str: str}
        """
        assert isinstance(environ, dict)
        now = time.time()
        self.prune_cache(now=now)
        if not self.storable(environ):
            return self.app(environ, start_response)
        path = environ.get("REQUEST_METHOD", "GET") + " "
        path += environ.get("SCRIPT_NAME", "/")
        path += environ.get("PATH_INFO", '')
        path += "?" + environ.get("QUERY_STRING", "")
        if path in self.cache and self.cacheable(environ):
            cache_object = self.cache[path]
            if cache_object[0] + self.maxage >= now:
                start_response(cache_object[1], list(cache_object[2]))
                return cache_object[3]
            else:
                del self.cache[path]
        cache_object = [now, "", [], []]
        def modified_start_respesponse(status, headers, exc_info=None):
            try:
                if cache_object[3]:
                    assert exc_info is not None
                    raise exc_info_for_raise(exc_info)
            finally:
                exc_info = None
            assert isinstance(status, str)
            assert isinstance(headers, list)
            cache_object[1] = status
            cache_object[2] = headers
            write = start_response(status, list(headers))
            def modified_write(data):
                cache_object[3].append(data)
                write(data)
            return modified_write

        ret = self.app(environ, modified_start_respesponse)
        assert hasattr(ret, "__iter__")

        if isinstance(ret, list):
            cache_object[3].extend(ret)
            self.insert_cache(path, cache_object, now)
            return ret
        def pass_through():
            for data in ret:
                cache_object[3].append(data)
                yield data
            self.insert_cache(path, cache_object, now)
        return CloseableIterator(getattr(ret, "close", None), pass_through())

__all__.append("DictAuthChecker")
class DictAuthChecker(object):
    """Verifies usernames and passwords by looking them up in a dict."""
    def __init__(self, users):
        """
        @type users: {str: str}
        @param users: is a dict mapping usernames to password."""
        self.users = users
    def __call__(self, username, password, environ):
        """check_function interface taking username and password and resulting
        in a bool.
        @type username: str
        @type password: str
        @type environ: {str: object}
        @rtype: bool
        """
        return username in self.users and self.users[username] == password

__all__.append("BasicAuthMiddleware")
class BasicAuthMiddleware(AuthenticationMiddleware):
    """Middleware implementing HTTP Basic Auth. Upon forwarding the request to
    the warpped application the environ dictionary is augmented by a REMOTE_USER
    key."""
    authorization_method = "basic"
    def __init__(self, app, check_function, realm='www', app401=None):
        """
        @param app: is a WSGI application.
        @param check_function: is a function taking three arguments username,
                password and environment returning a bool indicating whether the
                request may is allowed. The older interface of taking only the
                first two arguments is still supported via catching a
                C{TypeError}.
        @type realm: str
        @param app401: is an optional WSGI application to be used for error
                messages
        """
        AuthenticationMiddleware.__init__(self, app)
        self.check_function = check_function
        self.realm = realm
        self.app401 = app401

    def authenticate(self, auth, environ):
        assert isinstance(auth, str)
        assert isinstance(environ, dict)
        auth = str2bytes(auth)
        try:
            auth_info = base64.b64decode(auth)
        except TypeError:
            raise ProtocolViolation("failed to base64 decode auth_info")
        auth_info = bytes2str(auth_info)
        try:
            username, password = auth_info.split(':', 1)
        except ValueError:
            raise ProtocolViolation("no colon found in auth_info")
        try:
            result = self.check_function(username, password, environ)
        except TypeError: # catch old interface
            result = self.check_function(username, password)
        if result:
            return dict(user=username)
        raise AuthenticationRequired("credentials not valid")

    def www_authenticate(self, exception):
        return ("WWW-Authenticate", 'Basic realm="%s"' % self.realm)

    def authorization_required(self, environ, start_response, exception):
        if self.app401 is not None:
            return self.app401(environ, start_response)
        return AuthenticationMiddleware.authorization_required(
                self, environ, start_response, exception)

__all__.append("TracebackMiddleware")
class TracebackMiddleware(object):
    """In case the application throws an exception this middleware will show an
    html-formatted traceback using C{cgitb}."""
    def __init__(self, app):
        """app is the wsgi application to proxy."""
        self.app = app
    def __call__(self, environ, start_response):
        """wsgi interface
        @type environ: {str: str}
        """
        try:
            assert isinstance(environ, dict)
            ret = self.app(environ, start_response)
            assert hasattr(ret, "__iter__")

            if isinstance(ret, list):
                return ret
            # Take the first element of the iterator and possibly catch an
            # exception there.
            ret = iter(ret)
            try:
                first = next(ret)
            except StopIteration:
                return CloseableList(getattr(ret, "close", None), [])
            return CloseableIterator(getattr(ret, "close", None), [first], ret)
        except:
            exc_info = sys.exc_info()
            data = cgitb.html(exc_info)
            start_response("200 OK", [("Content-type", "text/html"),
                                      ("Content-length", str(len(data)))])
            if environ["REQUEST_METHOD"].upper() == "HEAD":
                return []
            return [data]
