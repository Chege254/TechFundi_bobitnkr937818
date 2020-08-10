__all__ = []

class AuthenticationRequired(Exception):
    """
    Internal Exception class that is thrown inside L{AuthenticationMiddleware},
    but not visible to other code.
    """

class ProtocolViolation(AuthenticationRequired):
    pass

class AuthenticationMiddleware(object):
    """Base class for HTTP authorization schemes.

    @cvar authorization_method: the implemented Authorization method. It will
        be verified against Authorization headers. Subclasses must define this
        attribute.
    @type authorization_method: str
    """
    authorization_method = None
    def __init__(self, app):
        """
        @param app: is a WSGI application.
        """
        assert self.authorization_method is not None
        self.app = app

    def authenticate(self, auth, environ):
        """Try to authenticate a request. The Authorization header is examined
        and checked agains the L{authorization_method} before being passed to
        this method. This method must either raise an AuthenticationRequired
        instance or return a dictionary explaining what was successfully
        authenticated.

        @type auth: str
        @param auth: is the part of the Authorization header after the method
        @type environ: {str: object}
        @param environ: is the environment passed with a WSGI request
        @rtype: {str: object}
        @returns: a dictionary that provides a key "user" listing the
            authenticated username as a string. It may also provide the key
            "outheaders" with a [(str, str)] value to extend the response
            headers.
        @raises AuthenticationRequired: if the authentication was unsuccessful
        """
        raise NotImplementedError

    def __call__(self, environ, start_response):
        """wsgi interface

        @type environ: {str: object}
        """
        assert isinstance(environ, dict)
        try:
            try:
                auth = environ["HTTP_AUTHORIZATION"]
            except KeyError:
                raise AuthenticationRequired("no Authorization header found")
            try:
                method, rest = auth.split(' ', 1)
            except ValueError:
                method, rest = auth, ""
            if method.lower() != self.authorization_method:
                raise AuthenticationRequired(
                    "authorization method not implemented: %r" % method)
            result = self.authenticate(rest, environ)
        except AuthenticationRequired as exc:
            return self.authorization_required(environ, start_response, exc)
        assert isinstance(result, dict)
        assert "user" in result
        environ["REMOTE_USER"] = result["user"]
        if "outheaders" in result:
            def modified_start_response(status, headers, exc_info=None):
                assert isinstance(headers, list)
                headers.extend(result["outheaders"])
                return start_response(status, headers, exc_info)
        else:
            modified_start_response = start_response
        return self.app(environ, modified_start_response)

    def www_authenticate(self, exception):
        """Generates a WWW-Authenticate header. Subclasses must implement this
        method.

        @type exception: L{AuthenticationRequired}
        @param exception: reason for generating the header
        @rtype: (str, str)
        @returns: the header as (part_before_colon, part_after_colon)
        """
        raise NotImplementedError

    def authorization_required(self, environ, start_response, exception):
        """Generate an error page after failed authentication. Apart from the
        exception parameter, this method behaves like a WSGI application.

        @type exception: L{AuthenticationRequired}
        @param exception: reason for the authentication failure
        """
        status = "401 Authorization required"
        html = b"<html><head><title>401 Authorization required</title></head>" \
               b"<body><h1>401 Authorization required</h1></body></html>"
        headers = [("Content-Type", "text/html"),
                   self.www_authenticate(exception),
                   ("Content-Length", str(len(html)))]
        start_response(status, headers)
        if environ["REQUEST_METHOD"].upper() == "HEAD":
            return []
        return [html]
